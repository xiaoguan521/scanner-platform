package api

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"scanner-platform/internal/account"
	"scanner-platform/internal/assets"
	"scanner-platform/internal/repo"
	"scanner-platform/internal/taskflow"
)

func TestTaskDetailLogsAndExportAreAuthenticatedAndSafe(t *testing.T) {
	ctx := context.Background()
	accounts, err := account.New(filepath.Join(t.TempDir(), "platform.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer accounts.Close()
	if err := accounts.InitAdmin(ctx, "taskdetailadmin", "Safe-Task-Detail-Password-12"); err != nil {
		t.Fatal(err)
	}
	store, err := repo.NewRuntime(accounts.SQLDB())
	if err != nil {
		t.Fatal(err)
	}
	assetStore, err := assets.New(accounts.SQLDB())
	if err != nil {
		t.Fatal(err)
	}
	task, err := store.CreateSyntheticTask(ctx)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(NewRuntimeHandler(store, NewDevelopmentHandler(accounts, assetStore), "", accounts))
	defer server.Close()
	worker := &taskflow.Worker{ServerURL: server.URL, ID: "task-detail-worker", Client: server.Client()}
	if worked, err := worker.ProcessOne(ctx); err != nil || !worked {
		t.Fatalf("complete synthetic task: worked=%v err=%v", worked, err)
	}
	if _, err := accounts.SQLDB().ExecContext(ctx, `INSERT INTO audit_logs(id,actor,action,object_type,object_id,detail,created_at) VALUES(?,?,?,?,?,?,?)`, "task-log-fixture", "taskdetailadmin", "custom_task_event", "task", task.ID, `{"secret":"must not return"}`, "2026-10-21T00:00:00Z"); err != nil {
		t.Fatal(err)
	}

	get := func(path string, cookie *http.Cookie) *http.Response {
		req, err := http.NewRequest(http.MethodGet, server.URL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		if cookie != nil {
			req.AddCookie(cookie)
		}
		response, err := server.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return response
	}
	anonymous := get("/api/v1/tasks/"+task.ID, nil)
	if anonymous.StatusCode != http.StatusUnauthorized {
		anonymous.Body.Close()
		t.Fatalf("anonymous task detail: %d", anonymous.StatusCode)
	}
	anonymous.Body.Close()

	loginRequest, err := http.NewRequest(http.MethodPost, server.URL+"/api/v1/auth/login", strings.NewReader(`{"username":"taskdetailadmin","password":"Safe-Task-Detail-Password-12"}`))
	if err != nil {
		t.Fatal(err)
	}
	loginRequest.Header.Set("Content-Type", "application/json")
	loginRequest.Header.Set("X-Requested-With", "XMLHttpRequest")
	login, err := server.Client().Do(loginRequest)
	if err != nil {
		t.Fatal(err)
	}
	if login.StatusCode != http.StatusOK || len(login.Cookies()) != 1 {
		login.Body.Close()
		t.Fatalf("login: status=%d cookies=%d", login.StatusCode, len(login.Cookies()))
	}
	cookie := login.Cookies()[0]
	login.Body.Close()
	pausedTask, err := store.CreateSyntheticTask(ctx)
	if err != nil {
		t.Fatal(err)
	}
	post := func(path string) *http.Response {
		req, err := http.NewRequest(http.MethodPost, server.URL+path, strings.NewReader("{}"))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Requested-With", "XMLHttpRequest")
		req.AddCookie(cookie)
		response, err := server.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return response
	}
	paused := post("/api/v1/tasks/" + pausedTask.ID + "/pause")
	if paused.StatusCode != http.StatusOK {
		paused.Body.Close()
		t.Fatalf("pause task: %d", paused.StatusCode)
	}
	paused.Body.Close()
	paused = get("/api/v1/tasks/"+pausedTask.ID, cookie)
	var pausedBody taskflow.Task
	if err := json.NewDecoder(paused.Body).Decode(&pausedBody); err != nil {
		paused.Body.Close()
		t.Fatal(err)
	}
	paused.Body.Close()
	if pausedBody.Status != "PAUSED" {
		t.Fatalf("pause status: %+v", pausedBody)
	}
	resumed := post("/api/v1/tasks/" + pausedTask.ID + "/resume")
	if resumed.StatusCode != http.StatusOK {
		resumed.Body.Close()
		t.Fatalf("resume task: %d", resumed.StatusCode)
	}
	resumed.Body.Close()

	detail := get("/api/v1/tasks/"+task.ID, cookie)
	if detail.StatusCode != http.StatusOK {
		body := make([]byte, 4096)
		n, _ := detail.Body.Read(body)
		detail.Body.Close()
		t.Fatalf("task detail: %d %s", detail.StatusCode, body[:n])
	}
	var taskBody taskflow.Task
	if err := json.NewDecoder(detail.Body).Decode(&taskBody); err != nil {
		detail.Body.Close()
		t.Fatal(err)
	}
	detail.Body.Close()
	if taskBody.ID != task.ID || taskBody.Status != "COMPLETED" || taskBody.FindingCount != 1 {
		t.Fatalf("unexpected task detail: %+v", taskBody)
	}

	logs := get("/api/v1/tasks/"+task.ID+"/logs", cookie)
	if logs.StatusCode != http.StatusOK {
		logs.Body.Close()
		t.Fatalf("task logs: %d", logs.StatusCode)
	}
	var logBody ListResponse[repo.TaskLog]
	if err := json.NewDecoder(logs.Body).Decode(&logBody); err != nil {
		logs.Body.Close()
		t.Fatal(err)
	}
	logs.Body.Close()
	if logBody.Total == 0 || len(logBody.Items) == 0 || logBody.Items[len(logBody.Items)-1].Message != "任务记录已更新" {
		t.Fatalf("unexpected task logs: %+v", logBody)
	}
	if strings.Contains(string(mustJSON(t, logBody)), "must not return") {
		t.Fatal("task log exposed audit detail")
	}

	jsonExport := get("/api/v1/tasks/"+task.ID+"/export?format=json", cookie)
	if jsonExport.StatusCode != http.StatusOK || jsonExport.Header.Get("Content-Disposition") != `attachment; filename="task-result.json"` {
		jsonExport.Body.Close()
		t.Fatalf("json export headers: status=%d disposition=%q", jsonExport.StatusCode, jsonExport.Header.Get("Content-Disposition"))
	}
	var exported TaskResultExport
	if err := json.NewDecoder(jsonExport.Body).Decode(&exported); err != nil {
		jsonExport.Body.Close()
		t.Fatal(err)
	}
	jsonExport.Body.Close()
	if exported.TaskID != task.ID || exported.Status != "COMPLETED" || len(exported.Findings) != 1 {
		t.Fatalf("unexpected json export: %+v", exported)
	}

	csvExport := get("/api/v1/tasks/"+task.ID+"/export?format=csv", cookie)
	if csvExport.StatusCode != http.StatusOK {
		csvExport.Body.Close()
		t.Fatalf("csv export: %d", csvExport.StatusCode)
	}
	rows, err := csv.NewReader(csvExport.Body).ReadAll()
	csvExport.Body.Close()
	if err != nil || len(rows) != 2 || len(rows[0]) != len(taskExportHeader) {
		t.Fatalf("unexpected csv export: rows=%d err=%v", len(rows), err)
	}

	invalid := get("/api/v1/tasks/"+task.ID+"/export?format=xml", cookie)
	if invalid.StatusCode != http.StatusBadRequest {
		invalid.Body.Close()
		t.Fatalf("invalid task export format: %d", invalid.StatusCode)
	}
	invalid.Body.Close()
}

func TestTaskCSVExportEscapesFormulaCells(t *testing.T) {
	data, err := renderTaskCSV(TaskResultExport{
		TaskID: "task-example", Status: "COMPLETED", CreatedAt: "2026-10-21T00:00:00Z", TargetCount: 1, FindingCount: 1,
		Findings: []TaskResultFinding{{ID: "finding-example", Severity: "HIGH", Title: "=HYPERLINK()", Target: "192.0.2.10:80", Engine: "nuclei", TemplateOrCVE: "@template", Package: "+package"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(strings.NewReader(string(data))).ReadAll()
	if err != nil || len(rows) != 2 {
		t.Fatalf("csv rows: %d err=%v", len(rows), err)
	}
	if rows[1][8] != "'=HYPERLINK()" || rows[1][13] != "'@template" || rows[1][16] != "'+package" {
		t.Fatalf("formula cells were not escaped: %#v", rows[1])
	}
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
