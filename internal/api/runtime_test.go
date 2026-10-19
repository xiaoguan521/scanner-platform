package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"scanner-platform/internal/account"
	"scanner-platform/internal/assets"
	"scanner-platform/internal/repo"
	"scanner-platform/internal/taskflow"
)

func TestRuntimeWorkerHTTPFlow(t *testing.T) {
	store, err := repo.OpenRuntime(filepath.Join(t.TempDir(), "platform.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.SeedSyntheticTask(context.Background()); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(NewRuntimeHandler(store, nil, ""))
	defer server.Close()
	worker := &taskflow.Worker{ServerURL: server.URL, ID: "worker-test", Client: server.Client()}
	worked, err := worker.ProcessOne(context.Background())
	if err != nil || !worked {
		t.Fatalf("worker execution: worked=%v err=%v", worked, err)
	}
	if worked, err := worker.ProcessOne(context.Background()); err != nil || worked {
		t.Fatalf("completed task was reissued: worked=%v err=%v", worked, err)
	}
	for _, path := range []string{"/api/v1/tasks", "/api/v1/findings"} {
		response, err := server.Client().Get(server.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		var body struct {
			Items []map[string]any `json:"items"`
			Total int              `json:"total"`
		}
		err = json.NewDecoder(response.Body).Decode(&body)
		response.Body.Close()
		if err != nil || response.StatusCode != http.StatusOK || body.Total != 1 || len(body.Items) != 1 || body.Items[0]["synthetic"] != true {
			t.Fatalf("%s: response=%+v err=%v", path, body, err)
		}
		if path == "/api/v1/tasks" && body.Items[0]["status"] != "COMPLETED" {
			t.Fatalf("task not completed: %+v", body)
		}
	}
}

func TestRuntimeServesUIAndRejectsInvalidTaskRequests(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte("<h1>Local scanner UI</h1>"), 0600); err != nil {
		t.Fatal(err)
	}
	store, err := repo.OpenRuntime(filepath.Join(t.TempDir(), "platform.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	handler := NewRuntimeHandler(store, nil, dir)
	for _, tc := range []struct {
		method, path, body string
		want               int
	}{
		{"GET", "/", "", 200},
		{"GET", "/readyz", "", 200},
		{"POST", "/api/v1/tasks", `{"synthetic":true}`, 201},
		{"POST", "/api/v1/tasks", `{"synthetic":false}`, 400},
		{"POST", "/api/v1/tasks", `{"synthetic":true} {}`, 400},
		{"POST", "/api/v1/tasks", `{"synthetic":true,"engine":"nuclei"}`, 400},
		{"POST", "/api/v1/worker/claim", `{"workerId":""}`, 400},
		{"POST", "/api/v1/worker/report", `{"taskId":"missing"}`, 409},
	} {
		t.Run(tc.method+tc.path+tc.body, func(t *testing.T) {
			out := httptest.NewRecorder()
			handler.ServeHTTP(out, httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body)))
			if out.Code != tc.want {
				t.Fatalf("status=%d want=%d body=%s", out.Code, tc.want, out.Body.String())
			}
		})
	}
}

func TestRuntimeAcceptsFullRangePortProbePlan(t *testing.T) {
	accounts, err := account.New(filepath.Join(t.TempDir(), "platform.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer accounts.Close()
	registry, err := assets.New(accounts.SQLDB())
	if err != nil {
		t.Fatal(err)
	}
	asset, err := registry.Create(context.Background(), "local-test", assets.Input{Kind: "host", Address: "192.0.2.20", BusinessGroup: "QA", Owner: "Example"})
	if err != nil {
		t.Fatal(err)
	}
	store, err := repo.NewRuntime(accounts.SQLDB())
	if err != nil {
		t.Fatal(err)
	}
	handler := NewRuntimeHandler(store, nil, "")
	send := func(body string) *httptest.ResponseRecorder {
		out := httptest.NewRecorder()
		handler.ServeHTTP(out, httptest.NewRequest(http.MethodPost, "/api/v1/tasks", strings.NewReader(body)))
		return out
	}
	response := send(`{"synthetic":false,"engine":"port-probe","assetId":"` + asset.ID + `","portProbe":{"preset":"custom","ranges":[{"start":8000,"end":8004}],"exclusions":[{"start":8001,"end":8001}],"opsApproved":true},"targets":[],"timeWindows":[]}`)
	if response.Code != http.StatusCreated {
		t.Fatalf("port probe task rejected: %d %s", response.Code, response.Body.String())
	}
	var task taskflow.Task
	if err := json.NewDecoder(response.Body).Decode(&task); err != nil {
		t.Fatal(err)
	}
	want := []int{8000, 8002, 8003, 8004}
	if len(task.Engines) != 1 || task.Engines[0] != "port-probe" || task.TargetCount != 1 || len(task.PortProbePorts) != len(want) {
		t.Fatalf("unexpected bounded task plan: %+v", task)
	}
	for index, port := range want {
		if task.PortProbePorts[index] != port {
			t.Fatalf("unexpected effective ports: %v", task.PortProbePorts)
		}
	}
	fullRange := send(`{"synthetic":false,"engine":"port-probe","assetId":"` + asset.ID + `","portProbe":{"preset":"custom","ranges":[{"start":1,"end":65535}],"exclusions":[{"start":443,"end":443}],"opsApproved":true},"targets":[],"timeWindows":[]}`)
	if fullRange.Code != http.StatusCreated {
		t.Fatalf("full TCP port range rejected: %d %s", fullRange.Code, fullRange.Body.String())
	}
	if err := json.NewDecoder(fullRange.Body).Decode(&task); err != nil {
		t.Fatal(err)
	}
	if len(task.PortProbePorts) != 65534 || task.PortProbePorts[0] != 1 || task.PortProbePorts[len(task.PortProbePorts)-1] != 65535 {
		t.Fatalf("full range was not dispatched with its exclusion applied: count=%d first/last=%v", len(task.PortProbePorts), task.PortProbePorts)
	}
	for _, port := range task.PortProbePorts {
		if port == 443 {
			t.Fatal("excluded port 443 was dispatched")
		}
	}
	tooWide := send(`{"synthetic":false,"engine":"port-probe","assetId":"` + asset.ID + `","portProbe":{"preset":"custom","ranges":[{"start":1,"end":65536}],"opsApproved":true},"targets":[],"timeWindows":[]}`)
	if tooWide.Code != http.StatusBadRequest {
		t.Fatalf("invalid port range accepted: %d %s", tooWide.Code, tooWide.Body.String())
	}
}
