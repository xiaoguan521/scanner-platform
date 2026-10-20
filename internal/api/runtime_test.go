package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"scanner-platform/internal/account"
	"scanner-platform/internal/assets"
	"scanner-platform/internal/portprobe"
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

func TestRuntimeWorkerPauseResumeAndIdempotentCompletion(t *testing.T) {
	ctx := context.Background()
	store, err := repo.OpenRuntime(filepath.Join(t.TempDir(), "platform.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	created, err := store.CreateSyntheticTask(ctx)
	if err != nil {
		t.Fatal(err)
	}

	// The local API normally assigns a fifteen-minute deadline to a task with
	// no explicit window. Override only the first claim in this test so the
	// worker reaches its local deadline without sleeping for a real window.
	apiHandler := NewRuntimeHandler(store, nil, "")
	var shortened atomic.Bool
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/worker/claim", func(w http.ResponseWriter, r *http.Request) {
		recorded := httptest.NewRecorder()
		apiHandler.ServeHTTP(recorded, r)
		body := recorded.Body.Bytes()
		if recorded.Code == http.StatusOK && !shortened.Swap(true) {
			var claimed taskflow.Task
			if err := json.Unmarshal(body, &claimed); err != nil {
				t.Fatalf("decode claimed task: %v", err)
			}
			claimed.HardDeadline = time.Now().Add(30 * time.Millisecond).UTC().Format(time.RFC3339Nano)
			body, err = json.Marshal(claimed)
			if err != nil {
				t.Fatalf("encode shortened task: %v", err)
			}
		}
		for key, values := range recorded.Header() {
			for _, value := range values {
				w.Header().Add(key, value)
			}
		}
		w.WriteHeader(recorded.Code)
		_, _ = w.Write(body)
	})
	mux.Handle("/", apiHandler)
	server := httptest.NewServer(mux)
	defer server.Close()

	worker := &taskflow.Worker{
		ServerURL: server.URL,
		ID:        "pause-resume-worker",
		Client:    server.Client(),
		Delay:     100 * time.Millisecond,
	}
	if worked, err := worker.ProcessOne(ctx); err != nil || !worked {
		t.Fatalf("deadline pause was not reported: worked=%v err=%v", worked, err)
	}
	tasks, err := store.ListRuntimeTasks(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(tasks) != 1 || tasks[0].ID != created.ID || tasks[0].Status != "PAUSED_WINDOW" {
		t.Fatalf("task was not paused: %+v", tasks)
	}
	findings, err := store.ListRuntimeFindings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("paused task inserted findings: %+v", findings)
	}

	if err := store.Tick(ctx, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	tasks, err = store.ListRuntimeTasks(ctx)
	if err != nil || len(tasks) != 1 || tasks[0].Status != "PENDING" {
		t.Fatalf("paused task did not resume into the queue: %+v err=%v", tasks, err)
	}

	worker.Delay = 0
	if worked, err := worker.ProcessOne(ctx); err != nil || !worked {
		t.Fatalf("resumed task did not complete: worked=%v err=%v", worked, err)
	}
	tasks, err = store.ListRuntimeTasks(ctx)
	if err != nil || len(tasks) != 1 || tasks[0].Status != "COMPLETED" {
		t.Fatalf("resumed task not completed: %+v err=%v", tasks, err)
	}
	findings, err = store.ListRuntimeFindings(ctx)
	if err != nil || len(findings) != 1 {
		t.Fatalf("resumed task result missing or duplicated: %+v err=%v", findings, err)
	}

	// A retry of the accepted report is harmless and cannot create a second
	// finding. This is the same payload a Worker would retry after a response
	// was lost.
	duplicate := taskflow.Report{
		TaskID:   created.ID,
		WorkerID: worker.ID,
		Target:   created.Chunks[0].Targets[0],
		Title:    taskflow.SyntheticTitle,
	}
	body, err := json.Marshal(duplicate)
	if err != nil {
		t.Fatal(err)
	}
	response, err := server.Client().Post(server.URL+"/api/v1/worker/report", "application/json", strings.NewReader(string(body)))
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("duplicate completion rejected: %d", response.StatusCode)
	}
	findings, err = store.ListRuntimeFindings(ctx)
	if err != nil || len(findings) != 1 {
		t.Fatalf("duplicate completion changed findings: %+v err=%v", findings, err)
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
	fullRange := send(`{"synthetic":false,"engine":"port-probe","assetId":"` + asset.ID + `","portProbe":{"preset":"custom","ranges":[{"start":1,"end":65535}],"exclusions":[{"start":443,"end":443}],"opsApproved":true,"fullConfirmed":true},"targets":[],"timeWindows":[]}`)
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

func TestRuntimeWorkerRenewAPIValidatesLeaseBinding(t *testing.T) {
	ctx := context.Background()
	accounts, err := account.New(filepath.Join(t.TempDir(), "platform.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer accounts.Close()
	registry, err := assets.New(accounts.SQLDB())
	if err != nil {
		t.Fatal(err)
	}
	asset, err := registry.Create(ctx, "local-test", assets.Input{Kind: "host", Address: "192.0.2.20", BusinessGroup: "QA", Owner: "Example"})
	if err != nil {
		t.Fatal(err)
	}
	store, err := repo.NewRuntime(accounts.SQLDB())
	if err != nil {
		t.Fatal(err)
	}
	store.LeaseDuration = time.Second
	created, err := store.CreateLocalTask(ctx, taskflow.TaskInput{
		Engine: "port-probe", AssetID: asset.ID,
		PortProbe: portprobe.Config{Preset: portprobe.PresetCustom, Ranges: []portprobe.Range{{Start: 1234, End: 1234}}, OpsApproved: true},
	}, "local-test")
	if err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(NewRuntimeHandler(store, nil, ""))
	defer server.Close()
	response, err := server.Client().Post(server.URL+"/api/v1/worker/claim", "application/json", strings.NewReader(`{"workerId":"api-lease-worker"}`))
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		response.Body.Close()
		t.Fatalf("claim status=%d", response.StatusCode)
	}
	var claimed taskflow.Task
	if err := json.NewDecoder(response.Body).Decode(&claimed); err != nil {
		response.Body.Close()
		t.Fatal(err)
	}
	response.Body.Close()
	if claimed.ID != created.ID || len(claimed.Chunks) != 1 || claimed.Chunks[0].PinnedRuleVersion == "" || claimed.Chunks[0].LeaseExpiresAt == nil {
		t.Fatalf("claim omitted lease binding: %+v", claimed)
	}

	payload := `{"taskId":"` + claimed.ID + `","workerId":"api-lease-worker","pinnedRuleVersion":"` + claimed.Chunks[0].PinnedRuleVersion + `"}`
	response, err = server.Client().Post(server.URL+"/api/v1/worker/renew", "application/json", strings.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(response.Body)
		response.Body.Close()
		t.Fatalf("valid renewal status=%d body=%s", response.StatusCode, body)
	}
	var renewed struct {
		LeaseExpiresAt time.Time `json:"leaseExpiresAt"`
	}
	if err := json.NewDecoder(response.Body).Decode(&renewed); err != nil {
		response.Body.Close()
		t.Fatal(err)
	}
	response.Body.Close()
	if renewed.LeaseExpiresAt.IsZero() || !renewed.LeaseExpiresAt.After(*claimed.Chunks[0].LeaseExpiresAt) {
		t.Fatalf("valid renewal did not extend lease: claimed=%s renewed=%s", claimed.Chunks[0].LeaseExpiresAt, renewed.LeaseExpiresAt)
	}

	badPayload := strings.Replace(payload, `"pinnedRuleVersion":"`+claimed.Chunks[0].PinnedRuleVersion+`"`, `"pinnedRuleVersion":"wrong-version"`, 1)
	response, err = server.Client().Post(server.URL+"/api/v1/worker/renew", "application/json", strings.NewReader(badPayload))
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusConflict {
		t.Fatalf("wrong version renewal status=%d, want %d", response.StatusCode, http.StatusConflict)
	}
}

func TestWorkerHeartbeatPersistsRuleReadinessAndLocalVersion(t *testing.T) {
	store, err := repo.OpenRuntime(filepath.Join(t.TempDir(), "platform.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	server := httptest.NewServer(NewRuntimeHandler(store, nil, ""))
	defer server.Close()

	postHeartbeat := func(body string) *http.Response {
		response, err := server.Client().Post(server.URL+"/api/v1/nodes/heartbeat", "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		return response
	}
	response := postHeartbeat(`{"id":"rules-worker","kind":"worker","status":"WAITING_FOR_RULES","localRuleVersion":""}`)
	if response.StatusCode != http.StatusOK {
		response.Body.Close()
		t.Fatalf("waiting heartbeat status=%d", response.StatusCode)
	}
	response.Body.Close()
	response, err = server.Client().Get(server.URL + "/api/v1/nodes")
	if err != nil {
		t.Fatal(err)
	}
	var list ListResponse[repo.LocalNode]
	if err := json.NewDecoder(response.Body).Decode(&list); err != nil {
		response.Body.Close()
		t.Fatal(err)
	}
	response.Body.Close()
	if len(list.Items) != 1 || list.Items[0].Status != taskflow.NodeStatusWaitingForRules || list.Items[0].BoundRuleVersion != "" {
		t.Fatalf("waiting rule state not persisted: %+v", list.Items)
	}

	response = postHeartbeat(`{"id":"rules-worker","kind":"worker","status":"ONLINE","localRuleVersion":"20261020.05"}`)
	if response.StatusCode != http.StatusOK {
		response.Body.Close()
		t.Fatalf("ready heartbeat status=%d", response.StatusCode)
	}
	response.Body.Close()
	response, err = server.Client().Get(server.URL + "/api/v1/nodes")
	if err != nil {
		t.Fatal(err)
	}
	list = ListResponse[repo.LocalNode]{}
	if err := json.NewDecoder(response.Body).Decode(&list); err != nil {
		response.Body.Close()
		t.Fatal(err)
	}
	response.Body.Close()
	if len(list.Items) != 1 || list.Items[0].Status != "ONLINE" || list.Items[0].BoundRuleVersion != "20261020.05" {
		t.Fatalf("ready rule state not persisted: %+v", list.Items)
	}

	response = postHeartbeat(`{"id":"rules-worker","kind":"worker","status":"WAITING_FOR_RULES","localRuleVersion":""}`)
	if response.StatusCode != http.StatusOK {
		response.Body.Close()
		t.Fatalf("waiting heartbeat after ready status=%d", response.StatusCode)
	}
	response.Body.Close()
	response, err = server.Client().Get(server.URL + "/api/v1/nodes")
	if err != nil {
		t.Fatal(err)
	}
	list = ListResponse[repo.LocalNode]{}
	if err := json.NewDecoder(response.Body).Decode(&list); err != nil {
		response.Body.Close()
		t.Fatal(err)
	}
	response.Body.Close()
	if len(list.Items) != 1 || list.Items[0].Status != taskflow.NodeStatusWaitingForRules || list.Items[0].BoundRuleVersion != "" {
		t.Fatalf("stale rule version was retained after waiting state: %+v", list.Items)
	}
}

func TestWorkerRuleReadinessAPIRejectsInvalidBindings(t *testing.T) {
	store, err := repo.OpenRuntime(filepath.Join(t.TempDir(), "platform.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	server := httptest.NewServer(NewRuntimeHandler(store, nil, ""))
	defer server.Close()
	post := func(path, body string) int {
		response, err := server.Client().Post(server.URL+path, "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		return response.StatusCode
	}
	if got := post("/api/v1/worker/claim", `{"workerId":"rules-worker","localRuleVersion":"bad","rulesReady":true}`); got != http.StatusBadRequest {
		t.Fatalf("invalid local rule version status=%d", got)
	}
	if got := post("/api/v1/worker/claim", `{"workerId":"rules-worker","localRuleVersion":"20261020.05","rulesReady":false}`); got != http.StatusBadRequest {
		t.Fatalf("inconsistent rule readiness status=%d", got)
	}
	if got := post("/api/v1/nodes/heartbeat", `{"id":"rules-worker","kind":"worker","status":"WAITING_FOR_RULES","localRuleVersion":"20261020.05"}`); got != http.StatusBadRequest {
		t.Fatalf("waiting heartbeat with version status=%d", got)
	}
}
