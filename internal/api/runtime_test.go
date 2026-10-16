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
