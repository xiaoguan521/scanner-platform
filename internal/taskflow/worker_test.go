package taskflow

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestWorkerPausesLocallyAtDeadline(t *testing.T) {
	reports := make(chan Report, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/worker/claim":
			json.NewEncoder(w).Encode(Task{ID: "test-deadline", Synthetic: true, HardDeadline: time.Now().Add(30 * time.Millisecond).UTC().Format(time.RFC3339Nano), Chunks: []Chunk{{Targets: []string{"192.0.2.20:80"}}}})
		case "/api/v1/worker/report":
			var report Report
			if err := json.NewDecoder(r.Body).Decode(&report); err != nil {
				t.Error(err)
			}
			reports <- report
			w.WriteHeader(200)
		default:
			t.Errorf("unexpected request %s", r.URL.Path)
			w.WriteHeader(400)
		}
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	worker := Worker{ServerURL: server.URL, ID: "deadline-worker", Delay: time.Hour, Client: server.Client()}
	if err := worker.Run(ctx, true); err != nil {
		t.Fatal(err)
	}
	select {
	case report := <-reports:
		if report.Status != "PAUSED_WINDOW" || report.Title != "" {
			t.Fatalf("deadline produced a success result: %+v", report)
		}
	default:
		t.Fatal("deadline was not reported")
	}
}

func TestOversizedEngineResultReportsFailureInsteadOfLeavingTaskRunning(t *testing.T) {
	var received Report
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/worker/claim":
			_ = json.NewEncoder(w).Encode(Task{ID: "large-result", Engines: []string{"trivy"}, Chunks: []Chunk{{Targets: []string{"fixture"}}}})
		case "/api/v1/worker/report":
			r.Body = http.MaxBytesReader(w, r.Body, MaxReportBytes)
			if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
				t.Error(err)
				w.WriteHeader(400)
				return
			}
			w.WriteHeader(200)
		default:
			w.WriteHeader(400)
		}
	}))
	defer server.Close()
	worker := Worker{ServerURL: server.URL, ID: "worker", Client: server.Client(), Execute: func(context.Context, Task) ([]Detection, error) {
		results := make([]Detection, 1200)
		for i := range results {
			results[i] = Detection{Engine: "trivy", Target: "fixture", TemplateID: "fixture", Title: "Fixture", Description: strings.Repeat("x", 4000)}
		}
		return results, nil
	}}
	if _, err := worker.ProcessOne(context.Background()); err != nil {
		t.Fatal(err)
	}
	if received.Status != "FAILED" || len(received.Findings) != 0 || received.Error == "" {
		t.Fatalf("oversized result did not report a bounded failure: %+v", received)
	}
}

func TestWorkerReportsOnlyDeliberatePublicExecutionErrors(t *testing.T) {
	for _, test := range []struct {
		name string
		err  error
		want string
	}{
		{"coverage", &ExecutionError{UserMessage: "该发行版尚未适配漏洞源"}, "该发行版尚未适配漏洞源"},
		{"private", fmt.Errorf("private engine diagnostic fixture"), "引擎执行失败，请检查节点状态、规则库、输入和 Worker 日志"},
		{"oversize", &ExecutionError{UserMessage: strings.Repeat("x", 501)}, "引擎执行失败，请检查节点状态、规则库、输入和 Worker 日志"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var received Report
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/api/v1/worker/claim":
					_ = json.NewEncoder(w).Encode(Task{ID: "fixture", Engines: []string{"trivy"}, Chunks: []Chunk{{Targets: []string{"lab-a/os"}}}})
				case "/api/v1/worker/report":
					if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
						t.Error(err)
					}
					w.WriteHeader(200)
				default:
					w.WriteHeader(400)
				}
			}))
			defer server.Close()
			worker := Worker{ServerURL: server.URL, ID: "worker", Client: server.Client(), Execute: func(context.Context, Task) ([]Detection, error) { return nil, test.err }}
			if _, err := worker.ProcessOne(context.Background()); err != nil {
				t.Fatal(err)
			}
			if received.Status != "FAILED" || received.Error != test.want || len(received.Findings) != 0 {
				t.Fatal(received)
			}
		})
	}
}

func TestWorkerReportsPortProbeResultsWithoutFindings(t *testing.T) {
	var received Report
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/worker/claim":
			_ = json.NewEncoder(w).Encode(Task{ID: "port-probe-task", AssetID: "asset-fixture", Engines: []string{"port-probe"}, PortProbePorts: []int{80, 443}, Chunks: []Chunk{{Targets: []string{"192.0.2.20"}}}})
		case "/api/v1/worker/report":
			if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
				t.Error(err)
			}
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer server.Close()
	worker := Worker{ServerURL: server.URL, ID: "probe-worker", Client: server.Client(), ProbePorts: func(_ context.Context, task Task) ([]PortProbeResult, error) {
		if task.AssetID != "asset-fixture" || len(task.PortProbePorts) != 2 {
			t.Fatalf("unexpected task: %+v", task)
		}
		return []PortProbeResult{{Port: 443}}, nil
	}}
	worked, err := worker.ProcessOne(context.Background())
	if err != nil || !worked {
		t.Fatalf("probe task did not complete: worked=%v err=%v", worked, err)
	}
	if received.Status != "COMPLETED" || len(received.Findings) != 0 || len(received.PortProbeResults) != 1 || received.PortProbeResults[0].Port != 443 {
		t.Fatalf("unexpected probe report: %+v", received)
	}
}
