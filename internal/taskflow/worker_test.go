package taskflow

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
