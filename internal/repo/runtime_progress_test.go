package repo

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"scanner-platform/internal/taskflow"
)

func TestRuntimeTaskProgressAllowsBoundedAutomaticPhases(t *testing.T) {
	tests := []struct {
		name   string
		update taskflow.ProgressUpdate
		want   bool
	}{
		{name: "service identification", update: taskflow.ProgressUpdate{Phase: "service_identification", Completed: 2, Total: 4}, want: true},
		{name: "http baseline", update: taskflow.ProgressUpdate{Phase: "http_scan", Completed: 1, Total: 4}, want: true},
		{name: "ssh one step", update: taskflow.ProgressUpdate{Phase: "ssh_collection", Completed: 1, Total: 1}, want: true},
		{name: "trivy one step", update: taskflow.ProgressUpdate{Phase: "trivy_scan", Completed: 0, Total: 1}, want: true},
		{name: "application batch", update: taskflow.ProgressUpdate{Phase: "application_scan", Completed: 8, Total: 8}, want: true},
		{name: "application batch too large", update: taskflow.ProgressUpdate{Phase: "application_scan", Completed: 257, Total: 257}, want: false},
		{name: "automatic phase exceeds ports", update: taskflow.ProgressUpdate{Phase: "http_scan", Completed: 5, Total: 11}, want: false},
		{name: "ssh exceeds one step", update: taskflow.ProgressUpdate{Phase: "ssh_collection", Completed: 2, Total: 2}, want: false},
		{name: "unknown phase", update: taskflow.ProgressUpdate{Phase: "other", Completed: 0, Total: 0}, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := validRuntimeTaskProgress("auto", 10, tt.update); got != tt.want {
				t.Fatalf("validRuntimeTaskProgress()=%v, want %v", got, tt.want)
			}
		})
	}
}

func TestRuntimeTaskProgressUsesAutomaticProbePortTotal(t *testing.T) {
	store, err := OpenRuntime(filepath.Join(t.TempDir(), "runtime.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	detail, err := json.Marshal(taskDetails{
		Input:      taskflow.TaskInput{Engine: "auto"},
		ProbePorts: []int{80, 8080},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := store.db.ExecContext(ctx, `INSERT INTO scan_tasks(id,status,worker_id,created_at,targets,details) VALUES(?,?,?,?,?,?)`,
		"auto-progress", "RUNNING", "worker", time.Now().UTC().Format(time.RFC3339Nano), `["192.0.2.10"]`, string(detail)); err != nil {
		t.Fatal(err)
	}
	for _, update := range []taskflow.ProgressUpdate{
		{TaskID: "auto-progress", Phase: "service_identification", Completed: 0, Total: 2},
		{TaskID: "auto-progress", Phase: "service_identification", Completed: 2, Total: 2},
		{TaskID: "auto-progress", Phase: "http_scan", Completed: 1, Total: 2},
	} {
		if err := store.UpdateRuntimeTaskProgress(ctx, "worker", update); err != nil {
			t.Fatalf("automatic progress update %+v rejected: %v", update, err)
		}
	}
	if err := store.UpdateRuntimeTaskProgress(ctx, "worker", taskflow.ProgressUpdate{TaskID: "auto-progress", Phase: "http_scan", Completed: 3, Total: 3}); err == nil {
		t.Fatal("automatic progress exceeding dispatched ports accepted")
	}
}

func TestRuntimeTaskProgressAllowsSingleEngineCompletion(t *testing.T) {
	if !validRuntimeTaskProgress("nuclei", 0, taskflow.ProgressUpdate{Phase: "engine_scan", Completed: 1, Total: 1}) {
		t.Fatal("completed engine progress rejected")
	}
	if validRuntimeTaskProgress("nuclei", 0, taskflow.ProgressUpdate{Phase: "engine_scan", Completed: 2, Total: 2}) {
		t.Fatal("over-complete engine progress accepted")
	}
}

func TestRuntimeTaskProgressStoresLivePortsAndRejectsUndispatched(t *testing.T) {
	store, err := OpenRuntime(filepath.Join(t.TempDir(), "runtime.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	detail, _ := json.Marshal(taskDetails{Input: taskflow.TaskInput{Engine: "auto"}, ProbePorts: []int{22, 80, 8080}})
	ctx := context.Background()
	if _, err := store.db.ExecContext(ctx, `INSERT INTO scan_tasks(id,status,worker_id,created_at,targets,details) VALUES(?,?,?,?,?,?)`,
		"live-ports", "RUNNING", "worker", time.Now().UTC().Format(time.RFC3339Nano), `["192.0.2.10"]`, string(detail)); err != nil {
		t.Fatal(err)
	}
	for _, update := range []taskflow.ProgressUpdate{
		{TaskID: "live-ports", Phase: "tcp_probe", Completed: 3, Total: 3},
		{TaskID: "live-ports", Phase: "service_identification", Total: 2, OpenPorts: []int{22, 80}},
		{TaskID: "live-ports", Phase: "http_scan", Total: 1, HTTPPorts: []int{80}, Services: []taskflow.LiveService{{Port: 80, Kind: "HTTP", Scheme: "http", Software: "nginx", Version: "1.24", Title: "Home"}, {Port: 22, Kind: "OTHER"}}},
		{TaskID: "live-ports", Phase: "http_scan", Completed: 1, Total: 1}, // later counter keeps the lists
	} {
		if err := store.UpdateRuntimeTaskProgress(ctx, "worker", update); err != nil {
			t.Fatalf("update %+v rejected: %v", update, err)
		}
	}
	progress, err := store.runtimeTaskProgress(ctx)
	if err != nil {
		t.Fatal(err)
	}
	got := progress["live-ports"]
	if len(got.OpenPorts) != 2 || len(got.HTTPPorts) != 1 || got.Phases["tcp_probe"].Total != 3 || got.Phases["service_identification"].Total != 2 || len(got.Services) != 2 || got.Services[0].Software != "nginx" {
		t.Fatalf("stored progress = %+v", got)
	}
	for _, bad := range []taskflow.ProgressUpdate{
		{TaskID: "live-ports", Phase: "http_scan", Completed: 1, Total: 1, OpenPorts: []int{443}},
		{TaskID: "live-ports", Phase: "http_scan", Completed: 1, Total: 1, HTTPPorts: []int{80, 80}},
		{TaskID: "live-ports", Phase: "http_scan", Completed: 1, Total: 1, Services: []taskflow.LiveService{{Port: 443, Kind: "HTTP", Scheme: "https"}}},
		{TaskID: "live-ports", Phase: "http_scan", Completed: 1, Total: 1, Services: []taskflow.LiveService{{Port: 80, Kind: "HTTP", Scheme: "gopher"}}},
		{TaskID: "live-ports", Phase: "http_scan", Completed: 1, Total: 1, Services: []taskflow.LiveService{{Port: 80, Kind: "OTHER", Title: string(make([]byte, 0)) + "ok\x00"}}},
	} {
		if err := store.UpdateRuntimeTaskProgress(ctx, "worker", bad); err == nil {
			t.Fatalf("invalid live ports accepted: %+v", bad)
		}
	}
}
