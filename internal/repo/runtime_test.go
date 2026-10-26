package repo

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"

	"scanner-platform/internal/taskflow"
)

func TestRuntimeTaskPersistsAndReportsAreIdempotent(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "platform.db")
	store, err := OpenRuntime(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := store.CreateSyntheticTask(ctx); err != nil {
		t.Fatal(err)
	}
	tasks, err := store.ListRuntimeTasks(ctx)
	if err != nil || len(tasks) != 1 || tasks[0].Status != "PENDING" {
		t.Fatalf("synthetic fixture task: %+v, %v", tasks, err)
	}
	task, err := store.ClaimRuntimeTask(ctx, "worker-test")
	if err != nil || task == nil || task.Status != "RUNNING" {
		t.Fatalf("claim: %+v, %v", task, err)
	}
	report := taskflow.Report{TaskID: task.ID, WorkerID: "worker-test", Target: task.Chunks[0].Targets[0], Title: taskflow.SyntheticTitle}
	wrong := report
	wrong.WorkerID = "worker-other"
	if err := store.CompleteRuntimeTask(ctx, wrong); !errors.Is(err, ErrTaskConflict) {
		t.Fatalf("another worker completed task: %v", err)
	}
	wrong = report
	wrong.Target = "198.51.100.10:443"
	if err := store.CompleteRuntimeTask(ctx, wrong); !errors.Is(err, ErrTaskConflict) {
		t.Fatalf("out-of-task result accepted: %v", err)
	}
	for range 2 {
		if err := store.CompleteRuntimeTask(ctx, report); err != nil {
			t.Fatal(err)
		}
	}
	other, err := OpenRuntime(path)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	tasks, err = other.ListRuntimeTasks(ctx)
	if err != nil || len(tasks) != 1 || tasks[0].Status != "COMPLETED" || tasks[0].CompletedChunks != 1 {
		t.Fatalf("saved completion: %+v, %v", tasks, err)
	}
	findings, err := other.ListRuntimeFindings(ctx)
	if err != nil || len(findings) != 1 || !findings[0].Synthetic || findings[0].Title != taskflow.SyntheticTitle {
		t.Fatalf("saved synthetic finding: %+v, %v", findings, err)
	}
}

func TestRuntimeAtomicClaimAcrossConnections(t *testing.T) {
	path := filepath.Join(t.TempDir(), "platform.db")
	first, err := OpenRuntime(path)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := OpenRuntime(path)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if _, err := first.CreateSyntheticTask(context.Background()); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	claimed := make(chan string, 2)
	for i, store := range []*RuntimeStore{first, second} {
		wg.Go(func() {
			worker := []string{"worker-a", "worker-b"}[i]
			task, err := store.ClaimRuntimeTask(context.Background(), worker)
			if err != nil {
				t.Errorf("claim: %v", err)
			} else if task != nil {
				claimed <- task.ID
			}
		})
	}
	wg.Wait()
	close(claimed)
	if len(claimed) != 1 {
		t.Fatalf("same queued task claimed %d times", len(claimed))
	}
}

func TestNextLiveProgressKeepsFinishedPhasesAndFoundPorts(t *testing.T) {
	history := nextLiveProgress("", "", 0, taskflow.ProgressUpdate{Phase: "tcp_probe", Total: 65535})
	history = nextLiveProgress(history, "tcp_probe", 65535, taskflow.ProgressUpdate{Phase: "service_identification", Total: 2, OpenPorts: []int{22, 80}})
	history = nextLiveProgress(history, "service_identification", 2, taskflow.ProgressUpdate{Phase: "http_scan", Total: 1, HTTPPorts: []int{80}})
	history = nextLiveProgress(history, "http_scan", 1, taskflow.ProgressUpdate{Phase: "http_scan", Completed: 1, Total: 1})
	live := decodeLiveProgress(history)
	if live.Phases["tcp_probe"] != (taskflow.PhaseCount{Completed: 65535, Total: 65535}) || live.Phases["service_identification"] != (taskflow.PhaseCount{Completed: 2, Total: 2}) {
		t.Fatalf("phases = %#v", live.Phases)
	}
	if len(live.OpenPorts) != 2 || len(live.HTTPPorts) != 1 || live.HTTPPorts[0] != 80 {
		t.Fatalf("found ports were lost: %#v", live)
	}
	if nextLiveProgress("", "", 0, taskflow.ProgressUpdate{Phase: "tcp_probe", Total: 3}) != "" || decodeLiveProgress("not json").Phases != nil {
		t.Fatal("empty or corrupt history must stay empty")
	}
}

func TestValidLivePortsRejectsUndispatchedDuplicateAndOversized(t *testing.T) {
	dispatched := map[int]bool{22: true, 80: true}
	if !validLivePorts([]int{22, 80}, dispatched) || !validLivePorts(nil, dispatched) {
		t.Fatal("dispatched ports must be accepted")
	}
	if validLivePorts([]int{443}, dispatched) || validLivePorts([]int{80, 80}, dispatched) {
		t.Fatal("undispatched or duplicate ports must be rejected")
	}
	many := make([]int, taskflow.MaxLivePorts+1)
	all := map[int]bool{}
	for i := range many {
		many[i] = i + 1
		all[i+1] = true
	}
	if validLivePorts(many, all) {
		t.Fatal("oversized lists must be rejected")
	}
}
