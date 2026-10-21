package repo

import (
	"database/sql"
	"errors"
	"testing"

	"scanner-platform/internal/taskflow"
)

func TestNewPostgresTaskProjectionRejectsNilDatabase(t *testing.T) {
	if _, err := NewPostgresTaskProjection(nil); !errors.Is(err, ErrPostgresDSNRequired) {
		t.Fatalf("expected postgres DSN error, got %v", err)
	}
}

func TestValidPostgresProjectionTask(t *testing.T) {
	tests := []struct {
		name string
		task taskflow.Task
		ok   bool
	}{
		{name: "valid", task: taskflow.Task{ID: "task-1", Status: "PENDING", TotalChunks: 1}, ok: true},
		{name: "bad status", task: taskflow.Task{ID: "task-1", Status: "UNKNOWN"}, ok: false},
		{name: "completed exceeds total", task: taskflow.Task{ID: "task-1", TotalChunks: 1, CompletedChunks: 2}, ok: false},
		{name: "newline id", task: taskflow.Task{ID: "task\n1"}, ok: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := validPostgresProjectionTask(tt.task); got != tt.ok {
				t.Fatalf("validPostgresProjectionTask()=%v, want %v", got, tt.ok)
			}
		})
	}
}

func TestPostgresTaskProjectionProgressValidation(t *testing.T) {
	if !validPostgresProgressIdentity("worker-1", taskflow.ProgressUpdate{TaskID: "task-1", Phase: "tcp_probe", Completed: 1, Total: 2}) {
		t.Fatal("valid progress rejected")
	}
	if validPostgresProgressIdentity("worker-1", taskflow.ProgressUpdate{TaskID: "task-1", Phase: "tcp_probe", Completed: 3, Total: 2}) {
		t.Fatal("invalid progress accepted")
	}
	if validPostgresProgressIdentity("worker\n1", taskflow.ProgressUpdate{TaskID: "task-1", Phase: "tcp_probe", Total: 1}) {
		t.Fatal("newline worker accepted")
	}
}

func TestPostgresTaskProjectionErrorsDoNotExposeDatabase(t *testing.T) {
	var db *sql.DB
	projection, err := NewPostgresTaskProjection(db)
	if err == nil || projection != nil {
		t.Fatal("nil database should not create projection")
	}
}
