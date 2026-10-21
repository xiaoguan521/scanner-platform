package repo

import (
	"errors"
	"testing"
)

func TestValidPostgresTaskRequiresExplicitNumericTargets(t *testing.T) {
	base := ScanTask{
		ID:        "task-1",
		ScopeID:   "scope-1",
		Status:    "PENDING",
		CreatedBy: "user-1",
		Engines:   []string{"nuclei"},
		Targets:   []string{"192.0.2.10:8080"},
	}
	for _, test := range []struct {
		name   string
		mutate func(*ScanTask)
		valid  bool
	}{
		{name: "valid", valid: true},
		{name: "hostname", mutate: func(task *ScanTask) { task.Targets = []string{"example.test:443"} }},
		{name: "cidr", mutate: func(task *ScanTask) { task.Targets = []string{"192.0.2.0/24:443"} }},
		{name: "unspecified", mutate: func(task *ScanTask) { task.Targets = []string{"0.0.0.0:443"} }},
		{name: "bad port", mutate: func(task *ScanTask) { task.Targets = []string{"192.0.2.10:0"} }},
		{name: "missing engine", mutate: func(task *ScanTask) { task.Engines = nil }},
	} {
		t.Run(test.name, func(t *testing.T) {
			task := base
			if test.mutate != nil {
				test.mutate(&task)
			}
			if got := validPostgresTask(task); got != test.valid {
				t.Fatalf("validPostgresTask()=%v, want %v for %+v", got, test.valid, task)
			}
		})
	}
}

func TestNewPostgresTaskStoreRejectsNilDatabase(t *testing.T) {
	if _, err := NewPostgresTaskStore(nil); !errors.Is(err, ErrPostgresDSNRequired) {
		t.Fatalf("nil database error=%v, want %v", err, ErrPostgresDSNRequired)
	}
}
