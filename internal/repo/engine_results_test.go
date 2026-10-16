package repo

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"scanner-platform/internal/rules"
	"scanner-platform/internal/taskflow"
)

func TestRealTasksMultipleResultsDedupAndFailure(t *testing.T) {
	store, actor := localFixture(t)
	ctx := context.Background()
	input := taskflow.TaskInput{Engine: "nuclei", Scheme: "http", Targets: []string{"192.0.2.20:80", "192.0.2.20:443"}}
	if _, err := store.CreateLocalTask(ctx, input, actor); !errors.Is(err, ErrInvalidTask) {
		t.Fatal("missing rules accepted", err)
	}
	data, _ := json.Marshal(rules.Bundle{Version: "20261016.01", Engines: []string{"nuclei", "trivy"}, IsCurrent: true, IntegrityVerified: true})
	if _, err := store.db.ExecContext(ctx, "INSERT INTO local_rule_bundles(version,data) VALUES(?,?)", "20261016.01", string(data)); err != nil {
		t.Fatal(err)
	}
	for iteration := 0; iteration < 2; iteration++ {
		created, err := store.CreateLocalTask(ctx, input, actor)
		if err != nil {
			t.Fatal(err)
		}
		if created.Synthetic || len(created.SkippedTargets) != 1 {
			t.Fatal(created)
		}
		task, err := store.ClaimRuntimeTask(ctx, "real-worker")
		if err != nil || task == nil {
			t.Fatal(task, err)
		}
		report := taskflow.Report{TaskID: task.ID, WorkerID: "real-worker", Status: "COMPLETED", Findings: []taskflow.Detection{
			{Engine: "nuclei", TemplateID: "header-one", Target: "192.0.2.20:80", Title: "Header one", Severity: "LOW", MatchedPath: "/"},
			{Engine: "nuclei", TemplateID: "header-two", Target: "192.0.2.20:80", Title: "Header two", Severity: "INFO", MatchedPath: "/"},
		}}
		wrong := report
		wrong.WorkerID = "other"
		if err := store.CompleteRuntimeTask(ctx, wrong); !errors.Is(err, ErrTaskConflict) {
			t.Fatal("wrong worker accepted", err)
		}
		wrong = report
		wrong.Findings = append([]taskflow.Detection{}, report.Findings...)
		wrong.Findings[0].Target = "192.0.2.20:443"
		if err := store.CompleteRuntimeTask(ctx, wrong); !errors.Is(err, ErrInvalidTask) {
			t.Fatal("skipped target result accepted", err)
		}
		wrong.Findings[0] = report.Findings[0]
		wrong.Findings[0].Engine = "zap"
		if err := store.CompleteRuntimeTask(ctx, wrong); !errors.Is(err, ErrInvalidTask) {
			t.Fatal("wrong engine accepted", err)
		}
		for range 2 {
			if err := store.CompleteRuntimeTask(ctx, report); err != nil {
				t.Fatal(err)
			}
		}
		findings, err := store.ListRuntimeFindings(ctx)
		if err != nil || len(findings) != 2 {
			t.Fatal("dedup or multiple finding failure", findings, err)
		}
		if findings[0].Synthetic || findings[0].BusinessGroup != "QA" {
			t.Fatal(findings[0])
		}
		if iteration == 0 {
			if _, err := store.UpdateFinding(ctx, findings[0].ID, "FALSE_POSITIVE", actor); err != nil {
				t.Fatal(err)
			}
		} else {
			found := false
			for _, f := range findings {
				found = found || f.Status == "FALSE_POSITIVE"
			}
			if !found {
				t.Fatal("repeat scan overwrote review state")
			}
		}
	}
	input.Engine = "zap"
	created, err := store.CreateLocalTask(ctx, input, actor)
	if err != nil {
		t.Fatal(err)
	}
	task, err := store.ClaimRuntimeTask(ctx, "real-worker")
	if err != nil || task.ID != created.ID {
		t.Fatal(task, err)
	}
	if err := store.CompleteRuntimeTask(ctx, taskflow.Report{TaskID: task.ID, WorkerID: "real-worker", Status: "FAILED", Error: "fixture failure"}); err != nil {
		t.Fatal(err)
	}
	tasks, _ := store.ListRuntimeTasks(ctx)
	if tasks[0].Status != "FAILED" || tasks[0].Error != "fixture failure" {
		t.Fatal(tasks[0])
	}
}

func TestTrivyInputAndZeroFindingsCompletion(t *testing.T) {
	store, actor := localFixture(t)
	ctx := context.Background()
	data, _ := json.Marshal(rules.Bundle{Version: "20261016.01", Engines: []string{"trivy"}, IsCurrent: true, IntegrityVerified: true})
	if _, err := store.db.ExecContext(ctx, "INSERT INTO local_rule_bundles(version,data) VALUES(?,?)", "20261016.01", string(data)); err != nil {
		t.Fatal(err)
	}
	input := taskflow.TaskInput{Engine: "trivy", InputKind: "filesystem", InputPath: "deps/local-fixture"}
	for _, path := range []string{"../outside", "/absolute", "https://example.com", "C:\\secret"} {
		bad := input
		bad.InputPath = path
		if _, err := store.CreateLocalTask(ctx, bad, actor); !errors.Is(err, ErrInvalidTask) {
			t.Fatal(path, err)
		}
	}
	if _, err := store.CreateLocalTask(ctx, input, actor); err != nil {
		t.Fatal(err)
	}
	task, err := store.ClaimRuntimeTask(ctx, "worker")
	if err != nil || task == nil || task.InputPath != input.InputPath {
		t.Fatal(task, err)
	}
	if err := store.CompleteRuntimeTask(ctx, taskflow.Report{TaskID: task.ID, WorkerID: "worker", Status: "COMPLETED"}); err != nil {
		t.Fatal(err)
	}
	findings, _ := store.ListRuntimeFindings(ctx)
	if len(findings) != 0 {
		t.Fatal("zero findings manufactured a finding")
	}
}

func TestImageFingerprintUsesImageIdentityAcrossArchiveNames(t *testing.T) {
	store, actor := localFixture(t)
	ctx := context.Background()
	data, _ := json.Marshal(rules.Bundle{Version: "20261016.01", Engines: []string{"trivy"}, IsCurrent: true, IntegrityVerified: true})
	if _, err := store.db.ExecContext(ctx, "INSERT INTO local_rule_bundles(version,data) VALUES(?,?)", "20261016.01", string(data)); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"images/first.tar", "images/renamed.tar"} {
		if _, err := store.CreateLocalTask(ctx, taskflow.TaskInput{Engine: "trivy", InputKind: "image-archive", InputPath: path}, actor); err != nil {
			t.Fatal(err)
		}
		task, err := store.ClaimRuntimeTask(ctx, "worker")
		if err != nil || task == nil {
			t.Fatal(task, err)
		}
		report := taskflow.Report{TaskID: task.ID, WorkerID: "worker", Status: "COMPLETED", Findings: []taskflow.Detection{{Engine: "trivy", Target: path, TemplateID: "CVE-2099-0001", Title: "fixture", Severity: "HIGH", Package: "fixture", InstalledVersion: "1.0", MatchedPath: path, ArtifactID: "sha256:0000000000000000000000000000000000000000000000000000000000000001"}}}
		if err := store.CompleteRuntimeTask(ctx, report); err != nil {
			t.Fatal(err)
		}
	}
	findings, err := store.ListRuntimeFindings(ctx)
	if err != nil || len(findings) != 1 {
		t.Fatalf("image duplicated after rename: %+v %v", findings, err)
	}
}

func TestLateEngineCompletionPausesWithoutFinding(t *testing.T) {
	store, actor := localFixture(t)
	ctx := context.Background()
	created, err := store.CreateLocalTask(ctx, taskflow.TaskInput{Engine: "zap", Scheme: "http", Targets: []string{"192.0.2.20:80"}}, actor)
	if err != nil {
		t.Fatal(err)
	}
	task, err := store.ClaimRuntimeTask(ctx, "worker")
	if err != nil || task.ID != created.ID {
		t.Fatal(task, err)
	}
	if _, err := store.db.ExecContext(ctx, `UPDATE scan_tasks SET details=json_set(details,'$.deadline',?) WHERE id=?`, time.Now().Add(-time.Second).Format(time.RFC3339Nano), task.ID); err != nil {
		t.Fatal(err)
	}
	if err := store.CompleteRuntimeTask(ctx, taskflow.Report{TaskID: task.ID, WorkerID: "worker", Status: "COMPLETED"}); !errors.Is(err, ErrTaskConflict) {
		t.Fatal(err)
	}
	tasks, _ := store.ListRuntimeTasks(ctx)
	if tasks[0].Status != "PAUSED_WINDOW" {
		t.Fatal(tasks[0])
	}
	findings, _ := store.ListRuntimeFindings(ctx)
	if len(findings) != 0 {
		t.Fatal("late result persisted")
	}
}

func TestLegacySingleFindingSchemaKeepsStoredRows(t *testing.T) {
	store, _ := localFixture(t)
	ctx := context.Background()
	if err := store.SeedSyntheticTask(ctx); err != nil {
		t.Fatal(err)
	}
	task, err := store.ClaimRuntimeTask(ctx, "worker")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CompleteRuntimeTask(ctx, taskflow.Report{TaskID: task.ID, WorkerID: "worker", Target: task.Chunks[0].Targets[0], Title: taskflow.SyntheticTitle}); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{`CREATE TABLE early_findings(id TEXT PRIMARY KEY,task_id TEXT NOT NULL UNIQUE REFERENCES scan_tasks(id),data TEXT NOT NULL)`, `INSERT INTO early_findings SELECT * FROM security_findings`, `DROP TABLE security_findings`, `ALTER TABLE early_findings RENAME TO security_findings`} {
		if _, err := store.db.ExecContext(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := NewRuntime(store.db); err != nil {
		t.Fatal(err)
	}
	findings, err := store.ListRuntimeFindings(ctx)
	if err != nil || len(findings) != 1 || !findings[0].Synthetic || findings[0].TaskID != task.ID {
		t.Fatal(findings, err)
	}
}
