package repo

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"scanner-platform/internal/portprobe"
	"scanner-platform/internal/rules"
	"scanner-platform/internal/taskflow"
)

func TestFindingRetestReusesFrozenScopeAndBlocksDuplicates(t *testing.T) {
	store, actor, finding := dispositionFixture(t)
	ctx := context.Background()
	task, retest, err := store.CreateFindingRetest(ctx, finding.ID, actor)
	if err != nil {
		t.Fatal(err)
	}
	if task.RetestFindingID != finding.ID || task.Status != "PENDING" || len(task.Chunks) != 1 || len(task.Chunks[0].Targets) != 1 || task.Chunks[0].Targets[0] != finding.Target {
		t.Fatalf("unexpected retest task: %+v", task)
	}
	if retest.ID == "" || retest.FindingID != finding.ID || retest.TaskID != task.ID || retest.Status != "PENDING" || retest.Actor != actor {
		t.Fatalf("unexpected retest relation: %+v", retest)
	}
	if _, _, err := store.CreateFindingRetest(ctx, finding.ID, actor); !errors.Is(err, ErrTaskConflict) {
		t.Fatalf("duplicate active retest was accepted: %v", err)
	}
	history, err := store.ListFindingRetests(ctx, finding.ID)
	if err != nil || len(history) != 1 || history[0].TaskID != task.ID {
		t.Fatalf("unexpected retest history: %+v %v", history, err)
	}
	var auditDetail string
	if err := store.db.QueryRowContext(ctx, `SELECT detail FROM audit_logs WHERE action='retest_finding' AND object_id=?`, finding.ID).Scan(&auditDetail); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(auditDetail, finding.Target) || strings.Contains(auditDetail, finding.TemplateOrCVE) {
		t.Fatalf("retest audit leaked finding data: %s", auditDetail)
	}
	if err := store.CancelTask(ctx, task.ID, actor); err != nil {
		t.Fatal(err)
	}
	second, _, err := store.CreateFindingRetest(ctx, finding.ID, actor)
	if err != nil || second.ID == task.ID {
		t.Fatalf("canceled retest did not allow a new attempt: %+v %v", second, err)
	}
}

func TestFindingRetestRejectsUnsupportedOrOutOfScopeFindings(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name   string
		mutate func(*RuntimeStore, string, string) error
	}{
		{name: "false positive", mutate: func(store *RuntimeStore, id, _ string) error {
			items, err := store.ListRuntimeFindings(ctx)
			if err != nil || len(items) != 1 {
				return err
			}
			items[0].Status = "FALSE_POSITIVE"
			raw, _ := json.Marshal(items[0])
			_, err = store.db.ExecContext(ctx, `UPDATE security_findings SET data=? WHERE id=?`, string(raw), id)
			return err
		}},
		{name: "out of scope", mutate: func(store *RuntimeStore, id, _ string) error {
			items, err := store.ListRuntimeFindings(ctx)
			if err != nil || len(items) != 1 {
				return err
			}
			items[0].Target = "192.0.2.20:443"
			raw, _ := json.Marshal(items[0])
			_, err = store.db.ExecContext(ctx, `UPDATE security_findings SET data=? WHERE id=?`, string(raw), id)
			return err
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store, actor, finding := dispositionFixture(t)
			if err := tc.mutate(store, finding.ID, actor); err != nil {
				t.Fatal(err)
			}
			if _, _, err := store.CreateFindingRetest(ctx, finding.ID, actor); !errors.Is(err, ErrInvalidTask) {
				t.Fatalf("unsupported retest was accepted: %v", err)
			}
			var count int
			if err := store.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM finding_retests WHERE finding_id=?`, finding.ID).Scan(&count); err != nil || count != 0 {
				t.Fatalf("retest relation changed after rejection: %d %v", count, err)
			}
		})
	}
}

func TestFindingRetestRejectsSyntheticAndMissingFindings(t *testing.T) {
	ctx := context.Background()
	store, actor := localFixture(t)
	task, err := store.CreateSyntheticTask(ctx)
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := store.ClaimRuntimeTask(ctx, "synthetic-retest-worker")
	if err != nil || claimed == nil {
		t.Fatal(claimed, err)
	}
	if err := store.CompleteRuntimeTask(ctx, taskflow.Report{TaskID: task.ID, WorkerID: "synthetic-retest-worker", Target: claimed.Chunks[0].Targets[0], Title: taskflow.SyntheticTitle}); err != nil {
		t.Fatal(err)
	}
	items, err := store.ListRuntimeFindings(ctx)
	if err != nil || len(items) != 1 {
		t.Fatal(items, err)
	}
	if _, _, err := store.CreateFindingRetest(ctx, items[0].ID, actor); !errors.Is(err, ErrInvalidTask) {
		t.Fatalf("synthetic finding retest was accepted: %v", err)
	}
	if _, err := store.ListFindingRetests(ctx, "missing-finding"); !errors.Is(err, ErrTaskConflict) {
		t.Fatalf("missing finding history did not fail closed: %v", err)
	}
}

func TestFindingRetestAutoUsesExactResolvedPorts(t *testing.T) {
	store, actor := localFixture(t)
	ctx := context.Background()
	bundle, _ := json.Marshal(rules.Bundle{Version: "20261021.01", Engines: []string{"nuclei", "trivy"}, IsCurrent: true, IntegrityVerified: true})
	if _, err := store.db.ExecContext(ctx, `INSERT INTO local_rule_bundles(version,data) VALUES(?,?)`, "20261021.01", string(bundle)); err != nil {
		t.Fatal(err)
	}
	var assetID string
	if err := store.db.QueryRowContext(ctx, `SELECT id FROM assets WHERE address=?`, "192.0.2.20").Scan(&assetID); err != nil {
		t.Fatal(err)
	}
	input := taskflow.TaskInput{Engine: "auto", AssetID: assetID, PortProbe: portprobe.Config{Preset: portprobe.PresetCustom, Ranges: []portprobe.Range{{Start: 22, End: 22}, {Start: 80, End: 80}}, OpsApproved: true}}
	parent, err := store.CreateLocalTask(ctx, input, actor)
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := store.ClaimRuntimeTask(ctx, "auto-retest-worker")
	if err != nil || claimed == nil {
		t.Fatal(claimed, err)
	}
	if err := store.CompleteRuntimeTask(ctx, taskflow.Report{
		TaskID: parent.ID, WorkerID: "auto-retest-worker", Status: "COMPLETED",
		SystemScanStatus: taskflow.SystemScanCompleted, ApplicationScanStatus: taskflow.ApplicationScanNotConfigured,
		PortProbeResults: []taskflow.PortProbeResult{{Port: 22}, {Port: 80}},
		ServiceResults:   []taskflow.ServiceResult{{Port: 22, Kind: "OTHER"}, {Port: 80, Kind: "HTTP", Scheme: "http"}},
		Findings:         []taskflow.Detection{{Engine: "nuclei", Target: "192.0.2.20:80", TemplateID: "fixture-auto", Title: "fixture auto", Severity: "LOW", MatchedPath: "/"}},
		CompletedFully:   true, RulesExecuted: true, ExecutedEngines: []string{"nuclei"}, RuleVersion: claimed.RuleVersion,
	}); err != nil {
		t.Fatal(err)
	}
	findings, err := store.ListRuntimeFindings(ctx)
	if err != nil || len(findings) != 1 {
		t.Fatal(findings, err)
	}
	child, _, err := store.CreateFindingRetest(ctx, findings[0].ID, actor)
	if err != nil {
		t.Fatal(err)
	}
	if child.AssetID != assetID || len(child.PortProbePorts) != 2 || child.PortProbePorts[0] != 22 || child.PortProbePorts[1] != 80 || child.Chunks[0].Targets[0] != "192.0.2.20" {
		t.Fatalf("auto retest expanded or changed scope: %+v", child)
	}
}

func TestFindingRetestAuditFailureRollsBackTaskAndRelation(t *testing.T) {
	store, actor, finding := dispositionFixture(t)
	ctx := context.Background()
	var before int
	if err := store.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM scan_tasks`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, `CREATE TRIGGER fail_finding_retest_audit BEFORE INSERT ON audit_logs
		WHEN NEW.action='retest_finding' BEGIN SELECT RAISE(ABORT,'audit failure'); END`); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.CreateFindingRetest(ctx, finding.ID, actor); err == nil {
		t.Fatal("audit failure was ignored")
	}
	var after, relations int
	if err := store.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM scan_tasks`).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM finding_retests WHERE finding_id=?`, finding.ID).Scan(&relations); err != nil {
		t.Fatal(err)
	}
	if before != after || relations != 0 {
		t.Fatalf("audit failure left retest state: tasks %d -> %d, relations %d", before, after, relations)
	}
}
