package repo

import (
	"context"
	"encoding/json"
	"net"
	"testing"
	"time"

	"scanner-platform/internal/reporting"
)

// Regression: automatic scans store a bare IP in their task chunks, while
// observations are identified by IP:port. These must resolve to one asset
// without mixing observations from another task on the same host.
func TestReportScopeRegressionBareIPAndSameHostTasks(t *testing.T) {
	store, _ := reportTestStore(t)
	ctx := context.Background()
	reportSeed(t, store)

	var initialID string
	if err := store.db.QueryRowContext(ctx, "SELECT id FROM scan_tasks LIMIT 1").Scan(&initialID); err != nil {
		t.Fatal(err)
	}
	autoTask, err := store.createRuntimeTask(ctx, "auto-ip-only", []string{"192.0.2.10"})
	if err != nil {
		t.Fatal(err)
	}
	recordReportObservation(t, store, autoTask.ID, "auto-http-check", "192.0.2.10", "8443")

	original := reportSnapshotFor(t, store, reporting.Scope{TaskID: initialID})
	if len(original.Assets) != 1 || len(original.Tasks) != 1 || len(original.Findings) != 1 ||
		original.Findings[0].Title != "原始发现" {
		t.Fatalf("first task included another task's history: assets=%d tasks=%d findings=%+v",
			len(original.Assets), len(original.Tasks), original.Findings)
	}
	auto := reportSnapshotFor(t, store, reporting.Scope{TaskID: autoTask.ID})
	if len(auto.Assets) != 1 || auto.Assets[0].Address != "192.0.2.10" ||
		len(auto.Tasks) != 1 || len(auto.Findings) != 1 ||
		auto.Findings[0].Title != "auto-http-check" || auto.Findings[0].AssetAddress != "192.0.2.10" {
		t.Fatalf("IP-only task lost IP:port observation: assets=%+v tasks=%d findings=%+v",
			auto.Assets, len(auto.Tasks), auto.Findings)
	}
	all := reportSnapshotFor(t, store, reporting.Scope{})
	if len(all.Findings) != 2 {
		t.Fatalf("unfiltered history mismatch: %+v", all.Findings)
	}
}

func TestReportScopeRegressionBusinessGroupFiltersTasksAndFindings(t *testing.T) {
	store, _ := reportTestStore(t)
	ctx := context.Background()
	reportSeed(t, store)

	created := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := store.db.ExecContext(ctx, `INSERT INTO assets(id,kind,address,business_group,owner,created_at)
		VALUES ('asset-other','host','192.0.2.11','其他业务组','其他责任人',?)`, created); err != nil {
		t.Fatal(err)
	}
	otherTask, err := store.createRuntimeTask(ctx, "other-group-task", []string{"192.0.2.11:8080"})
	if err != nil {
		t.Fatal(err)
	}
	recordReportObservation(t, store, otherTask.ID, "other-group-finding", "192.0.2.11", "8080")

	selected := reportSnapshotFor(t, store, reporting.Scope{BusinessGroup: "示例业务组"})
	if len(selected.Assets) != 1 || len(selected.Tasks) != 1 || len(selected.Findings) != 1 ||
		selected.Assets[0].Address != "192.0.2.10" || selected.Findings[0].Title != "原始发现" {
		t.Fatalf("business group leaked other targets: assets=%+v tasks=%+v findings=%+v",
			selected.Assets, selected.Tasks, selected.Findings)
	}
	other := reportSnapshotFor(t, store, reporting.Scope{BusinessGroup: "其他业务组"})
	if len(other.Assets) != 1 || len(other.Tasks) != 1 || len(other.Findings) != 1 ||
		other.Assets[0].Address != "192.0.2.11" || other.Findings[0].Title != "other-group-finding" {
		t.Fatalf("other group report mismatch: assets=%+v tasks=%+v findings=%+v",
			other.Assets, other.Tasks, other.Findings)
	}

	if _, err := store.CreateReport(ctx, reporting.Request{
		Format: "html", Scope: reporting.Scope{TaskID: otherTask.ID, BusinessGroup: "示例业务组"},
	}, "test-user"); err == nil {
		t.Fatal("contradictory task+business group silently produced an empty report")
	}
}

func recordReportObservation(t *testing.T, store *RuntimeStore, taskID, title, host, port string) {
	t.Helper()
	ctx := context.Background()
	f := reporting.Finding{
		ID: title, TaskID: taskID, Fingerprint: title, RiskType: "web",
		TemplateOrCVE: "example-header", Title: title,
		Target: net.JoinHostPort(host, port), Severity: "MEDIUM",
		DetectMethod: "configuration", Confidence: "high", LastSeen: time.Now().UTC(),
	}
	data, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, `INSERT INTO security_findings(id,task_id,data) VALUES (?,?,?)`,
		f.ID, taskID, string(data)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, `INSERT INTO task_finding_observations(task_id,finding_id,data) VALUES (?,?,?)`,
		taskID, f.ID, string(data)); err != nil {
		t.Fatal(err)
	}
}

func reportSnapshotFor(t *testing.T, store *RuntimeStore, scope reporting.Scope) reporting.Snapshot {
	t.Helper()
	ctx := context.Background()
	job, err := store.CreateReport(ctx, reporting.Request{Format: "html", Scope: scope}, "report-test")
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := store.ReportSnapshot(ctx, job.SnapshotID)
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}
