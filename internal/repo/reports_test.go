package repo

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"scanner-platform/internal/reporting"
)

func reportTestStore(t *testing.T) (*RuntimeStore, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "reports.db")
	s, err := OpenRuntime(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	if err := s.InitReports(context.Background()); err != nil {
		t.Fatal(err)
	}
	return s, path
}
func reportSeed(t *testing.T, s *RuntimeStore) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err := s.db.ExecContext(ctx, `INSERT INTO assets(id,kind,address,business_group,owner,created_at) VALUES ('asset-example','host','192.0.2.10','示例业务组','示例责任人',?)`, now)
	if err != nil {
		t.Fatal(err)
	}
	task, err := s.CreateSyntheticTask(ctx)
	if err != nil {
		t.Fatal(err)
	}
	finding := reporting.Finding{ID: "finding-example", TaskID: task.ID, Fingerprint: "fp-example", RiskType: "web", TemplateOrCVE: "example-header", Title: "原始发现", Target: "192.0.2.10:8080", Severity: "HIGH", DetectMethod: "configuration", Confidence: "high", LastSeen: time.Now().UTC()}
	data, _ := json.Marshal(finding)
	if _, err := s.db.ExecContext(ctx, `INSERT INTO security_findings(id,task_id,data) VALUES (?,?,?)`, finding.ID, task.ID, string(data)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.ExecContext(ctx, `INSERT INTO task_finding_observations(task_id,finding_id,data) VALUES (?,?,?)`, task.ID, finding.ID, string(data)); err != nil {
		t.Fatal(err)
	}
}
func TestReportFrozenTemplateDataRetryAndPersistentHistory(t *testing.T) {
	s, path := reportTestStore(t)
	ctx := context.Background()
	reportSeed(t, s)
	job, err := s.CreateReport(ctx, reporting.Request{Format: "html"}, "test-user")
	if err != nil {
		t.Fatal(err)
	}
	if job.Status != "QUEUED" || job.SnapshotVersion != 1 || job.SnapshotID == "" {
		t.Fatalf("job: %+v", job)
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE security_findings SET data=replace(data,'原始发现','之后改变')`); err != nil {
		t.Fatal(err)
	}
	template := reporting.DefaultTemplate()
	template.Company = "之后改变公司"
	if _, err := s.SaveReportTemplate(ctx, template, "test-user"); err != nil {
		t.Fatal(err)
	}
	snap, err := s.ReportSnapshot(ctx, job.SnapshotID)
	if err != nil {
		t.Fatal(err)
	}
	if snap.Findings[0].Title != "原始发现" || snap.Template.Company == "之后改变公司" {
		t.Fatal("frozen snapshot changed")
	}
	blocked := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocked, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	if done, err := s.ProcessNextReport(ctx, blocked); err != nil || !done {
		t.Fatalf("generation: %v %v", done, err)
	}
	failed, err := s.GetReport(ctx, job.ID)
	if err != nil || failed.Status != "FAILED" || failed.Error == "" {
		t.Fatalf("expected retryable failure: %+v %v", failed, err)
	}
	retry, err := s.RetryReport(ctx, job.ID, "test-user")
	if err != nil || retry.SnapshotID != job.SnapshotID {
		t.Fatalf("retry did not preserve snapshot: %+v %v", retry, err)
	}
	dir := t.TempDir()
	if _, err := s.ProcessNextReport(ctx, dir); err != nil {
		t.Fatal(err)
	}
	ready, file, err := s.OpenReport(ctx, job.ID)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(file.Name())
	file.Close()
	if err != nil {
		t.Fatal(err)
	}
	if ready.Status != "READY" || ready.FileSize != int64(len(data)) || ready.Attempts != 2 || !strings.Contains(string(data), "原始发现") || strings.Contains(string(data), "之后改变") {
		t.Fatalf("artifact mismatch: %+v", ready)
	}
	other, err := OpenRuntime(path)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	history, err := other.ListReports(ctx)
	if err != nil || len(history) != 1 || history[0].Status != "READY" {
		t.Fatalf("history: %+v %v", history, err)
	}
	if _, err := s.RetryReport(ctx, job.ID, "test-user"); err != ErrReportConflict {
		t.Fatalf("ready job retried: %v", err)
	}
}
func TestReportTaskScopeUsesHistoricalObservations(t *testing.T) {
	s, _ := reportTestStore(t)
	ctx := context.Background()
	reportSeed(t, s)
	var taskID string
	if err := s.db.QueryRowContext(ctx, `SELECT id FROM scan_tasks LIMIT 1`).Scan(&taskID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE security_findings SET data=replace(data,'原始发现','最新发现')`); err != nil {
		t.Fatal(err)
	}
	job, err := s.CreateReport(ctx, reporting.Request{Format: "xlsx", Scope: reporting.Scope{TaskID: taskID}}, "test-user")
	if err != nil {
		t.Fatal(err)
	}
	snap, err := s.ReportSnapshot(ctx, job.SnapshotID)
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Findings) != 1 || snap.Findings[0].Title != "原始发现" || len(snap.Tasks) != 1 {
		t.Fatalf("task report used current findings: %+v", snap)
	}
	if _, err := s.CreateReport(ctx, reporting.Request{Format: "docx", Scope: reporting.Scope{TaskID: "missing"}}, "test-user"); err == nil {
		t.Fatal("missing task accepted")
	}
}
func TestReportRecoveryAndClaimOnce(t *testing.T) {
	s, _ := reportTestStore(t)
	ctx := context.Background()
	job, err := s.CreateReport(ctx, reporting.Request{Format: "docx"}, "test-user")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE report_jobs SET status='GENERATING' WHERE id=?`, job.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.RecoverReports(ctx); err != nil {
		t.Fatal(err)
	}
	if done, err := s.ProcessNextReport(ctx, t.TempDir()); err != nil || !done {
		t.Fatalf("recover generation: %v %v", done, err)
	}
	if done, err := s.ProcessNextReport(ctx, t.TempDir()); err != nil || done {
		t.Fatalf("job claimed twice: %v %v", done, err)
	}
}

func TestReportOtherFormatsReuseFrozenSnapshotAfterChanges(t *testing.T) {
	s, _ := reportTestStore(t)
	ctx := context.Background()
	reportSeed(t, s)
	first, err := s.CreateReport(ctx, reporting.Request{Format: "html"}, "original-creator")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ProcessNextReport(ctx, t.TempDir()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE security_findings SET data=replace(data,'原始发现','之后发现')`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE assets SET owner='之后责任人'`); err != nil {
		t.Fatal(err)
	}
	tpl := reporting.DefaultTemplate()
	tpl.Name = "之后方案"
	if _, err := s.SaveReportTemplate(ctx, tpl, "test-user"); err != nil {
		t.Fatal(err)
	}
	for _, format := range []string{"xlsx", "docx", "csv", "json"} {
		other, err := s.CreateReportFormat(ctx, first.ID, format, "format-creator")
		if err != nil {
			t.Fatal(err)
		}
		if other.ID == first.ID || other.SnapshotID != first.SnapshotID || other.Name != first.Name || other.Format != format || other.CreatedBy != "format-creator" {
			t.Fatalf("derived job: %+v", other)
		}
		snap, err := s.ReportSnapshot(ctx, other.SnapshotID)
		if err != nil {
			t.Fatal(err)
		}
		if snap.Findings[0].Title != "原始发现" || snap.Assets[0].Owner == "之后责任人" || snap.Template.Name == "之后方案" {
			t.Fatal("other format re-read mutable data")
		}
		if done, err := s.ProcessNextReport(ctx, t.TempDir()); err != nil || !done {
			t.Fatalf("derived generation: %v %v", done, err)
		}
		ready, file, err := s.OpenReport(ctx, other.ID)
		if err != nil {
			t.Fatal(err)
		}
		file.Close()
		if ready.Status != "READY" {
			t.Fatal("other format not generated")
		}
	}
	if _, err := s.CreateReportFormat(ctx, first.ID, "pdf", "test-user"); err == nil {
		t.Fatal("invalid derivative format accepted")
	}
}

func TestReportRecoveryReplacesExistingOrphanArtifact(t *testing.T) {
	s, _ := reportTestStore(t)
	ctx := context.Background()
	job, err := s.CreateReport(ctx, reporting.Request{Format: "html"}, "test-user")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, job.ID+".html")
	if err := os.WriteFile(path, []byte("orphan from interrupted generation"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE report_jobs SET status='GENERATING' WHERE id=?`, job.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.RecoverReports(ctx); err != nil {
		t.Fatal(err)
	}
	if done, err := s.ProcessNextReport(ctx, dir); err != nil || !done {
		t.Fatalf("regeneration: %v %v", done, err)
	}
	ready, file, err := s.OpenReport(ctx, job.ID)
	if err != nil {
		t.Fatal(err)
	}
	file.Close()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if ready.Status != "READY" || strings.Contains(string(content), "orphan from") || !strings.Contains(string(content), job.SnapshotID) {
		t.Fatalf("orphan was not replaced: %+v", ready)
	}
}
