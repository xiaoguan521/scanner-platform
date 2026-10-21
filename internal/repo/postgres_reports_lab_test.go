//go:build lab

package repo

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"scanner-platform/internal/reporting"
	"scanner-platform/internal/taskflow"
)

func TestPostgresReportStoreLab(t *testing.T) {
	dsnFile := os.Getenv("POSTGRES_DSN_FILE")
	if dsnFile == "" {
		t.Skip("set POSTGRES_DSN_FILE to an isolated PostgreSQL fixture")
	}
	dsn, err := ReadPostgresDSNFile(filepath.Clean(dsnFile))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	db, err := OpenPostgres(ctx, PostgresConfig{DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := MigratePostgres(ctx, db); err != nil {
		t.Fatal(err)
	}

	const (
		userID    = "lab-postgres-report-user"
		reviewer  = "lab-postgres-report-reviewer"
		assetID   = "lab-postgres-report-asset"
		scopeID   = "lab-postgres-report-scope"
		taskID    = "lab-postgres-report-task"
		findingID = "finding-lab-postgres-report"
	)
	cleanup := func() {
		_, _ = db.ExecContext(ctx, `DELETE FROM report_jobs WHERE data::jsonb ->> 'createdBy'=$1`, userID)
		_, _ = db.ExecContext(ctx, `DELETE FROM audit_logs WHERE actor=$1`, userID)
		_, _ = db.ExecContext(ctx, `DELETE FROM audit_logs WHERE object_id IN ($1,$2)`, taskID, findingID)
		_, _ = db.ExecContext(ctx, `DELETE FROM task_finding_observations WHERE task_id=$1`, taskID)
		_, _ = db.ExecContext(ctx, `DELETE FROM finding_projections WHERE finding_id=$1`, findingID)
		_, _ = db.ExecContext(ctx, `DELETE FROM finding_events WHERE finding_id=$1`, findingID)
		_, _ = db.ExecContext(ctx, `DELETE FROM security_findings WHERE id=$1`, findingID)
		_, _ = db.ExecContext(ctx, `DELETE FROM scan_task_projections WHERE task_id=$1`, taskID)
		_, _ = db.ExecContext(ctx, `DELETE FROM scan_task_progress WHERE task_id=$1`, taskID)
		_, _ = db.ExecContext(ctx, `DELETE FROM scan_task_chunks WHERE task_id=$1`, taskID)
		_, _ = db.ExecContext(ctx, `DELETE FROM scan_tasks WHERE id=$1`, taskID)
		_, _ = db.ExecContext(ctx, `DELETE FROM authorized_scopes WHERE id=$1`, scopeID)
		_, _ = db.ExecContext(ctx, `DELETE FROM asset_profiles WHERE asset_id=$1`, assetID)
		_, _ = db.ExecContext(ctx, `DELETE FROM asset_services WHERE asset_id=$1`, assetID)
		_, _ = db.ExecContext(ctx, `DELETE FROM asset_login_entries WHERE asset_id=$1`, assetID)
		_, _ = db.ExecContext(ctx, `DELETE FROM asset_ports WHERE asset_id=$1`, assetID)
		_, _ = db.ExecContext(ctx, `DELETE FROM assets WHERE id=$1`, assetID)
		_, _ = db.ExecContext(ctx, `DELETE FROM users WHERE id IN ($1,$2)`, userID, reviewer)
	}
	cleanup()
	defer cleanup()
	for _, user := range []struct{ id, name string }{{userID, "lab_report_user"}, {reviewer, "lab_report_reviewer"}} {
		if _, err := db.ExecContext(ctx, `INSERT INTO users(id,username,role,is_active,password_hash)
			VALUES ($1,$2,'admin',TRUE,'fixture-only')`, user.id, user.name); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO assets(id,kind,address,business_group,owner)
		VALUES ($1,'host','192.0.2.41','fixture','fixture-owner')`, assetID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO asset_profiles(asset_id,data)
		VALUES ($1,'{"name":"fixture host","osName":"Debian","osFamily":"linux"}')`, assetID); err != nil {
		t.Fatal(err)
	}
	service := `{"port":8080,"protocol":"tcp","state":"open","kind":"HTTP","scheme":"http","software":"Apache","version":"2.4","loginEntries":[]}`
	if _, err := db.ExecContext(ctx, `INSERT INTO asset_services(asset_id,port,data) VALUES ($1,8080,$2)`, assetID, service); err != nil {
		t.Fatal(err)
	}
	login := `{"type":"web","name":"fixture login","port":8080,"url":"http://192.0.2.41:8080/login","https":false}`
	if _, err := db.ExecContext(ctx, `INSERT INTO asset_login_entries(asset_id,entry_key,data) VALUES ($1,'web:8080:fixture',$2)`, assetID, login); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO asset_ports(asset_id,port,kind,source) VALUES ($1,8080,'WEB','fixture')`, assetID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO authorized_scopes
		(id,asset_id,cidr_or_host,max_targets,time_windows,requested_by,approved_by,approval_ticket,expires_at,status,created_at)
		VALUES ($1,$2,'192.0.2.41',1,'[]',$3,$4,'REPORT-LAB',CURRENT_TIMESTAMP + INTERVAL '1 hour','APPROVED',CURRENT_TIMESTAMP)`, scopeID, assetID, userID, reviewer); err != nil {
		t.Fatal(err)
	}
	queue, err := NewPostgresTaskStore(db)
	if err != nil {
		t.Fatal(err)
	}
	if err := queue.CreateTask(ctx, ScanTask{ID: taskID, ScopeID: scopeID, Status: "PENDING", CreatedBy: userID,
		Engines: []string{"trivy"}, Targets: []string{"192.0.2.41:8080"}, PinnedRuleVersion: "rules-lab"}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE scan_tasks SET status='COMPLETED' WHERE id=$1`, taskID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE scan_task_chunks SET status='COMPLETED',completed_fully=TRUE,finished_at=CURRENT_TIMESTAMP WHERE task_id=$1`, taskID); err != nil {
		t.Fatal(err)
	}
	now := testPostgresFindingTime()
	projection, err := NewPostgresTaskProjection(db)
	if err != nil {
		t.Fatal(err)
	}
	projection.now = func() time.Time { return now }
	if err := projection.Save(ctx, taskflow.Task{ID: taskID, ScopeID: scopeID, ScopeName: "192.0.2.41", AssetID: assetID,
		Status: "COMPLETED", Engines: []string{"trivy"}, CreatedAt: now, SystemScanStatus: taskflow.SystemScanCompleted,
		Chunks:      []taskflow.Chunk{{ID: taskID + "-chunk", TaskID: taskID, Status: "COMPLETED", Targets: []string{"192.0.2.41:8080"}, CompletedFully: true}},
		TotalChunks: 1, CompletedChunks: 1, TargetCount: 1}); err != nil {
		t.Fatal(err)
	}
	findingStore, err := NewPostgresFindingStore(db)
	if err != nil {
		t.Fatal(err)
	}
	findingStore.now = func() time.Time { return now }
	finding := taskflow.Finding{ID: findingID, TaskID: taskID, AssetID: assetID,
		Fingerprint: stablePostgresFindingFingerprint("192.0.2.41:8080", "trivy", "CVE-2026-0041", "", "apache2", "2.4"),
		Severity:    "HIGH", Title: "fixture report finding", Engine: "trivy", TemplateOrCVE: "CVE-2026-0041",
		Target: "192.0.2.41:8080", Status: "OPEN", FirstSeen: now, LastSeen: now,
		Package: "apache2", InstalledVersion: "2.4", RiskType: "system", DetectMethod: "version", VerifiedInRun: true}
	if _, err := findingStore.SaveFinding(ctx, finding); err != nil {
		t.Fatal(err)
	}
	store, err := NewPostgresReportStore(db)
	if err != nil {
		t.Fatal(err)
	}
	store.now = func() time.Time { return now }
	if err := store.InitReports(ctx); err != nil {
		t.Fatal(err)
	}
	job, err := store.CreateReport(ctx, reporting.Request{Format: "json", Scope: reporting.Scope{TaskID: taskID}}, userID)
	if err != nil {
		t.Fatal(err)
	}
	if job.Status != "QUEUED" || job.SnapshotID == "" {
		t.Fatalf("created report=%+v", job)
	}
	snapshot, err := store.ReportSnapshot(ctx, job.SnapshotID)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Scope.TaskID != taskID || len(snapshot.Assets) != 1 || len(snapshot.Tasks) != 1 || len(snapshot.Findings) != 1 || snapshot.Summary.SystemVulnerabilities != 1 {
		t.Fatalf("snapshot=%+v", snapshot)
	}
	page, err := store.ListReportsPage(ctx, ReportListQuery{Page: 1, PageSize: 10, Format: "json", Search: job.SnapshotID[:8]})
	if err != nil || page.Total != 1 || len(page.Items) != 1 {
		t.Fatalf("report page=%+v err=%v", page, err)
	}
	if processed, err := store.ProcessNextReport(ctx, t.TempDir()); err != nil || !processed {
		t.Fatalf("process report processed=%v err=%v", processed, err)
	}
	ready, file, err := store.OpenReport(ctx, job.ID)
	if err != nil {
		current, getErr := store.GetReport(ctx, job.ID)
		t.Fatalf("open report: %v current=%+v getErr=%v", err, current, getErr)
	}
	defer file.Close()
	if ready.Status != "READY" || ready.FileSize == 0 {
		t.Fatalf("ready report=%+v", ready)
	}
	var exported reporting.Snapshot
	if err := json.NewDecoder(file).Decode(&exported); err != nil {
		t.Fatal(err)
	}
	if exported.ID != snapshot.ID || len(exported.Findings) != 1 {
		t.Fatalf("exported snapshot=%+v", exported)
	}
}
