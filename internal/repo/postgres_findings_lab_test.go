//go:build lab

package repo

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"scanner-platform/internal/taskflow"
)

func TestPostgresFindingStoreLab(t *testing.T) {
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
		userID    = "lab-postgres-finding-user"
		reviewer  = "lab-postgres-finding-reviewer"
		assetID   = "lab-postgres-finding-asset"
		scopeID   = "lab-postgres-finding-scope"
		nodeID    = "lab-postgres-finding-node"
		taskID    = "lab-postgres-finding-task"
		findingID = "finding-lab-postgres-finding"
	)
	cleanup := func() {
		_, _ = db.ExecContext(ctx, `DELETE FROM audit_logs WHERE object_id=$1`, findingID)
		_, _ = db.ExecContext(ctx, `DELETE FROM finding_events WHERE finding_id=$1`, findingID)
		_, _ = db.ExecContext(ctx, `DELETE FROM task_finding_observations WHERE task_id=$1`, taskID)
		_, _ = db.ExecContext(ctx, `DELETE FROM finding_projections WHERE finding_id=$1`, findingID)
		_, _ = db.ExecContext(ctx, `DELETE FROM security_findings WHERE id=$1`, findingID)
		_, _ = db.ExecContext(ctx, `DELETE FROM scan_task_chunks WHERE task_id=$1`, taskID)
		_, _ = db.ExecContext(ctx, `DELETE FROM scan_tasks WHERE id=$1`, taskID)
		_, _ = db.ExecContext(ctx, `DELETE FROM authorized_scopes WHERE id=$1`, scopeID)
		_, _ = db.ExecContext(ctx, `DELETE FROM assets WHERE id=$1`, assetID)
		_, _ = db.ExecContext(ctx, `DELETE FROM nodes WHERE id=$1`, nodeID)
		_, _ = db.ExecContext(ctx, `DELETE FROM users WHERE id IN ($1,$2)`, userID, reviewer)
	}
	cleanup()
	defer cleanup()
	for _, user := range []struct{ id, name string }{{userID, "lab_finding_user"}, {reviewer, "lab_finding_reviewer"}} {
		if _, err := db.ExecContext(ctx, `INSERT INTO users(id,username,role,is_active,password_hash)
			VALUES ($1,$2,'admin',TRUE,'fixture-only')`, user.id, user.name); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO assets(id,kind,address,business_group,owner)
		VALUES ($1,'host','192.0.2.12','fixture','fixture-owner')`, assetID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO authorized_scopes
		(id,asset_id,cidr_or_host,max_targets,time_windows,requested_by,approved_by,approval_ticket,expires_at,status,created_at)
		VALUES ($1,$2,'192.0.2.12',1,'[]',$3,$4,'LAB-FINDING',CURRENT_TIMESTAMP + INTERVAL '1 hour','APPROVED',CURRENT_TIMESTAMP)`, scopeID, assetID, userID, reviewer); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO nodes(id,kind,host_id,token_hash)
		VALUES ($1,'worker','lab-host','fixture-finding-hash')`, nodeID); err != nil {
		t.Fatal(err)
	}
	queue, err := NewPostgresTaskStore(db)
	if err != nil {
		t.Fatal(err)
	}
	if err := queue.CreateTask(ctx, ScanTask{
		ID: taskID, ScopeID: scopeID, Status: "PENDING", CreatedBy: userID,
		Engines: []string{"trivy"}, Targets: []string{"192.0.2.12:8080"},
		PinnedRuleVersion: "rules-lab",
	}); err != nil {
		t.Fatal(err)
	}
	store, err := NewPostgresFindingStore(db)
	if err != nil {
		t.Fatal(err)
	}
	now := testPostgresFindingTime()
	store.now = func() time.Time { return now }
	fingerprint := stablePostgresFindingFingerprint("192.0.2.12:8080", "trivy", "CVE-2026-0002", "", "apache2", "2.4")
	finding := taskflow.Finding{
		ID: findingID, TaskID: taskID, AssetID: assetID, Fingerprint: fingerprint,
		Severity: "HIGH", Title: "fixture package finding", Engine: "trivy",
		TemplateOrCVE: "CVE-2026-0002", Target: "192.0.2.12:8080", Status: "OPEN",
		FirstSeen: now, LastSeen: now, Package: "apache2", InstalledVersion: "2.4",
		DetectMethod: "version", RiskType: "system", VerifiedInRun: true,
	}
	saved, err := store.SaveFinding(ctx, finding)
	if err != nil {
		t.Fatal(err)
	}
	if saved.ID != findingID || saved.Status != "OPEN" {
		t.Fatalf("saved finding=%+v", saved)
	}
	got, err := store.Get(ctx, findingID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Fingerprint != fingerprint || got.AssetID != assetID || got.Status != "OPEN" {
		t.Fatalf("got finding=%+v", got)
	}
	page, err := store.ListPage(ctx, FindingListQuery{Page: 1, PageSize: 20, Search: "package", Risk: "system"})
	if err != nil {
		t.Fatal(err)
	}
	if page.Total != 1 || len(page.Items) != 1 || page.Counts.Version != 1 {
		t.Fatalf("finding page=%+v", page)
	}
	until := now.Add(time.Hour)
	accepted, err := store.UpdateFindingDisposition(ctx, findingID, FindingDisposition{
		Status: "ACCEPTED_RISK", Reason: "fixture review", AcceptedUntil: until.Format(time.RFC3339),
	}, userID)
	if err != nil {
		t.Fatal(err)
	}
	if accepted.Status != "ACCEPTED_RISK" || accepted.AcceptedUntil == nil {
		t.Fatalf("accepted finding=%+v", accepted)
	}
	events, err := store.ListEvents(ctx, findingID)
	if err != nil || len(events) != 1 || events[0].ToStatus != "ACCEPTED_RISK" {
		t.Fatalf("events=%+v err=%v", events, err)
	}
	if err := store.ExpireAcceptedRisks(ctx, now.Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	opened, err := store.Get(ctx, findingID)
	if err != nil {
		t.Fatal(err)
	}
	if opened.Status != "OPEN" || opened.AcceptedUntil != nil {
		t.Fatalf("expired finding=%+v", opened)
	}
	// A subsequent hit keeps the stable ID and reopens a fixed lifecycle row.
	if _, err := db.ExecContext(ctx, `UPDATE security_findings SET lifecycle_status='FIXED' WHERE id=$1`, findingID); err != nil {
		t.Fatal(err)
	}
	reopened, err := store.SaveFinding(ctx, finding)
	if err != nil {
		t.Fatal(err)
	}
	if reopened.Status != "REOPENED" {
		t.Fatalf("reopened finding=%+v", reopened)
	}
}
