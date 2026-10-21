//go:build lab

package repo

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPostgresTaskStoreLab(t *testing.T) {
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
		userID   = "lab-postgres-queue-user"
		reviewer = "lab-postgres-queue-reviewer"
		assetID  = "lab-postgres-queue-asset"
		scopeID  = "lab-postgres-queue-scope"
		nodeID   = "lab-postgres-queue-node"
		taskID   = "lab-postgres-queue-task"
	)
	cleanup := func() {
		_, _ = db.ExecContext(ctx, `DELETE FROM scan_task_chunks WHERE task_id=$1`, taskID)
		_, _ = db.ExecContext(ctx, `DELETE FROM scan_tasks WHERE id=$1`, taskID)
		_, _ = db.ExecContext(ctx, `DELETE FROM authorized_scopes WHERE id=$1`, scopeID)
		_, _ = db.ExecContext(ctx, `DELETE FROM assets WHERE id=$1`, assetID)
		_, _ = db.ExecContext(ctx, `DELETE FROM nodes WHERE id=$1`, nodeID)
		_, _ = db.ExecContext(ctx, `DELETE FROM users WHERE id IN ($1,$2)`, userID, reviewer)
	}
	cleanup()
	defer cleanup()
	for _, user := range []struct{ id, name string }{{userID, "lab_queue_user"}, {reviewer, "lab_queue_reviewer"}} {
		if _, err := db.ExecContext(ctx, `INSERT INTO users(id,username,role,is_active,password_hash)
			VALUES ($1,$2,'admin',TRUE,'fixture-only')`, user.id, user.name); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO assets(id,kind,address,business_group,owner)
		VALUES ($1,'host','192.0.2.10','fixture','fixture-owner')`, assetID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO authorized_scopes
		(id,asset_id,cidr_or_host,max_targets,time_windows,requested_by,approved_by,approval_ticket,expires_at,status,created_at)
		VALUES ($1,$2,'192.0.2.10',1,'[]',$3,$4,'LAB-QUEUE',CURRENT_TIMESTAMP + INTERVAL '1 hour','APPROVED',CURRENT_TIMESTAMP)`, scopeID, assetID, userID, reviewer); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO nodes(id,kind,host_id,token_hash)
		VALUES ($1,'worker','lab-host','fixture-hash')`, nodeID); err != nil {
		t.Fatal(err)
	}

	store, err := NewPostgresTaskStore(db)
	if err != nil {
		t.Fatal(err)
	}
	store.leaseDuration = time.Minute
	store.now = func() time.Time { return time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC) }
	if err := store.CreateTask(ctx, ScanTask{
		ID: taskID, ScopeID: scopeID, Status: "PENDING", CreatedBy: userID,
		Engines: []string{"nuclei"}, Targets: []string{"192.0.2.10:8080"}, PinnedRuleVersion: "rules-lab",
	}); err != nil {
		t.Fatal(err)
	}
	chunk, err := store.ClaimChunk(ctx, nodeID)
	if err != nil {
		t.Fatal(err)
	}
	if chunk.Status != "RUNNING" || chunk.WorkerNodeID != nodeID || len(chunk.Targets) != 1 {
		t.Fatalf("claimed chunk=%+v", chunk)
	}
	if count, err := store.CountRunningByVersion(ctx, "rules-lab", nodeID); err != nil || count != 1 {
		t.Fatalf("running count=%d err=%v, want 1", count, err)
	}
	if _, err := store.RenewChunkLease(ctx, chunk.ID, nodeID, "rules-lab"); err != nil {
		t.Fatal(err)
	}
	if err := store.CompleteChunk(ctx, chunk.ID, true); err != nil {
		t.Fatal(err)
	}
	if count, err := store.CountRunningByVersion(ctx, "rules-lab", nodeID); err != nil || count != 0 {
		t.Fatalf("running count after completion=%d err=%v, want 0", count, err)
	}
	var status string
	if err := db.QueryRowContext(ctx, `SELECT status FROM scan_tasks WHERE id=$1`, taskID).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "COMPLETED" {
		t.Fatalf("task status=%q, want COMPLETED", status)
	}
}
