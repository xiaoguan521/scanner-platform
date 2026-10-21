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

func TestPostgresTaskProjectionLab(t *testing.T) {
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
		userID   = "lab-postgres-projection-user"
		reviewer = "lab-postgres-projection-reviewer"
		assetID  = "lab-postgres-projection-asset"
		scopeID  = "lab-postgres-projection-scope"
		nodeID   = "lab-postgres-projection-node"
		taskID   = "lab-postgres-projection-task"
	)
	cleanup := func() {
		_, _ = db.ExecContext(ctx, `DELETE FROM scan_task_progress WHERE task_id=$1`, taskID)
		_, _ = db.ExecContext(ctx, `DELETE FROM scan_task_projections WHERE task_id=$1`, taskID)
		_, _ = db.ExecContext(ctx, `DELETE FROM scan_task_chunks WHERE task_id=$1`, taskID)
		_, _ = db.ExecContext(ctx, `DELETE FROM scan_tasks WHERE id=$1`, taskID)
		_, _ = db.ExecContext(ctx, `DELETE FROM authorized_scopes WHERE id=$1`, scopeID)
		_, _ = db.ExecContext(ctx, `DELETE FROM assets WHERE id=$1`, assetID)
		_, _ = db.ExecContext(ctx, `DELETE FROM nodes WHERE id=$1`, nodeID)
		_, _ = db.ExecContext(ctx, `DELETE FROM users WHERE id IN ($1,$2)`, userID, reviewer)
	}
	cleanup()
	defer cleanup()
	for _, user := range []struct{ id, name string }{{userID, "lab_projection_user"}, {reviewer, "lab_projection_reviewer"}} {
		if _, err := db.ExecContext(ctx, `INSERT INTO users(id,username,role,is_active,password_hash)
			VALUES ($1,$2,'admin',TRUE,'fixture-only')`, user.id, user.name); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO assets(id,kind,address,business_group,owner)
		VALUES ($1,'host','192.0.2.11','fixture','fixture-owner')`, assetID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO authorized_scopes
		(id,asset_id,cidr_or_host,max_targets,time_windows,requested_by,approved_by,approval_ticket,expires_at,status,created_at)
		VALUES ($1,$2,'192.0.2.11',1,'[]',$3,$4,'LAB-PROJECTION',CURRENT_TIMESTAMP + INTERVAL '1 hour','APPROVED',CURRENT_TIMESTAMP)`, scopeID, assetID, userID, reviewer); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO nodes(id,kind,host_id,token_hash)
		VALUES ($1,'worker','lab-host','fixture-projection-hash')`, nodeID); err != nil {
		t.Fatal(err)
	}

	queue, err := NewPostgresTaskStore(db)
	if err != nil {
		t.Fatal(err)
	}
	if err := queue.CreateTask(ctx, ScanTask{
		ID: taskID, ScopeID: scopeID, Status: "PENDING", CreatedBy: userID,
		Engines: []string{"port-probe"}, Targets: []string{"192.0.2.11:8080"},
		PinnedRuleVersion: NoRuleLeaseVersion,
	}); err != nil {
		t.Fatal(err)
	}
	projection, err := NewPostgresTaskProjection(db)
	if err != nil {
		t.Fatal(err)
	}
	projection.now = func() time.Time { return time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC) }
	if err := projection.Save(ctx, taskflow.Task{
		ID: taskID, ScopeID: scopeID, ScopeName: "fixture scope", Status: "PENDING",
		Engines: []string{"port-probe"}, TotalChunks: 1, TargetCount: 1,
		PortProbePorts: []int{8080}, CreatedAt: projection.now(),
	}); err != nil {
		t.Fatal(err)
	}
	initial, err := projection.Get(ctx, taskID)
	if err != nil {
		t.Fatal(err)
	}
	if initial.Status != "PENDING" || initial.TargetCount != 1 || len(initial.Chunks) != 1 {
		t.Fatalf("initial projection=%+v", initial)
	}

	chunk, err := queue.ClaimChunk(ctx, nodeID)
	if err != nil {
		t.Fatal(err)
	}
	if err := projection.SaveProgress(ctx, nodeID, taskflow.ProgressUpdate{
		TaskID: taskID, Phase: "tcp_probe", Completed: 1, Total: 1,
	}); err != nil {
		t.Fatal(err)
	}
	if err := projection.SaveProgress(ctx, nodeID, taskflow.ProgressUpdate{
		TaskID: taskID, Phase: "tcp_probe", Completed: 0, Total: 1,
	}); err != ErrPostgresProjectionInvalid {
		t.Fatalf("progress regression error=%v, want %v", err, ErrPostgresProjectionInvalid)
	}
	progressed, err := projection.Get(ctx, taskID)
	if err != nil {
		t.Fatal(err)
	}
	if progressed.Status != "RUNNING" || progressed.Progress == nil || progressed.Progress.Completed != 1 {
		t.Fatalf("progressed projection=%+v", progressed)
	}
	if err := queue.CompleteChunk(ctx, chunk.ID, true); err != nil {
		t.Fatal(err)
	}
	completed, err := projection.Get(ctx, taskID)
	if err != nil {
		t.Fatal(err)
	}
	if completed.Status != "COMPLETED" || completed.CompletedChunks != 1 {
		t.Fatalf("completed projection=%+v", completed)
	}
}
