//go:build lab

package repo

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"scanner-platform/internal/portprobe"
	"scanner-platform/internal/taskflow"
)

func TestPostgresScheduleCreatesOneShotTaskAndRunHistory(t *testing.T) {
	dsnFile := os.Getenv("POSTGRES_DSN_FILE")
	if dsnFile == "" {
		t.Skip("set POSTGRES_DSN_FILE to an isolated PostgreSQL fixture")
	}
	ctx := context.Background()
	dsn, err := ReadPostgresDSNFile(filepath.Clean(dsnFile))
	if err != nil {
		t.Fatal(err)
	}
	db, err := OpenPostgres(ctx, PostgresConfig{DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := MigratePostgres(ctx, db); err != nil {
		t.Fatal(err)
	}

	const (
		actor   = "lab-postgres-schedule-user"
		review  = "lab-postgres-schedule-reviewer"
		assetID = "lab-postgres-schedule-asset"
		scopeID = "lab-postgres-schedule-scope"
	)
	var scheduleID string
	cleanup := func() {
		if scheduleID != "" {
			_, _ = db.ExecContext(ctx, `DELETE FROM schedule_runs WHERE schedule_id=$1`, scheduleID)
			_, _ = db.ExecContext(ctx, `DELETE FROM task_schedules WHERE id=$1`, scheduleID)
		}
		_, _ = db.ExecContext(ctx, `DELETE FROM scan_task_progress WHERE task_id LIKE 'task-%' AND task_id IN (SELECT id FROM scan_tasks WHERE created_by=$1)`, actor)
		_, _ = db.ExecContext(ctx, `DELETE FROM scan_task_chunks WHERE task_id IN (SELECT id FROM scan_tasks WHERE created_by=$1)`, actor)
		_, _ = db.ExecContext(ctx, `DELETE FROM scan_task_projections WHERE task_id IN (SELECT id FROM scan_tasks WHERE created_by=$1)`, actor)
		_, _ = db.ExecContext(ctx, `DELETE FROM scan_tasks WHERE created_by=$1`, actor)
		_, _ = db.ExecContext(ctx, `DELETE FROM audit_logs WHERE actor IN ($1,$2)`, actor, review)
		_, _ = db.ExecContext(ctx, `DELETE FROM asset_port_reviews WHERE asset_id=$1`, assetID)
		_, _ = db.ExecContext(ctx, `DELETE FROM asset_port_request_authors WHERE asset_id=$1`, assetID)
		_, _ = db.ExecContext(ctx, `DELETE FROM asset_port_requests WHERE asset_id=$1`, assetID)
		_, _ = db.ExecContext(ctx, `DELETE FROM asset_ports WHERE asset_id=$1`, assetID)
		_, _ = db.ExecContext(ctx, `DELETE FROM authorized_scopes WHERE id=$1`, scopeID)
		_, _ = db.ExecContext(ctx, `DELETE FROM assets WHERE id=$1`, assetID)
		_, _ = db.ExecContext(ctx, `DELETE FROM users WHERE id IN ($1,$2)`, actor, review)
	}
	cleanup()
	defer cleanup()
	for _, user := range []struct{ id, name string }{{actor, "pg_schedule_user"}, {review, "pg_schedule_reviewer"}} {
		if _, err := db.ExecContext(ctx, `INSERT INTO users(id,username,role,is_active,password_hash)
			VALUES ($1,$2,'admin',TRUE,'fixture-only')`, user.id, user.name); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO assets(id,kind,address,business_group,owner)
		VALUES ($1,'host','192.0.2.60','fixture','fixture-owner')`, assetID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO asset_port_requests(asset_id,port)
		VALUES ($1,8080)`, assetID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO asset_port_request_authors(asset_id,port,requested_by)
		VALUES ($1,8080,$2)`, assetID, actor); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO asset_ports(asset_id,port,kind,source)
		VALUES ($1,8080,'WEB','lab')`, assetID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO asset_port_reviews(asset_id,port,status,reviewed_by,approval_ticket,reviewed_at)
		VALUES ($1,8080,'APPROVED',$2,'PG-SCHEDULE-LAB',CURRENT_TIMESTAMP)`, assetID, review); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO authorized_scopes
		(id,asset_id,cidr_or_host,max_targets,time_windows,requested_by,approved_by,approval_ticket,expires_at,status,created_at)
		VALUES ($1,$2,'192.0.2.60',1,'[]',$3,$4,'PG-SCHEDULE-SCOPE',CURRENT_TIMESTAMP + INTERVAL '1 hour','APPROVED',CURRENT_TIMESTAMP)`, scopeID, assetID, actor, review); err != nil {
		t.Fatal(err)
	}

	store, err := NewPostgresRuntime(db)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Millisecond)
	schedule, err := store.SaveSchedule(ctx, taskflow.Schedule{
		Name: "lab one shot",
		TaskInput: taskflow.TaskInput{
			Engine:  "auto",
			AssetID: assetID,
			PortProbe: portprobe.Config{
				Preset:      portprobe.PresetCustom,
				Ranges:      []portprobe.Range{{Start: 8080, End: 8080}},
				OpsApproved: true,
			},
		},
		NextRun:         now.Add(time.Second).Format(time.RFC3339Nano),
		IntervalMinutes: 0,
	}, actor)
	if err != nil {
		t.Fatal(err)
	}
	scheduleID = schedule.ID
	if schedule.ID == "" || !schedule.Enabled {
		t.Fatalf("saved schedule=%+v", schedule)
	}
	if err := store.Tick(ctx, now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := store.Tick(ctx, now.Add(3*time.Second)); err != nil {
		t.Fatal(err)
	}
	runs, total, err := store.ListScheduleRuns(ctx, schedule.ID, 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if total != 1 || len(runs) != 1 || runs[0].Status != "PENDING" || runs[0].TaskID == "" {
		t.Fatalf("schedule runs total=%d runs=%+v", total, runs)
	}
	created, err := store.GetRuntimeTask(ctx, runs[0].TaskID)
	if err != nil {
		t.Fatal(err)
	}
	if created.AssetID != assetID || created.Status != "PENDING" || created.PortProbePorts[0] != 8080 {
		t.Fatalf("generated task=%+v", created)
	}
	items, err := store.ListSchedules(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].Enabled || items[0].LastTaskID != created.ID {
		t.Fatalf("schedule after tick=%+v", items)
	}
}
