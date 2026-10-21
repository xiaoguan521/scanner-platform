//go:build lab

package repo

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"scanner-platform/internal/taskflow"
)

func TestPostgresFindingWorkLab(t *testing.T) {
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
		actorID    = "lab-pg-work-admin"
		engineerID = "lab-pg-work-engineer"
		viewerID   = "lab-pg-work-viewer"
		assetID    = "lab-pg-work-asset"
		scopeID    = "lab-pg-work-scope"
		taskID     = "lab-pg-work-task"
		findingA   = "lab-pg-work-finding-a"
		findingB   = "lab-pg-work-finding-b"
	)
	cleanup := func() {
		_, _ = db.ExecContext(ctx, `DELETE FROM audit_logs WHERE object_id IN ($1,$2)`, findingA, findingB)
		_, _ = db.ExecContext(ctx, `DELETE FROM finding_notes WHERE finding_id IN ($1,$2)`, findingA, findingB)
		_, _ = db.ExecContext(ctx, `DELETE FROM finding_assignment_events WHERE finding_id IN ($1,$2)`, findingA, findingB)
		_, _ = db.ExecContext(ctx, `DELETE FROM finding_events WHERE finding_id IN ($1,$2)`, findingA, findingB)
		_, _ = db.ExecContext(ctx, `DELETE FROM task_finding_observations WHERE task_id=$1`, taskID)
		_, _ = db.ExecContext(ctx, `DELETE FROM finding_projections WHERE finding_id IN ($1,$2)`, findingA, findingB)
		_, _ = db.ExecContext(ctx, `DELETE FROM security_findings WHERE id IN ($1,$2)`, findingA, findingB)
		_, _ = db.ExecContext(ctx, `DELETE FROM scan_task_projections WHERE task_id=$1`, taskID)
		_, _ = db.ExecContext(ctx, `DELETE FROM scan_task_chunks WHERE task_id=$1`, taskID)
		_, _ = db.ExecContext(ctx, `DELETE FROM scan_tasks WHERE id=$1`, taskID)
		_, _ = db.ExecContext(ctx, `DELETE FROM authorized_scopes WHERE id=$1`, scopeID)
		_, _ = db.ExecContext(ctx, `DELETE FROM assets WHERE id=$1`, assetID)
		_, _ = db.ExecContext(ctx, `DELETE FROM users WHERE id IN ($1,$2,$3)`, actorID, engineerID, viewerID)
	}
	cleanup()
	defer cleanup()
	for _, user := range []struct{ id, name, role string }{
		{actorID, "lab_pg_work_admin", "admin"},
		{engineerID, "lab_pg_work_engineer", "security_engineer"},
		{viewerID, "lab_pg_work_viewer", "viewer"},
	} {
		if _, err := db.ExecContext(ctx, `INSERT INTO users(id,username,role,is_active,password_hash)
			VALUES ($1,$2,$3,TRUE,'fixture-only')`, user.id, user.name, user.role); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO assets(id,kind,address,business_group,owner)
		VALUES ($1,'host','192.0.2.71','fixture','fixture-owner')`, assetID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO authorized_scopes
		(id,asset_id,cidr_or_host,max_targets,time_windows,requested_by,approved_by,approval_ticket,expires_at,status,created_at)
		VALUES ($1,$2,'192.0.2.71',1,'[]',$3,$4,'LAB-PG-WORK',CURRENT_TIMESTAMP + INTERVAL '1 hour','APPROVED',CURRENT_TIMESTAMP)`, scopeID, assetID, actorID, engineerID); err != nil {
		t.Fatal(err)
	}
	queue, err := NewPostgresTaskStore(db)
	if err != nil {
		t.Fatal(err)
	}
	if err := queue.CreateTask(ctx, ScanTask{
		ID: taskID, ScopeID: scopeID, Status: "PENDING", CreatedBy: actorID,
		Engines: []string{"trivy"}, Targets: []string{"192.0.2.71:8080"},
		PinnedRuleVersion: "rules-lab",
	}); err != nil {
		t.Fatal(err)
	}
	findings, err := NewPostgresFindingStore(db)
	if err != nil {
		t.Fatal(err)
	}
	for _, fixture := range []struct{ id, rule string }{
		{findingA, "CVE-2026-0101"}, {findingB, "CVE-2026-0102"},
	} {
		fingerprint := stablePostgresFindingFingerprint("192.0.2.71:8080", "trivy", fixture.rule, "", "fixture-package", "1")
		if _, err := findings.SaveFinding(ctx, taskflow.Finding{
			ID: fixture.id, TaskID: taskID, AssetID: assetID, Fingerprint: fingerprint,
			Severity: "HIGH", Title: "fixture finding", Engine: "trivy",
			TemplateOrCVE: fixture.rule, Target: "192.0.2.71:8080", Status: "OPEN",
			FirstSeen: time.Now().UTC(), LastSeen: time.Now().UTC(),
		}); err != nil {
			t.Fatal(err)
		}
	}
	store, err := NewPostgresRuntime(db)
	if err != nil {
		t.Fatal(err)
	}
	assignees, err := store.ListFindingAssignees(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, assignee := range assignees {
		if assignee.ID == viewerID {
			t.Fatal("viewer was listed as an assignee")
		}
	}
	if _, err := store.AssignFinding(ctx, findingA, viewerID, actorID); !errors.Is(err, ErrInvalidTask) {
		t.Fatalf("viewer assignment error=%v", err)
	}
	assigned, err := store.AssignFinding(ctx, findingA, engineerID, actorID)
	if err != nil || assigned.AssigneeID != engineerID {
		t.Fatalf("assigned=%+v err=%v", assigned, err)
	}
	if _, err := store.AddFindingNote(ctx, findingA, "bad\nline", actorID); !errors.Is(err, ErrInvalidTask) {
		t.Fatalf("control character note error=%v", err)
	}
	note, err := store.AddFindingNote(ctx, findingA, "fixture note", engineerID)
	if err != nil || note.Body != "fixture note" {
		t.Fatalf("note=%+v err=%v", note, err)
	}
	notes, err := store.ListFindingNotes(ctx, findingA)
	if err != nil || len(notes) != 1 || notes[0].ActorName != "lab_pg_work_engineer" {
		t.Fatalf("notes=%+v err=%v", notes, err)
	}
	assignments, err := store.ListFindingAssignmentEvents(ctx, findingA)
	if err != nil || len(assignments) != 1 || assignments[0].ToAssigneeID != engineerID {
		t.Fatalf("assignments=%+v err=%v", assignments, err)
	}
	if _, err := store.BatchAssignFindings(ctx, FindingBatchAssignment{
		AssigneeID: engineerID, Items: []FindingBatchAssignmentItem{
			{ID: findingA, ExpectedAssigneeID: ""}, {ID: findingB, ExpectedAssigneeID: ""},
		},
	}, actorID); !errors.Is(err, ErrTaskConflict) {
		t.Fatalf("stale batch assignment error=%v", err)
	}
	if _, err := store.BatchAssignFindings(ctx, FindingBatchAssignment{
		AssigneeID: engineerID, Items: []FindingBatchAssignmentItem{{ID: findingB, ExpectedAssigneeID: ""}},
	}, actorID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.BatchFindingDisposition(ctx, FindingBatchDisposition{
		Status: "IN_PROGRESS", Items: []FindingBatchItem{
			{ID: findingA, ExpectedStatus: "OPEN"}, {ID: findingB, ExpectedStatus: "FIXED"},
		},
	}, actorID); !errors.Is(err, ErrTaskConflict) {
		t.Fatalf("stale batch disposition error=%v", err)
	}
	if _, err := store.BatchFindingDisposition(ctx, FindingBatchDisposition{
		Status: "IN_PROGRESS", Items: []FindingBatchItem{
			{ID: findingB, ExpectedStatus: "OPEN"}, {ID: findingA, ExpectedStatus: "OPEN"},
		},
	}, actorID); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{findingA, findingB} {
		current, err := findings.Get(ctx, id)
		if err != nil || current.Status != "IN_PROGRESS" || current.AssigneeID != engineerID {
			t.Fatalf("current finding=%+v err=%v", current, err)
		}
	}
	observed, err := store.ListTaskFindings(ctx, taskID)
	if err != nil || len(observed) != 2 {
		t.Fatalf("observed=%+v err=%v", observed, err)
	}
	for _, item := range observed {
		if item.Status != "OPEN" || item.AssigneeID != "" {
			t.Fatalf("human work changed frozen observation: %+v", item)
		}
	}
	var audit string
	if err := db.QueryRowContext(ctx, `SELECT detail FROM audit_logs WHERE action='finding_note_added'
		AND object_id=$1`, findingA).Scan(&audit); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(audit, note.Body) || !strings.Contains(audit, note.ID) {
		t.Fatalf("note audit exposed content or missed ID: %q", audit)
	}
	// A downstream audit failure must undo the finding projection and event.
	if _, err := db.ExecContext(ctx, `CREATE FUNCTION lab_pg_work_reject_audit() RETURNS trigger
		LANGUAGE plpgsql AS $$ BEGIN
		IF NEW.action='finding_assignee_changed' AND NEW.object_id='lab-pg-work-finding-b' THEN
			RAISE EXCEPTION 'fixture audit failure';
		END IF;
		RETURN NEW;
		END $$`); err != nil {
		t.Fatal(err)
	}
	defer db.ExecContext(ctx, `DROP FUNCTION IF EXISTS lab_pg_work_reject_audit()`)
	if _, err := db.ExecContext(ctx, `CREATE TRIGGER lab_pg_work_reject_audit
		BEFORE INSERT ON audit_logs FOR EACH ROW EXECUTE FUNCTION lab_pg_work_reject_audit()`); err != nil {
		t.Fatal(err)
	}
	defer db.ExecContext(ctx, `DROP TRIGGER IF EXISTS lab_pg_work_reject_audit ON audit_logs`)
	if _, err := store.BatchAssignFindings(ctx, FindingBatchAssignment{
		AssigneeID: "", Items: []FindingBatchAssignmentItem{
			{ID: findingA, ExpectedAssigneeID: engineerID},
			{ID: findingB, ExpectedAssigneeID: engineerID},
		},
	}, actorID); err == nil {
		t.Fatal("audit failure allowed partial batch assignment")
	}
	for _, id := range []string{findingA, findingB} {
		current, err := findings.Get(ctx, id)
		if err != nil || current.AssigneeID != engineerID {
			t.Fatalf("audit failure changed assignment for %s: %+v err=%v", id, current, err)
		}
	}
}
