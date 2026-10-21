package repo

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"

	"scanner-platform/internal/taskflow"
)

func TestFindingAssignmentValidationHistoryAndScanPreservation(t *testing.T) {
	store, actor, f := dispositionFixture(t)
	ctx := context.Background()
	for _, user := range []struct {
		id, role string
		active   int
	}{{"engineer", "security_engineer", 1}, {"viewer", "viewer", 1}, {"disabled", "security_engineer", 0}} {
		if _, err := store.db.Exec(`INSERT INTO users(id,username,role,is_active,password_hash) VALUES(?,?,?,?,?)`, user.id, user.id, user.role, user.active, "fixture-unused"); err != nil {
			t.Fatal(err)
		}
	}
	candidates, err := store.ListFindingAssignees(ctx)
	if err != nil || len(candidates) != 2 {
		t.Fatal(candidates, err)
	}
	for _, id := range []string{"missing", "disabled", "viewer", "bad\n"} {
		if _, err := store.AssignFinding(ctx, f.ID, id, actor); !errors.Is(err, ErrInvalidTask) {
			t.Fatalf("%q %v", id, err)
		}
	}
	if _, err := store.AssignFinding(ctx, f.ID, "engineer", "viewer"); !errors.Is(err, ErrInvalidTask) {
		t.Fatal(err)
	}
	assigned, err := store.AssignFinding(ctx, f.ID, "engineer", actor)
	if err != nil || assigned.AssigneeName != "engineer" || assigned.Owner != f.Owner || assigned.Status != f.Status {
		t.Fatal(assigned, err)
	}
	if _, err := store.AssignFinding(ctx, f.ID, "engineer", actor); !errors.Is(err, ErrInvalidTask) {
		t.Fatal("noop", err)
	}
	var count int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM finding_assignment_events WHERE finding_id=?`, f.ID).Scan(&count); err != nil || count != 1 {
		t.Fatal(count, err)
	}
	task := createClaimedNucleiTask(t, store, actor, "assignment-worker")
	completeNucleiFixture(t, store, task, fixtureNucleiFinding())
	findings, err := store.ListRuntimeFindings(ctx)
	if err != nil || len(findings) != 1 || findings[0].AssigneeID != "engineer" {
		t.Fatal(findings, err)
	}
	cleared, err := store.AssignFinding(ctx, f.ID, "", actor)
	if err != nil || cleared.AssigneeID != "" || cleared.AssigneeName != "" {
		t.Fatal(cleared, err)
	}
	if _, err := store.AssignFinding(ctx, "missing", "engineer", actor); !errors.Is(err, ErrTaskNotFound) {
		t.Fatal(err)
	}
}

func TestFindingNotesAppendValidationConcurrencyAndAudit(t *testing.T) {
	store, actor, f := dispositionFixture(t)
	ctx := context.Background()
	for _, body := range []string{"", "  ", "a\nb", "a\u2028b", "a\u2029b", "\ttext", "text\r", "\x00", string([]byte{0xff}), strings.Repeat("中", 667)} {
		if _, err := store.AddFindingNote(ctx, f.ID, body, actor); !errors.Is(err, ErrInvalidTask) {
			t.Fatalf("%q %v", body, err)
		}
	}
	if _, err := store.AddFindingNote(ctx, "missing", "note", actor); !errors.Is(err, ErrTaskNotFound) {
		t.Fatal(err)
	}
	body := strings.Repeat("中", 666) + "ab"
	note, err := store.AddFindingNote(ctx, f.ID, body, actor)
	if err != nil || note.Body != body || note.ActorName == "" {
		t.Fatal(note, err)
	}
	var detail string
	if err := store.db.QueryRow(`SELECT detail FROM audit_logs WHERE action='finding_note_added' AND object_id=?`, f.ID).Scan(&detail); err != nil || strings.Contains(detail, body) || !strings.Contains(detail, note.ID) {
		t.Fatal(detail, err)
	}
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := store.AddFindingNote(ctx, f.ID, "第二条备注", actor); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	notes, err := store.ListFindingNotes(ctx, f.ID)
	if err != nil || len(notes) != 3 || notes[0].Body != body {
		t.Fatal(notes, err)
	}
	items, err := store.ListRuntimeFindings(ctx)
	if err != nil || items[0].Status != f.Status {
		t.Fatal(items, err)
	}
	if _, err := store.ListFindingNotes(ctx, "missing"); !errors.Is(err, ErrTaskNotFound) {
		t.Fatal(err)
	}
}

func TestFindingBatchAssignmentIsAtomicAndExposesHistory(t *testing.T) {
	store, actor, first := dispositionFixture(t)
	ctx := context.Background()
	if _, err := store.db.Exec(`INSERT INTO users(id,username,role,is_active,password_hash) VALUES(?,?,?,?,?)`, "engineer", "engineer", "security_engineer", 1, "fixture-unused"); err != nil {
		t.Fatal(err)
	}
	second := first
	second.ID = "batch-assignment-second"
	second.Fingerprint = "batch-assignment-second-fingerprint"
	secondTask, err := store.CreateSyntheticTask(ctx)
	if err != nil {
		t.Fatal(err)
	}
	second.TaskID = secondTask.ID
	secondRaw, err := json.Marshal(second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec(`INSERT INTO security_findings(id,task_id,data) VALUES(?,?,?)`, second.ID, second.TaskID, string(secondRaw)); err != nil {
		t.Fatal(err)
	}
	in := FindingBatchAssignment{AssigneeID: "engineer", Items: []FindingBatchAssignmentItem{
		{ID: first.ID, ExpectedAssigneeID: ""},
		{ID: second.ID, ExpectedAssigneeID: ""},
	}}
	updated, err := store.BatchAssignFindings(ctx, in, actor)
	if err != nil || len(updated) != 2 || updated[0].AssigneeID != "engineer" || updated[1].AssigneeID != "engineer" {
		t.Fatalf("updated=%+v err=%v", updated, err)
	}
	events, err := store.ListFindingAssignmentEvents(ctx, first.ID)
	if err != nil || len(events) != 1 || events[0].ToAssigneeID != "engineer" || events[0].FromAssigneeID != "" {
		t.Fatalf("events=%+v err=%v", events, err)
	}
	stale := in
	stale.Items = []FindingBatchAssignmentItem{{ID: first.ID, ExpectedAssigneeID: ""}, {ID: second.ID, ExpectedAssigneeID: "engineer"}}
	if _, err := store.BatchAssignFindings(ctx, stale, actor); !errors.Is(err, ErrTaskConflict) {
		t.Fatalf("stale batch err=%v", err)
	}
	var count int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM finding_assignment_events`).Scan(&count); err != nil || count != 2 {
		t.Fatalf("partial assignment events=%d err=%v", count, err)
	}
}

func TestFindingWorkAuditFailureRollsBack(t *testing.T) {
	store, actor, f := dispositionFixture(t)
	ctx := context.Background()
	if _, err := store.db.Exec(`CREATE TRIGGER reject_work_audit BEFORE INSERT ON audit_logs WHEN NEW.action IN ('finding_assignee_changed','finding_note_added') BEGIN SELECT RAISE(ABORT,'fixture reject'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AssignFinding(ctx, f.ID, actor, actor); err == nil {
		t.Fatal("assignment should fail")
	}
	if _, err := store.AddFindingNote(ctx, f.ID, "not retained", actor); err == nil {
		t.Fatal("note should fail")
	}
	var raw string
	if err := store.db.QueryRow(`SELECT data FROM security_findings WHERE id=?`, f.ID).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var finding taskflow.Finding
	if err := json.Unmarshal([]byte(raw), &finding); err != nil || finding.AssigneeID != "" {
		t.Fatal(finding, err)
	}
	for _, table := range []string{"finding_notes", "finding_assignment_events"} {
		var count int
		if err := store.db.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&count); err != nil || count != 0 {
			t.Fatal(table, count, err)
		}
	}
}
