package repo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"scanner-platform/internal/taskflow"
	"sync"
	"testing"
)

func batchFixture(t *testing.T) (*RuntimeStore, string, []taskflow.Finding) {
	t.Helper()
	store, actor, f := dispositionFixture(t)
	items := []taskflow.Finding{f}
	for i := 0; i < 2; i++ {
		clone := f
		clone.ID = fmt.Sprintf("batch-finding-%d", i)
		clone.Fingerprint = fmt.Sprintf("batch-fingerprint-%d", i)
		clone.AssigneeID = "assignment-snapshot"
		clone.AssigneeName = "fixture user"
		raw, _ := json.Marshal(clone)
		if _, err := store.db.Exec(`INSERT INTO security_findings(id,task_id,data) VALUES(?,?,?)`, clone.ID, clone.TaskID, string(raw)); err != nil {
			t.Fatal(err)
		}
		items = append(items, clone)
	}
	return store, actor, items
}
func batchInput(items []taskflow.Finding, status string) FindingBatchDisposition {
	in := FindingBatchDisposition{Status: status}
	for _, f := range items {
		in.Items = append(in.Items, FindingBatchItem{ID: f.ID, ExpectedStatus: f.Status})
	}
	return in
}
func TestFindingBatchSuccessAndPreservation(t *testing.T) {
	store, actor, items := batchFixture(t)
	ctx := context.Background()
	in := batchInput(items, "ACCEPTED_RISK")
	accept := acceptInput()
	in.Reason = accept.Reason
	in.AcceptedUntil = accept.AcceptedUntil
	got, err := store.BatchFindingDisposition(ctx, in, actor)
	if err != nil || len(got) != 3 {
		t.Fatal(got, err)
	}
	for _, f := range got {
		if f.Status != "ACCEPTED_RISK" || f.AcceptedUntil == nil || f.AcceptedReason != accept.Reason {
			t.Fatal(f)
		}
		for _, old := range items {
			if old.ID == f.ID && (f.Fingerprint != old.Fingerprint || f.AssigneeID != old.AssigneeID || f.AssigneeName != old.AssigneeName) {
				t.Fatal("metadata changed", old, f)
			}
		}
		events, err := store.ListFindingEvents(ctx, f.ID)
		if err != nil || len(events) != 1 {
			t.Fatal(events, err)
		}
		var detail string
		if err := store.db.QueryRow(`SELECT detail FROM audit_logs WHERE object_id=? AND action='finding_status_changed'`, f.ID).Scan(&detail); err != nil || detail == "" {
			t.Fatal(detail, err)
		}
	}
}
func TestFindingBatchRejectsInvalidAndRollsBack(t *testing.T) {
	for _, name := range []string{"empty", "over-limit", "duplicate", "empty-id", "empty-status", "missing", "stale", "fixed", "false-positive-accept", "accepted-progress", "noop", "bad-accept", "audit", "event", "cas"} {
		t.Run(name, func(t *testing.T) {
			store, actor, items := batchFixture(t)
			in := batchInput(items, "IN_PROGRESS")
			want := ErrInvalidTask
			switch name {
			case "empty":
				in.Items = nil
			case "over-limit":
				for len(in.Items) < 101 {
					in.Items = append(in.Items, FindingBatchItem{ID: fmt.Sprint(len(in.Items)), ExpectedStatus: "OPEN"})
				}
			case "duplicate":
				in.Items[2] = in.Items[0]
			case "empty-id":
				in.Items[2].ID = " "
			case "empty-status":
				in.Items[2].ExpectedStatus = ""
			case "missing":
				in.Items[2].ID = "missing"
				want = ErrTaskConflict
			case "stale":
				in.Items[2].ExpectedStatus = "REOPENED"
				want = ErrTaskConflict
			case "fixed", "false-positive-accept", "accepted-progress":
				f := items[2]
				f.Status = map[string]string{"fixed": "FIXED", "false-positive-accept": "FALSE_POSITIVE", "accepted-progress": "ACCEPTED_RISK"}[name]
				raw, _ := json.Marshal(f)
				if _, err := store.db.Exec(`UPDATE security_findings SET data=? WHERE id=?`, string(raw), f.ID); err != nil {
					t.Fatal(err)
				}
				in.Items[2].ExpectedStatus = f.Status
				if name == "false-positive-accept" {
					a := acceptInput()
					in.Status = a.Status
					in.Reason = a.Reason
					in.AcceptedUntil = a.AcceptedUntil
				}
			case "noop":
				in.Status = "OPEN"
			case "bad-accept":
				in.Status = "ACCEPTED_RISK"
			case "audit":
				_, _ = store.db.Exec(`CREATE TRIGGER batch_reject_audit BEFORE INSERT ON audit_logs WHEN NEW.action='finding_status_changed' AND NEW.object_id='batch-finding-1' BEGIN SELECT RAISE(ABORT,'audit fixture'); END`)
				want = nil
			case "event":
				_, _ = store.db.Exec(`CREATE TRIGGER batch_reject_event BEFORE INSERT ON finding_events WHEN NEW.finding_id='batch-finding-1' BEGIN SELECT RAISE(ABORT,'event fixture'); END`)
				want = nil
			case "cas":
				_, _ = store.db.Exec(`CREATE TRIGGER batch_reject_cas BEFORE UPDATE ON security_findings WHEN OLD.id='batch-finding-1' BEGIN SELECT RAISE(IGNORE); END`)
				want = ErrTaskConflict
			}
			before := map[string]string{}
			for _, f := range items {
				var raw string
				if err := store.db.QueryRow(`SELECT data FROM security_findings WHERE id=?`, f.ID).Scan(&raw); err != nil {
					t.Fatal(err)
				}
				before[f.ID] = raw
			}
			_, err := store.BatchFindingDisposition(context.Background(), in, actor)
			if err == nil || want != nil && !errors.Is(err, want) {
				t.Fatal(err, want)
			}
			for id, raw := range before {
				var after string
				if err := store.db.QueryRow(`SELECT data FROM security_findings WHERE id=?`, id).Scan(&after); err != nil || after != raw {
					t.Fatal("partial update", id, err)
				}
			}
			var n int
			if err := store.db.QueryRow(`SELECT COUNT(*) FROM finding_events`).Scan(&n); err != nil || n != 0 {
				t.Fatal("partial events", n, err)
			}
			if err := store.db.QueryRow(`SELECT COUNT(*) FROM audit_logs WHERE action='finding_status_changed'`).Scan(&n); err != nil || n != 0 {
				t.Fatal("partial audit", n, err)
			}
		})
	}
}
func TestFindingBatchConcurrentStatusSnapshot(t *testing.T) {
	store, actor, items := batchFixture(t)
	in := batchInput(items, "IN_PROGRESS")
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := store.BatchFindingDisposition(context.Background(), in, actor)
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	success := 0
	for err := range errs {
		if err == nil {
			success++
		} else if !errors.Is(err, ErrTaskConflict) {
			t.Fatal(err)
		}
	}
	if success != 1 {
		t.Fatal(success)
	}
	var n int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM finding_events`).Scan(&n); err != nil || n != 3 {
		t.Fatal(n, err)
	}
}
