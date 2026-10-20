package repo

import (
	"context"
	"encoding/json"
	"errors"
	"scanner-platform/internal/taskflow"
	"strings"
	"sync"
	"testing"
	"time"
)

func dispositionFixture(t *testing.T) (*RuntimeStore, string, taskflow.Finding) {
	t.Helper()
	store, actor := localFixture(t)
	approveFixturePort(t, store, actor, "192.0.2.20", 80)
	installNucleiFixtureBundle(t, store, "20261020.10")
	task := createClaimedNucleiTask(t, store, actor, "disposition-worker")
	completeNucleiFixture(t, store, task, fixtureNucleiFinding())
	items, err := store.ListRuntimeFindings(context.Background())
	if err != nil || len(items) != 1 {
		t.Fatal(items, err)
	}
	return store, actor, items[0]
}
func acceptInput() FindingDisposition {
	return FindingDisposition{Status: "ACCEPTED_RISK", Reason: "业务变更窗口待安排", AcceptedUntil: time.Now().Add(time.Hour).Format(time.RFC3339)}
}

func TestFindingAcceptanceValidationAndTransitions(t *testing.T) {
	store, actor, f := dispositionFixture(t)
	ctx := context.Background()
	for _, tc := range []struct {
		name string
		in   FindingDisposition
	}{
		{"no reason", FindingDisposition{Status: "ACCEPTED_RISK", AcceptedUntil: acceptInput().AcceptedUntil}},
		{"control", FindingDisposition{Status: "ACCEPTED_RISK", Reason: "a\nb", AcceptedUntil: acceptInput().AcceptedUntil}},
		{"too long", FindingDisposition{Status: "ACCEPTED_RISK", Reason: strings.Repeat("中", 167), AcceptedUntil: acceptInput().AcceptedUntil}},
		{"past", FindingDisposition{Status: "ACCEPTED_RISK", Reason: "reason", AcceptedUntil: time.Now().Add(-time.Minute).Format(time.RFC3339)}},
		{"too far", FindingDisposition{Status: "ACCEPTED_RISK", Reason: "reason", AcceptedUntil: time.Now().Add(366 * 24 * time.Hour).Format(time.RFC3339)}},
		{"no zone", FindingDisposition{Status: "ACCEPTED_RISK", Reason: "reason", AcceptedUntil: "2026-10-21T12:00:00"}},
		{"fixed", FindingDisposition{Status: "FIXED"}}, {"noop", FindingDisposition{Status: "OPEN"}}, {"extraneous", FindingDisposition{Status: "IN_PROGRESS", Reason: "unexpected"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := store.UpdateFindingDisposition(ctx, f.ID, tc.in, actor); !errors.Is(err, ErrInvalidTask) {
				t.Fatal(err)
			}
		})
	}
	if _, err := store.UpdateFindingDisposition(ctx, f.ID, acceptInput(), ""); !errors.Is(err, ErrInvalidTask) {
		t.Fatal("empty actor", err)
	}
	in := acceptInput()
	in.Reason = "  " + in.Reason + "  "
	accepted, err := store.UpdateFindingDisposition(ctx, f.ID, in, actor)
	if err != nil || accepted.AcceptedUntil == nil || accepted.AcceptedReason != strings.TrimSpace(in.Reason) {
		t.Fatal(accepted, err)
	}
	if _, err := store.UpdateFinding(ctx, f.ID, "FALSE_POSITIVE", actor); !errors.Is(err, ErrInvalidTask) {
		t.Fatal("accepted must be revoked first", err)
	}
	events, err := store.ListFindingEvents(ctx, f.ID)
	if err != nil || len(events) != 1 || events[0].Reason != accepted.AcceptedReason {
		t.Fatal(events, err)
	}
	var detail string
	if err := store.db.QueryRow(`SELECT detail FROM audit_logs WHERE object_id=? AND action='finding_status_changed'`, f.ID).Scan(&detail); err != nil || strings.Contains(detail, accepted.AcceptedReason) || !strings.Contains(detail, events[0].ID) {
		t.Fatal(detail, err)
	}
	reopened, err := store.UpdateFinding(ctx, f.ID, "OPEN", actor)
	if err != nil || reopened.AcceptedUntil != nil || reopened.AcceptedReason != "" {
		t.Fatal(reopened, err)
	}
	if _, err := store.UpdateFinding(ctx, f.ID, "FALSE_POSITIVE", actor); err != nil {
		t.Fatal(err)
	}
	if _, err := store.UpdateFindingDisposition(ctx, f.ID, acceptInput(), actor); !errors.Is(err, ErrInvalidTask) {
		t.Fatal("false positive accepted", err)
	}
}

func TestFindingAcceptanceExpiryConcurrentAndLegacy(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		t.Run(map[bool]string{false: "expired", true: "legacy"}[legacy], func(t *testing.T) {
			store, actor, f := dispositionFixture(t)
			ctx := context.Background()
			f.Status = "ACCEPTED_RISK"
			f.AcceptedReason = "legacy reason"
			expired := time.Now().Add(-time.Hour)
			if !legacy {
				f.AcceptedUntil = &expired
			}
			raw, _ := json.Marshal(f)
			if _, err := store.db.Exec(`UPDATE security_findings SET data=? WHERE id=?`, string(raw), f.ID); err != nil {
				t.Fatal(err)
			}
			var wg sync.WaitGroup
			errs := make(chan error, 8)
			for i := 0; i < 8; i++ {
				wg.Add(1)
				go func() { defer wg.Done(); errs <- store.ExpireAcceptedRisks(ctx, time.Now()) }()
			}
			wg.Wait()
			close(errs)
			for err := range errs {
				if err != nil {
					t.Fatal(err)
				}
			}
			items, err := store.ListRuntimeFindings(ctx)
			if err != nil || items[0].Status != "OPEN" || items[0].AcceptedUntil != nil || items[0].AcceptedReason != "" {
				t.Fatal(items, err)
			}
			events, err := store.ListFindingEvents(ctx, f.ID)
			if err != nil || len(events) != 1 || events[0].Actor != "system" {
				t.Fatal(events, err)
			}
			if _, err := store.UpdateFinding(ctx, f.ID, "IN_PROGRESS", actor); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestFindingAcceptanceMalformedExpiryReopens(t *testing.T) {
	store, _, f := dispositionFixture(t)
	ctx := context.Background()
	f.Status = "ACCEPTED_RISK"
	f.AcceptedReason = "legacy reason"
	raw, _ := json.Marshal(f)
	var object map[string]any
	if err := json.Unmarshal(raw, &object); err != nil {
		t.Fatal(err)
	}
	object["acceptedUntil"] = "not-a-timestamp"
	raw, _ = json.Marshal(object)
	if _, err := store.db.Exec(`UPDATE security_findings SET data=? WHERE id=?`, string(raw), f.ID); err != nil {
		t.Fatal(err)
	}
	items, err := store.ListRuntimeFindings(ctx)
	if err != nil || len(items) != 1 || items[0].Status != "OPEN" || items[0].AcceptedUntil != nil || items[0].AcceptedReason != "" {
		t.Fatal(items, err)
	}
	events, err := store.ListFindingEvents(ctx, f.ID)
	if err != nil || len(events) != 1 || events[0].ToStatus != "OPEN" {
		t.Fatal(events, err)
	}
}

func TestFindingAcceptanceScanPreservationAndLifecycleEvents(t *testing.T) {
	store, actor, f := dispositionFixture(t)
	ctx := context.Background()
	accepted, err := store.UpdateFindingDisposition(ctx, f.ID, acceptInput(), actor)
	if err != nil {
		t.Fatal(err)
	}
	task := createClaimedNucleiTask(t, store, actor, "disposition-worker")
	completeNucleiFixture(t, store, task, fixtureNucleiFinding())
	items, err := store.ListRuntimeFindings(ctx)
	if err != nil || items[0].Status != "ACCEPTED_RISK" || items[0].AcceptedReason != accepted.AcceptedReason || !items[0].AcceptedUntil.Equal(*accepted.AcceptedUntil) {
		t.Fatal(items, err)
	}
	// Expiry is processed before the result, even without a list or Tick.
	expired := time.Now().Add(-time.Hour)
	items[0].AcceptedUntil = &expired
	raw, _ := json.Marshal(items[0])
	if _, err := store.db.Exec(`UPDATE security_findings SET data=? WHERE id=?`, string(raw), f.ID); err != nil {
		t.Fatal(err)
	}
	task = createClaimedNucleiTask(t, store, actor, "disposition-worker")
	completeNucleiFixture(t, store, task)
	items, err = store.ListRuntimeFindings(ctx)
	if err != nil || items[0].Status != "FIXED" {
		t.Fatal(items, err)
	}
	if _, err := store.UpdateFinding(ctx, f.ID, "OPEN", actor); !errors.Is(err, ErrInvalidTask) {
		t.Fatal("manual reopened fixed", err)
	}
	task = createClaimedNucleiTask(t, store, actor, "disposition-worker")
	completeNucleiFixture(t, store, task, fixtureNucleiFinding())
	events, err := store.ListFindingEvents(ctx, f.ID)
	if err != nil || len(events) != 4 || events[1].ToStatus != "OPEN" || events[2].ToStatus != "FIXED" || events[3].ToStatus != "REOPENED" {
		t.Fatal(events, err)
	}
}

func TestFindingDispositionRollsBackWhenEventFails(t *testing.T) {
	store, actor, f := dispositionFixture(t)
	ctx := context.Background()
	if _, err := store.db.Exec(`CREATE TRIGGER reject_finding_event BEFORE INSERT ON finding_events BEGIN SELECT RAISE(ABORT,'fixture reject'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.UpdateFindingDisposition(ctx, f.ID, acceptInput(), actor); err == nil {
		t.Fatal("event error ignored")
	}
	items, err := store.ListRuntimeFindings(ctx)
	if err != nil || items[0].Status != "OPEN" || items[0].AcceptedUntil != nil {
		t.Fatal(items, err)
	}
	var n int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM audit_logs WHERE object_id=? AND action='finding_status_changed'`, f.ID).Scan(&n); err != nil || n != 0 {
		t.Fatal(n, err)
	}
}

func TestFindingAcceptanceTickAndAuditRollback(t *testing.T) {
	store, actor, f := dispositionFixture(t)
	ctx := context.Background()
	accepted, err := store.UpdateFindingDisposition(ctx, f.ID, acceptInput(), actor)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Tick(ctx, accepted.AcceptedUntil.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	events, err := store.ListFindingEvents(ctx, f.ID)
	if err != nil || len(events) != 2 || events[1].Actor != "system" || events[1].ToStatus != "OPEN" {
		t.Fatal(events, err)
	}
	if _, err := store.db.Exec(`CREATE TRIGGER reject_finding_audit BEFORE INSERT ON audit_logs WHEN NEW.action='finding_status_changed' BEGIN SELECT RAISE(ABORT,'fixture audit reject'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.UpdateFindingDisposition(ctx, f.ID, acceptInput(), actor); err == nil {
		t.Fatal("audit failure ignored")
	}
	items, err := store.ListRuntimeFindings(ctx)
	if err != nil || items[0].Status != "OPEN" {
		t.Fatal(items, err)
	}
	events, err = store.ListFindingEvents(ctx, f.ID)
	if err != nil || len(events) != 2 {
		t.Fatal("audit failure left an event", events, err)
	}
}

func TestFindingAcceptanceFromActiveStatesAndListExpiry(t *testing.T) {
	for _, status := range []string{"IN_PROGRESS", "REOPENED"} {
		t.Run(status, func(t *testing.T) {
			store, actor, f := dispositionFixture(t)
			ctx := context.Background()
			f.Status = status
			raw, _ := json.Marshal(f)
			if _, err := store.db.Exec(`UPDATE security_findings SET data=? WHERE id=?`, string(raw), f.ID); err != nil {
				t.Fatal(err)
			}
			accepted, err := store.UpdateFindingDisposition(ctx, f.ID, acceptInput(), actor)
			if err != nil || accepted.Status != "ACCEPTED_RISK" {
				t.Fatal(accepted, err)
			}
			expired := time.Now().Add(-time.Hour)
			accepted.AcceptedUntil = &expired
			raw, _ = json.Marshal(accepted)
			if _, err := store.db.Exec(`UPDATE security_findings SET data=? WHERE id=?`, string(raw), f.ID); err != nil {
				t.Fatal(err)
			}
			items, err := store.ListRuntimeFindings(ctx)
			if err != nil || items[0].Status != "OPEN" || items[0].AcceptedUntil != nil {
				t.Fatal(items, err)
			}
		})
	}
}
