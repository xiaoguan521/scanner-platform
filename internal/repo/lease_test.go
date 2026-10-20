package repo

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"scanner-platform/internal/portprobe"
	"scanner-platform/internal/taskflow"
)

func TestRuntimeMigratesLeaseColumnsForExistingSQLiteDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE scan_tasks (
		id TEXT PRIMARY KEY, status TEXT NOT NULL,
		worker_id TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL,
		started_at TEXT, finished_at TEXT, targets TEXT NOT NULL)`); err != nil {
		db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	store, err := OpenRuntime(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	rows, err := store.db.QueryContext(context.Background(), "PRAGMA table_info(scan_tasks)")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	columns := map[string]bool{}
	for rows.Next() {
		var cid, notNull, pk int
		var name, kind string
		var defaultValue any
		if err := rows.Scan(&cid, &name, &kind, &notNull, &defaultValue, &pk); err != nil {
			t.Fatal(err)
		}
		columns[name] = true
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"details", "pinned_rule_version", "lease_expires_at"} {
		if !columns[name] {
			t.Fatalf("legacy migration did not add %s: %v", name, columns)
		}
	}
}

func createLeasePortProbe(t *testing.T, store *RuntimeStore, actor string) taskflow.Task {
	t.Helper()
	ctx := context.Background()
	var assetID string
	if err := store.db.QueryRowContext(ctx, "SELECT id FROM assets WHERE address=?", "192.0.2.20").Scan(&assetID); err != nil {
		t.Fatal(err)
	}
	task, err := store.CreateLocalTask(ctx, taskflow.TaskInput{
		Engine: "port-probe", AssetID: assetID,
		PortProbe: portprobe.Config{Preset: portprobe.PresetCustom, Ranges: []portprobe.Range{{Start: 1234, End: 1234}}, OpsApproved: true},
	}, actor)
	if err != nil {
		t.Fatal(err)
	}
	return task
}

func TestRuntimeClaimRenewAndTickReclaimLease(t *testing.T) {
	store, actor := localFixture(t)
	store.LeaseDuration = 120 * time.Millisecond
	ctx := context.Background()
	created := createLeasePortProbe(t, store, actor)

	claimed, err := store.ClaimRuntimeTask(ctx, "lease-worker")
	if err != nil || claimed == nil {
		t.Fatalf("claim real task: %+v %v", claimed, err)
	}
	chunk := claimed.Chunks[0]
	if claimed.Synthetic || chunk.PinnedRuleVersion != NoRuleLeaseVersion || chunk.LeaseExpiresAt == nil || !chunk.LeaseExpiresAt.After(time.Now().UTC()) {
		t.Fatalf("claim did not return a bounded lease: %+v", claimed)
	}
	if count, err := store.CountRunningByVersion(ctx, "lease-worker", NoRuleLeaseVersion); err != nil || count != 1 {
		t.Fatalf("running lease count=%d err=%v", count, err)
	}

	if _, err := store.RenewChunkLease(ctx, claimed.ID, "other-worker", chunk.PinnedRuleVersion); !errors.Is(err, ErrTaskLease) {
		t.Fatalf("wrong worker renewal accepted: %v", err)
	}
	if _, err := store.RenewChunkLease(ctx, claimed.ID, "lease-worker", "other-version"); !errors.Is(err, ErrTaskLease) {
		t.Fatalf("wrong version renewal accepted: %v", err)
	}
	oldExpiry := *chunk.LeaseExpiresAt
	newExpiry, err := store.RenewChunkLease(ctx, claimed.ID, "lease-worker", chunk.PinnedRuleVersion)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if !newExpiry.After(oldExpiry) || newExpiry.Sub(now) > store.LeaseDuration+50*time.Millisecond {
		t.Fatalf("renewal was not extended within the bound: old=%s new=%s now=%s", oldExpiry, newExpiry, now)
	}

	if _, err := store.db.ExecContext(ctx, "UPDATE scan_tasks SET lease_expires_at=? WHERE id=?", now.Add(-time.Second).Format(time.RFC3339Nano), claimed.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.RenewChunkLease(ctx, claimed.ID, "lease-worker", chunk.PinnedRuleVersion); !errors.Is(err, ErrTaskLease) {
		t.Fatalf("expired renewal accepted: %v", err)
	}
	if err := store.Tick(ctx, now); err != nil {
		t.Fatal(err)
	}
	tasks, err := store.ListRuntimeTasks(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(tasks) != 1 || tasks[0].ID != created.ID || tasks[0].Status != "PENDING" || tasks[0].Chunks[0].LeaseExpiresAt != nil || tasks[0].Chunks[0].PinnedRuleVersion != "" {
		t.Fatalf("expired lease was not reclaimed: %+v", tasks)
	}
}

func TestRuntimeConcurrentLeaseRenewalsKeepBinding(t *testing.T) {
	store, actor := localFixture(t)
	store.LeaseDuration = time.Second
	ctx := context.Background()
	created := createLeasePortProbe(t, store, actor)
	claimed, err := store.ClaimRuntimeTask(ctx, "lease-race-worker")
	if err != nil || claimed == nil {
		t.Fatalf("claim: %+v %v", claimed, err)
	}
	version := claimed.Chunks[0].PinnedRuleVersion
	var wg sync.WaitGroup
	results := make(chan error, 12)
	for range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := store.RenewChunkLease(ctx, created.ID, "lease-race-worker", version)
			results <- err
		}()
	}
	wg.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatalf("concurrent renewal failed: %v", err)
		}
	}
	var status, worker, bound, lease string
	if err := store.db.QueryRowContext(ctx, "SELECT status,worker_id,pinned_rule_version,lease_expires_at FROM scan_tasks WHERE id=?", created.ID).Scan(&status, &worker, &bound, &lease); err != nil {
		t.Fatal(err)
	}
	if status != "RUNNING" || worker != "lease-race-worker" || bound != version || lease == "" {
		t.Fatalf("concurrent renewal changed binding: status=%q worker=%q version=%q lease=%q", status, worker, bound, lease)
	}
}

func TestClaimWithLocalRulesSkipsUnavailableRuleTaskButKeepsNoRuleTaskEligible(t *testing.T) {
	store, actor := localFixture(t)
	ctx := context.Background()
	approveFixturePort(t, store, actor, "192.0.2.20", 80)
	installNucleiFixtureBundle(t, store, "20261020.05")
	if _, err := store.CreateLocalTask(ctx, taskflow.TaskInput{Engine: "nuclei", Scheme: "http", Targets: []string{"192.0.2.20:80"}}, actor); err != nil {
		t.Fatal(err)
	}
	portTask := createLeasePortProbe(t, store, actor)

	claimed, err := store.ClaimRuntimeTaskWithRules(ctx, "rules-missing-worker", "", false)
	if err != nil || claimed == nil || len(claimed.Engines) != 1 || claimed.Engines[0] != "port-probe" || claimed.ID != portTask.ID {
		t.Fatalf("missing local rules claimed the wrong task: %+v err=%v", claimed, err)
	}
	if claimed, err := store.ClaimRuntimeTaskWithRules(ctx, "rules-mismatch-worker", "20261020.06", true); err != nil || claimed != nil {
		t.Fatalf("mismatched local rules claimed a rule task: %+v err=%v", claimed, err)
	}
	claimed, err = store.ClaimRuntimeTaskWithRules(ctx, "rules-ready-worker", "20261020.05", true)
	if err != nil || claimed == nil || len(claimed.Engines) != 1 || claimed.Engines[0] != "nuclei" {
		t.Fatalf("matching local rules did not claim rule task: %+v err=%v", claimed, err)
	}
}
