//go:build lab

package repo

import (
	"context"
	"os"
	"testing"

	"scanner-platform/internal/rules"
)

func TestPostgresRuleJobQueueClaimAndReport(t *testing.T) {
	dsnFile := os.Getenv("POSTGRES_DSN_FILE")
	if dsnFile == "" {
		t.Skip("POSTGRES_DSN_FILE is required for the PostgreSQL lab regression")
	}
	ctx := context.Background()
	dsn, err := ReadPostgresDSNFile(dsnFile)
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
	store, err := NewPostgresRuntime(db)
	if err != nil {
		t.Fatal(err)
	}
	job, err := store.QueueRuleJob(ctx, rules.Job{Kind: "ACTIVATE", Version: "20261020.120359"}, "lab-rule-job")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, _ = db.ExecContext(ctx, "DELETE FROM audit_logs WHERE object_id=$1", job.ID)
		_, _ = db.ExecContext(ctx, "DELETE FROM rule_jobs WHERE id=$1", job.ID)
	}()
	claimed, err := store.ClaimRuleJob(ctx, "lab-updater")
	if err != nil || claimed == nil || claimed.ID != job.ID || claimed.NodeID != "lab-updater" || claimed.Status != "RUNNING" {
		t.Fatalf("claim job=%+v err=%v", claimed, err)
	}
	if err := store.ReportRuleJob(ctx, rules.Report{JobID: job.ID, NodeID: "lab-updater", Status: "COMPLETED", Version: job.Version, Message: "done"}); err != nil {
		t.Fatal(err)
	}
	items, err := store.ListRuleJobs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range items {
		if item.ID == job.ID && item.Status != "COMPLETED" {
			t.Fatalf("reported rule job status=%q", item.Status)
		}
	}
}
