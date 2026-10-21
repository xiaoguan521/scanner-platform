//go:build lab

package repo

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPostgresNodeLifecycleLab(t *testing.T) {
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
	store, err := NewPostgresRuntime(db)
	if err != nil {
		t.Fatal(err)
	}
	const nodeID = "lab-node-lifecycle"
	cleanup := func() {
		_, _ = db.ExecContext(ctx, `DELETE FROM node_lifecycle_events WHERE node_id=$1`, nodeID)
		_, _ = db.ExecContext(ctx, `DELETE FROM node_lifecycle WHERE id=$1`, nodeID)
		_, _ = db.ExecContext(ctx, `DELETE FROM audit_logs WHERE object_type='node' AND object_id=$1`, nodeID)
	}
	cleanup()
	defer cleanup()

	item, err := store.RegisterNodeLifecycle(ctx, NodeLifecycle{ID: nodeID, Kind: "worker", HostID: "lab-host"}, "lab-admin")
	if err != nil || item.Status != "REGISTERED" {
		t.Fatalf("register item=%+v err=%v", item, err)
	}
	page, err := store.ListNodesPage(ctx, NodeListQuery{Page: 1, PageSize: 20, Search: nodeID})
	if err != nil || page.Total != 1 || len(page.Items) != 1 || page.Items[0].LifecycleStatus != "REGISTERED" {
		t.Fatalf("registered-only node page=%+v err=%v", page, err)
	}
	if err := store.TouchNodeLifecycle(ctx, nodeID, "worker"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.GetNodeLifecycle(ctx, nodeID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE node_lifecycle SET last_heartbeat=$1 WHERE id=$2`, nodeTime(time.Now().Add(-11*time.Second)), nodeID); err != nil {
		t.Fatal(err)
	}
	if err := store.RefreshNodeLifecycle(ctx, time.Now()); err != nil {
		t.Fatal(err)
	}
	item, _, err = store.GetNodeLifecycle(ctx, nodeID)
	if err != nil || item.Status != "OFFLINE" || item.OfflineGeneration != 1 {
		t.Fatalf("offline item=%+v err=%v", item, err)
	}
	if err := store.RevokeNodeLifecycle(ctx, nodeID, "lab-admin"); err != nil {
		t.Fatal(err)
	}
	if err := store.TouchNodeLifecycle(ctx, nodeID, "worker"); !errors.Is(err, ErrNodeRevoked) {
		t.Fatalf("revoked heartbeat err=%v", err)
	}
	events, err := store.ListNodeLifecycleEvents(ctx, nodeID)
	if err != nil || len(events) != 3 {
		t.Fatalf("events=%+v err=%v", events, err)
	}
}
