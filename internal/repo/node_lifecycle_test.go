package repo

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestNodeLifecycleRegistrationHeartbeatOfflineAndRevocation(t *testing.T) {
	store, err := OpenRuntime(filepath.Join(t.TempDir(), "nodes.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	input := NodeLifecycle{ID: "worker-a", Kind: "worker", HostID: "host-a"}
	if _, err := store.RegisterNodeLifecycle(ctx, NodeLifecycle{ID: "bad/id", Kind: "worker", HostID: "host-a"}, "admin"); !errors.Is(err, ErrInvalidNodeLifecycle) {
		t.Fatalf("invalid id: %v", err)
	}
	item, err := store.RegisterNodeLifecycle(ctx, input, "admin")
	if err != nil || item.Status != "REGISTERED" {
		t.Fatalf("register: %+v %v", item, err)
	}
	if _, err := store.RegisterNodeLifecycle(ctx, input, "admin"); !errors.Is(err, ErrNodeLifecycleExists) {
		t.Fatalf("duplicate: %v", err)
	}
	if err := store.TouchNodeLifecycle(ctx, "worker-a", "updater"); !errors.Is(err, ErrInvalidNodeLifecycle) {
		t.Fatalf("wrong kind: %v", err)
	}
	if err := store.TouchNodeLifecycle(ctx, "worker-a", "worker"); err != nil {
		t.Fatal(err)
	}
	item, found, err := store.GetNodeLifecycle(ctx, "worker-a")
	if err != nil || !found || item.Status != "ONLINE" || item.LastHeartbeat == nil {
		t.Fatalf("online: %+v %t %v", item, found, err)
	}
	if _, err := store.db.ExecContext(ctx, `UPDATE node_lifecycle SET last_heartbeat=? WHERE id=?`, nodeTime(time.Now().Add(-11*time.Second)), "worker-a"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := store.RefreshNodeLifecycle(ctx, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	item, _, err = store.GetNodeLifecycle(ctx, "worker-a")
	if err != nil || item.Status != "OFFLINE" || item.OfflineGeneration != 1 {
		t.Fatalf("offline: %+v %v", item, err)
	}
	if err := store.TouchNodeLifecycle(ctx, "worker-a", "worker"); err != nil {
		t.Fatal(err)
	}
	events, err := store.ListNodeLifecycleEvents(ctx, "worker-a")
	if err != nil || len(events) != 3 || events[0].Kind != "REGISTERED" || events[1].Kind != "OFFLINE" || events[2].Kind != "RECOVERED" {
		t.Fatalf("events: %+v %v", events, err)
	}
	if err := store.RevokeNodeLifecycle(ctx, "worker-a", "admin"); err != nil {
		t.Fatal(err)
	}
	if err := store.RevokeNodeLifecycle(ctx, "worker-a", "admin"); err != nil {
		t.Fatal(err)
	}
	if err := store.TouchNodeLifecycle(ctx, "worker-a", "worker"); !errors.Is(err, ErrNodeRevoked) {
		t.Fatalf("revoked heartbeat: %v", err)
	}
	events, err = store.ListNodeLifecycleEvents(ctx, "worker-a")
	if err != nil || len(events) != 4 || events[3].Kind != "REVOKED" {
		t.Fatalf("revoke event: %+v %v", events, err)
	}
	if err := store.RevokeNodeLifecycle(ctx, "missing", "admin"); !errors.Is(err, ErrNodeLifecycleNotFound) {
		t.Fatalf("missing: %v", err)
	}
}

func TestNodeOfflineNotificationIsIdempotent(t *testing.T) {
	store, err := OpenRuntime(filepath.Join(t.TempDir(), "nodes.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	if _, err := store.RegisterNodeLifecycle(ctx, NodeLifecycle{ID: "offline-worker", Kind: "worker", HostID: "host-a"}, "admin"); err != nil {
		t.Fatal(err)
	}
	if err := store.TouchNodeLifecycle(ctx, "offline-worker", "worker"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, `UPDATE node_lifecycle SET last_heartbeat=? WHERE id=?`, nodeTime(time.Now().Add(-11*time.Second)), "offline-worker"); err != nil {
		t.Fatal(err)
	}
	if err := store.RefreshNotifications(ctx); err != nil {
		t.Fatal(err)
	}
	if err := store.RefreshNotifications(ctx); err != nil {
		t.Fatal(err)
	}
	items, err := store.ListNotifications(ctx, false)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, item := range items.Items {
		if item.Kind == "node_offline" && item.ObjectID == "offline-worker" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("node offline notifications=%d, want 1: %+v", count, items.Items)
	}
}
