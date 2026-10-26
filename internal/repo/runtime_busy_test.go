package repo

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

// A second handle on the same file holds the write lock briefly; the runtime
// store must wait for it (busy_timeout) rather than fail with SQLITE_BUSY, even
// after its pooled connection has been replaced.
func TestRuntimeStoreWaitsForBusyDatabaseOnReplacedConnection(t *testing.T) {
	path := filepath.Join(t.TempDir(), "runtime.db")
	store, err := OpenRuntime(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	other, err := OpenRuntime(path)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()

	store.db.SetMaxIdleConns(0) // force every call onto a brand-new connection
	ctx := context.Background()
	tx, err := other.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO audit_logs(id,actor,action,created_at) VALUES('busy-1','t','a','2026-01-01T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	go func() {
		time.Sleep(700 * time.Millisecond)
		tx.Commit()
	}()
	start := time.Now()
	if _, err := store.db.ExecContext(ctx, `INSERT INTO audit_logs(id,actor,action,created_at) VALUES('busy-2','t','a','2026-01-01T00:00:00Z')`); err != nil {
		t.Fatalf("write during a short lock must wait, got %v", err)
	}
	if time.Since(start) < 500*time.Millisecond {
		t.Fatal("write did not wait for the lock holder")
	}
}
