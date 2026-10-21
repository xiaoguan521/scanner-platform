package repo

import (
	"context"
	"path/filepath"
	"testing"
)

func TestListAuditLogsFiltersAndOmitsDetail(t *testing.T) {
	ctx := context.Background()
	store, err := OpenRuntime(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	for _, row := range []struct {
		id, actor, action, objectType, objectID, createdAt string
	}{
		{"audit-1", "alice", "create_asset", "asset", "asset-1", "2026-10-20T10:00:00Z"},
		{"audit-2", "bob", "delete_asset", "asset", "asset-2", "2026-10-20T11:00:00Z"},
		{"audit-3", "alice", "create_task", "task", "task-1", "2026-10-20T12:00:00Z"},
	} {
		if _, err := store.db.ExecContext(ctx, `INSERT INTO audit_logs(id,actor,action,object_type,object_id,detail,created_at) VALUES(?,?,?,?,?,?,?)`, row.id, row.actor, row.action, row.objectType, row.objectID, `{"target":"192.0.2.10","secret":"should-not-return"}`, row.createdAt); err != nil {
			t.Fatal(err)
		}
	}
	items, total, err := store.ListAuditLogs(ctx, AuditLogQuery{Actor: "alice", ObjectType: "asset", Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if total != 1 || len(items) != 1 || items[0].ID != "audit-1" || items[0].Actor != "alice" || items[0].ObjectID != "asset-1" {
		t.Fatalf("unexpected filtered audit logs: total=%d items=%+v", total, items)
	}
	items, total, err = store.ListAuditLogs(ctx, AuditLogQuery{Limit: 2, Offset: 1})
	if err != nil {
		t.Fatal(err)
	}
	if total != 3 || len(items) != 2 || items[0].ID != "audit-2" || items[1].ID != "audit-1" {
		t.Fatalf("unexpected pagination/order: total=%d items=%+v", total, items)
	}
	items, total, err = store.ListAuditLogs(ctx, AuditLogQuery{ObjectID: "asset-2", Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if total != 1 || len(items) != 1 || items[0].ID != "audit-2" {
		t.Fatalf("unexpected object id filter: total=%d items=%+v", total, items)
	}
}
