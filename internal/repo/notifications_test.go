package repo

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"scanner-platform/internal/approvals"
)

func TestNotificationsRefreshIsIdempotentAndReadStatePersists(t *testing.T) {
	store, actor := localFixture(t)
	ctx := context.Background()
	if _, err := approvals.New(store.db); err != nil {
		t.Fatal(err)
	}
	var assetID string
	if err := store.db.QueryRowContext(ctx, "SELECT id FROM assets LIMIT 1").Scan(&assetID); err != nil {
		t.Fatal(err)
	}
	windows, _ := json.Marshal([]map[string]any{{"weekdays": []int{1}, "start": "09:00", "end": "18:00", "timeZone": "UTC"}})
	if _, err := store.db.ExecContext(ctx, `INSERT INTO authorized_scopes
		(id,asset_id,cidr_or_host,max_targets,time_windows,requested_by,approved_by,approval_ticket,expires_at,status,review_note,created_at)
		VALUES(?,?,?,?,?,?,?,?,?,'APPROVED','',?)`,
		"scope-notification", assetID, "192.0.2.20", 1, string(windows), actor, actor, "ticket-notification", time.Now().Add(24*time.Hour).UTC().Format(time.RFC3339), time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	task, err := store.CreateSyntheticTask(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, "UPDATE scan_tasks SET status='FAILED' WHERE id=?", task.ID); err != nil {
		t.Fatal(err)
	}
	first, err := store.ListNotifications(ctx, false)
	if err != nil || len(first.Items) != 2 || first.Total != 2 || first.UnreadCount != 2 {
		t.Fatalf("first notification refresh: %+v %v", first, err)
	}
	second, err := store.ListNotifications(ctx, true)
	if err != nil || len(second.Items) != 2 {
		t.Fatalf("duplicate notification refresh: %+v %v", second, err)
	}
	if err := store.MarkNotificationRead(ctx, first.Items[0].ID); err != nil {
		t.Fatal(err)
	}
	unread, err := store.ListNotifications(ctx, true)
	if err != nil || len(unread.Items) != 1 || unread.UnreadCount != 1 {
		t.Fatalf("read state: %+v %v", unread, err)
	}
	if err := store.MarkAllNotificationsRead(ctx); err != nil {
		t.Fatal(err)
	}
	allRead, err := store.ListNotifications(ctx, true)
	if err != nil || len(allRead.Items) != 0 || allRead.UnreadCount != 0 {
		t.Fatalf("mark all read: %+v %v", allRead, err)
	}
}
