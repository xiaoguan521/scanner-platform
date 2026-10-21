package repo

import (
	"context"
	"errors"
	"strconv"
	"testing"

	"scanner-platform/internal/findings"
)

func TestKnowledgePageSearchesServerProjectionAndBounds(t *testing.T) {
	store, actor := localFixture(t)
	ctx := context.Background()
	for _, item := range []findings.KnowledgeEntry{
		{ID: "EXAMPLE-001", Title: "Apache risk", Description: "one", Component: "apache", Source: "fixture", Language: "zh-CN", Solution: "upgrade", AffectedRanges: []findings.VersionRange{{Introduced: "1.0", Fixed: "2.0"}}},
		{ID: "EXAMPLE-002", Title: "Redis risk", Description: "two", Component: "redis", Source: "fixture", Language: "original", Solution: "upgrade", AffectedRanges: []findings.VersionRange{{Introduced: "1.0", Fixed: "2.0"}}},
	} {
		if _, err := store.SaveKnowledge(ctx, item, actor); err != nil {
			t.Fatal(err)
		}
	}
	page, err := store.ListKnowledgePage(ctx, KnowledgeListQuery{Page: 1, PageSize: 1, Search: "redis"})
	if err != nil || page.Total != 1 || len(page.Items) != 1 || page.Items[0].ID != "EXAMPLE-002" || page.PageSize != 1 {
		t.Fatalf("knowledge page=%+v err=%v", page, err)
	}
	if _, err := store.ListKnowledgePage(ctx, KnowledgeListQuery{Page: 1, PageSize: 101}); !errors.Is(err, ErrInvalidKnowledgeListQuery) {
		t.Fatalf("invalid knowledge page size err=%v", err)
	}
	if _, err := store.ListKnowledgePage(ctx, KnowledgeListQuery{Page: 1, PageSize: 10, Search: "redis%"}); err != nil {
		t.Fatalf("escaped knowledge search failed: %v", err)
	}
}

func TestNotificationPagePreservesUnreadCountAndBounds(t *testing.T) {
	store, _ := localFixture(t)
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		id := "notification-page-" + strconv.Itoa(i)
		if _, err := store.db.ExecContext(ctx, `INSERT INTO notifications(id,kind,severity,title,message,object_type,object_id,created_at) VALUES(?,?,?,?,?,?,?,?)`, id, "test", "info", "title", "safe summary", "test", id, "2026-10-21T00:00:0"+strconv.Itoa(i)+"Z"); err != nil {
			t.Fatal(err)
		}
		if _, err := store.db.ExecContext(ctx, `INSERT INTO notification_deliveries(id,notification_id,state,next_attempt_at,created_at) VALUES(?,?, 'DELIVERED', ?, ?)`, "delivery-"+id, id, "2026-10-21T00:00:00Z", "2026-10-21T00:00:00Z"); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.MarkNotificationRead(ctx, "notification-page-0"); err != nil {
		t.Fatal(err)
	}
	page, err := store.ListNotificationsPage(ctx, NotificationListQuery{Page: 1, PageSize: 1, UnreadOnly: true})
	if err != nil || page.Total != 2 || page.UnreadCount != 2 || len(page.Items) != 1 || page.Page != 1 {
		t.Fatalf("notification page=%+v err=%v", page, err)
	}
	if _, err := store.ListNotificationsPage(ctx, NotificationListQuery{Page: 1, PageSize: 101}); !errors.Is(err, ErrInvalidNotificationListQuery) {
		t.Fatalf("invalid notification page size err=%v", err)
	}
}
