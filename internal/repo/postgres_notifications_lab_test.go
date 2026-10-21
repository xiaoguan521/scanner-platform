//go:build lab

package repo

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestPostgresNotificationsRefreshReadAndWebhookDelivery(t *testing.T) {
	dsnFile := os.Getenv("POSTGRES_DSN_FILE")
	if dsnFile == "" {
		t.Skip("set POSTGRES_DSN_FILE to an isolated PostgreSQL fixture")
	}
	ctx := context.Background()
	dsn, err := ReadPostgresDSNFile(filepath.Clean(dsnFile))
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

	const (
		actor   = "lab-postgres-notification-user"
		review  = "lab-postgres-notification-reviewer"
		assetID = "lab-postgres-notification-asset"
		scopeID = "lab-postgres-notification-scope"
		taskID  = "lab-postgres-notification-task"
	)
	cleanup := func() {
		_, _ = db.ExecContext(ctx, `DELETE FROM notification_deliveries WHERE notification_id LIKE 'notification-scope_%' OR notification_id LIKE 'notification-task-failed-%'`)
		_, _ = db.ExecContext(ctx, `DELETE FROM notifications WHERE id LIKE 'notification-scope_%' OR id=$1`, "notification-task-failed-"+taskID)
		_, _ = db.ExecContext(ctx, `DELETE FROM product_settings WHERE id=$1`, notificationSettingsID)
		_, _ = db.ExecContext(ctx, `DELETE FROM scan_tasks WHERE id=$1`, taskID)
		_, _ = db.ExecContext(ctx, `DELETE FROM authorized_scopes WHERE id=$1`, scopeID)
		_, _ = db.ExecContext(ctx, `DELETE FROM assets WHERE id=$1`, assetID)
		_, _ = db.ExecContext(ctx, `DELETE FROM audit_logs WHERE actor IN ($1,$2)`, actor, review)
		_, _ = db.ExecContext(ctx, `DELETE FROM users WHERE id IN ($1,$2)`, actor, review)
	}
	cleanup()
	defer cleanup()
	for _, user := range []struct{ id, name string }{{actor, "pg_notification_user"}, {review, "pg_notification_reviewer"}} {
		if _, err := db.ExecContext(ctx, `INSERT INTO users(id,username,role,is_active,password_hash)
			VALUES ($1,$2,'admin',TRUE,'fixture-only')`, user.id, user.name); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO assets(id,kind,address,business_group,owner)
		VALUES ($1,'host','192.0.2.70','fixture','fixture-owner')`, assetID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO authorized_scopes
		(id,asset_id,cidr_or_host,max_targets,time_windows,requested_by,approved_by,approval_ticket,expires_at,status,created_at)
		VALUES ($1,$2,'192.0.2.70',1,'[]',$3,$4,'PG-NOTIFICATION-SCOPE',CURRENT_TIMESTAMP + INTERVAL '1 hour','APPROVED',CURRENT_TIMESTAMP)`, scopeID, assetID, actor, review); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO scan_tasks
		(id,scope_id,engines,status,created_by) VALUES ($1,$2,'["auto"]','FAILED',$3)`, taskID, scopeID, actor); err != nil {
		t.Fatal(err)
	}

	store, err := NewPostgresRuntime(db)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.RefreshNotifications(ctx); err != nil {
		t.Fatal(err)
	}
	page, err := store.ListNotificationsPage(ctx, NotificationListQuery{Page: 1, PageSize: 100})
	if err != nil {
		t.Fatal(err)
	}
	var scopeNotification, taskNotification string
	for _, item := range page.Items {
		if item.ObjectID == scopeID {
			scopeNotification = item.ID
		}
		if item.ObjectID == taskID {
			taskNotification = item.ID
		}
	}
	if scopeNotification == "" || taskNotification == "" || page.UnreadCount < 2 {
		t.Fatalf("notification page=%+v", page)
	}
	if err := store.MarkNotificationRead(ctx, scopeNotification); err != nil {
		t.Fatal(err)
	}
	readPage, err := store.ListNotificationsPage(ctx, NotificationListQuery{Page: 1, PageSize: 100, UnreadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range readPage.Items {
		if item.ID == scopeNotification {
			t.Fatalf("read notification remained unread: %+v", item)
		}
	}

	var received int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.Header.Get("X-Scanner-Event") != "notification" {
			t.Errorf("webhook request method=%s event=%q", r.Method, r.Header.Get("X-Scanner-Event"))
		}
		var body struct {
			SchemaVersion int          `json:"schemaVersion"`
			Event         string       `json:"event"`
			Notification  Notification `json:"notification"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decode webhook body: %v", err)
		} else if body.SchemaVersion != 1 || body.Event != "notification" || body.Notification.ID == "" {
			t.Errorf("webhook body=%+v", body)
		}
		received++
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	if _, err := store.SaveNotificationSettings(ctx, NotificationSettings{WebhookEnabled: true, WebhookURL: server.URL}, actor); err != nil {
		t.Fatal(err)
	}
	delivered, err := store.DispatchNotificationOutbox(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if delivered < 2 || received < 2 {
		t.Fatalf("delivered=%d received=%d", delivered, received)
	}
	var state string
	if err := db.QueryRowContext(ctx, `SELECT state FROM notification_deliveries WHERE notification_id=$1`, taskNotification).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if state != "DELIVERED" {
		t.Fatalf("task notification delivery state=%q", state)
	}
	settings, err := store.GetNotificationSettings(ctx)
	if err != nil || !settings.WebhookEnabled || settings.WebhookURL != server.URL {
		t.Fatalf("settings=%+v err=%v", settings, err)
	}
}
