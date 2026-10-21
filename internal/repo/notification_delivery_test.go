package repo

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNotificationSettingsValidationAndPersistence(t *testing.T) {
	store, _ := reportTestStore(t)
	ctx := context.Background()
	if _, err := store.SaveNotificationSettings(ctx, NotificationSettings{WebhookEnabled: true, WebhookURL: "http://notify.example.test/hook"}, "admin"); !errors.Is(err, ErrInvalidNotificationSettings) {
		t.Fatalf("non-loopback HTTP webhook accepted: %v", err)
	}
	saved, err := store.SaveNotificationSettings(ctx, NotificationSettings{WebhookEnabled: true, WebhookURL: "https://notify.example.test/hook"}, "admin")
	if err != nil || !saved.WebhookEnabled || saved.WebhookURL != "https://notify.example.test/hook" {
		t.Fatalf("save notification settings: %+v %v", saved, err)
	}
	loaded, err := store.GetNotificationSettings(ctx)
	if err != nil || loaded != saved {
		t.Fatalf("load notification settings: %+v %v", loaded, err)
	}
	cleared, err := store.SaveNotificationSettings(ctx, NotificationSettings{WebhookEnabled: true}, "admin")
	if err != nil || cleared.WebhookEnabled || cleared.WebhookURL != "" {
		t.Fatalf("blank webhook did not disable delivery: %+v %v", cleared, err)
	}
}

func TestNotificationOutboxDeliversSafeSummaryAndRetries(t *testing.T) {
	store, _ := reportTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	var payload webhookNotification
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.Header.Get("X-Scanner-Event") != "notification" {
			t.Fatalf("unexpected webhook request: %s %s", r.Method, r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("decode webhook payload: %v", err)
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()
	if _, err := store.SaveNotificationSettings(ctx, NotificationSettings{WebhookEnabled: true, WebhookURL: server.URL + "/hook"}, "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, `INSERT INTO notifications(id,kind,severity,title,message,object_type,object_id,created_at) VALUES(?,?,?,?,?,?,?,?)`, "notification-safe", "task_failed", "error", "扫描失败", "请查看任务详情", "task", "task-1", now.Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, `INSERT INTO notification_deliveries(id,notification_id,state,next_attempt_at,created_at) VALUES(?,?,?,?,?)`, "delivery-notification-safe", "notification-safe", "PENDING", now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	count, err := store.dispatchNotificationOutbox(ctx, server.Client(), now)
	if err != nil || count != 1 {
		t.Fatalf("dispatch count=%d err=%v", count, err)
	}
	if payload.SchemaVersion != 1 || payload.Notification.ID != "notification-safe" || strings.Contains(payload.Notification.Message, "127.0.0.1") {
		t.Fatalf("unexpected webhook payload: %+v", payload)
	}
	var state string
	if err := store.db.QueryRowContext(ctx, "SELECT state FROM notification_deliveries WHERE id=?", "delivery-notification-safe").Scan(&state); err != nil || state != "DELIVERED" {
		t.Fatalf("delivery state=%s err=%v", state, err)
	}
}

func TestNotificationOutboxMarksPermanentFailureAfterBoundedRetries(t *testing.T) {
	store, _ := reportTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "ignored body", http.StatusBadGateway) }))
	defer server.Close()
	if _, err := store.SaveNotificationSettings(ctx, NotificationSettings{WebhookEnabled: true, WebhookURL: server.URL}, "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, `INSERT INTO notifications(id,kind,severity,title,message,object_type,object_id,created_at) VALUES(?,?,?,?,?,?,?,?)`, "notification-failure", "task_failed", "error", "扫描失败", "摘要", "task", "task-2", now.Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, `INSERT INTO notification_deliveries(id,notification_id,state,attempts,next_attempt_at,created_at) VALUES(?,?,?,?,?,?)`, "delivery-notification-failure", "notification-failure", "PENDING", 4, now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.dispatchNotificationOutbox(ctx, server.Client(), now); err != nil {
		t.Fatal(err)
	}
	var state, lastError string
	if err := store.db.QueryRowContext(ctx, "SELECT state,last_error FROM notification_deliveries WHERE id=?", "delivery-notification-failure").Scan(&state, &lastError); err != nil {
		t.Fatal(err)
	}
	if state != "DEAD" || !strings.Contains(lastError, "HTTP 502") {
		t.Fatalf("unexpected permanent failure: state=%s error=%q", state, lastError)
	}
}

func TestNotificationOutboxRequeuesStaleClaim(t *testing.T) {
	store, _ := reportTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusAccepted) }))
	defer server.Close()
	if _, err := store.SaveNotificationSettings(ctx, NotificationSettings{WebhookEnabled: true, WebhookURL: server.URL}, "admin"); err != nil {
		t.Fatal(err)
	}
	stale := now.Add(-6 * time.Minute).Format(time.RFC3339Nano)
	if _, err := store.db.ExecContext(ctx, `INSERT INTO notifications(id,kind,severity,title,message,object_type,object_id,created_at) VALUES(?,?,?,?,?,?,?,?)`, "notification-stale", "task_failed", "error", "扫描失败", "摘要", "task", "task-3", stale); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, `INSERT INTO notification_deliveries(id,notification_id,state,attempts,next_attempt_at,created_at) VALUES(?,?,?,?,?,?)`, "delivery-notification-stale", "notification-stale", "SENDING", 1, stale, stale); err != nil {
		t.Fatal(err)
	}
	if _, err := store.dispatchNotificationOutbox(ctx, server.Client(), now); err != nil {
		t.Fatal(err)
	}
	var state string
	var attempts int
	if err := store.db.QueryRowContext(ctx, "SELECT state,attempts FROM notification_deliveries WHERE id=?", "delivery-notification-stale").Scan(&state, &attempts); err != nil {
		t.Fatal(err)
	}
	if state != "DELIVERED" || attempts != 2 {
		t.Fatalf("stale claim was not requeued and delivered: state=%s attempts=%d", state, attempts)
	}
}
