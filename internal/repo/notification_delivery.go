package repo

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// NotificationSettings controls the optional, administrator-configured
// outbound webhook. The payload is limited to the same safe summary that is
// shown in the in-product notification center; targets, credentials, request
// and response evidence are never sent.
type NotificationSettings struct {
	WebhookEnabled bool   `json:"webhookEnabled"`
	WebhookURL     string `json:"webhookUrl"`
}

type NotificationDelivery struct {
	ID             string  `json:"id"`
	NotificationID string  `json:"notificationId"`
	State          string  `json:"state"`
	Attempts       int     `json:"attempts"`
	NextAttemptAt  string  `json:"nextAttemptAt"`
	LastError      string  `json:"lastError,omitempty"`
	DeliveredAt    *string `json:"deliveredAt,omitempty"`
	CreatedAt      string  `json:"createdAt"`
}

type NotificationDeliveryList struct {
	Items []NotificationDelivery `json:"items"`
	Total int                    `json:"total"`
}

const (
	notificationSettingsID          = "notification-settings"
	notificationDeliveryBatch       = 20
	notificationDeliveryMaxAttempts = 5
)

var ErrInvalidNotificationSettings = errors.New("invalid notification settings")

func defaultNotificationSettings() NotificationSettings {
	return NotificationSettings{}
}

func validateNotificationSettings(settings NotificationSettings) (NotificationSettings, error) {
	settings.WebhookURL = strings.TrimSpace(settings.WebhookURL)
	if len(settings.WebhookURL) > 2048 {
		return settings, fmt.Errorf("%w: webhook URL is too long", ErrInvalidNotificationSettings)
	}
	if settings.WebhookURL == "" {
		settings.WebhookEnabled = false
		return settings, nil
	}
	parsed, err := url.Parse(settings.WebhookURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || strings.ContainsAny(settings.WebhookURL, "\r\n") {
		return settings, fmt.Errorf("%w: webhook URL must be an absolute URL without credentials, query or fragment", ErrInvalidNotificationSettings)
	}
	host := parsed.Hostname()
	if host == "" {
		return settings, fmt.Errorf("%w: webhook URL host is required", ErrInvalidNotificationSettings)
	}
	if parsed.Scheme != "https" && !isLoopbackWebhookHost(host) {
		return settings, fmt.Errorf("%w: non-loopback webhook URL must use HTTPS", ErrInvalidNotificationSettings)
	}
	if parsed.Port() != "" {
		port, err := strconv.Atoi(parsed.Port())
		if err != nil || port < 1 || port > 65535 {
			return settings, fmt.Errorf("%w: webhook URL port is invalid", ErrInvalidNotificationSettings)
		}
	}
	return settings, nil
}

func isLoopbackWebhookHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func notificationSettingsIn(ctx context.Context, q productQueryer) (NotificationSettings, error) {
	settings := defaultNotificationSettings()
	var raw string
	err := q.QueryRowContext(ctx, "SELECT data FROM product_settings WHERE id=?", notificationSettingsID).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return settings, nil
	}
	if err != nil {
		return settings, err
	}
	if err := json.Unmarshal([]byte(raw), &settings); err != nil {
		return defaultNotificationSettings(), fmt.Errorf("decode notification settings: %w", err)
	}
	return validateNotificationSettings(settings)
}

func (s *RuntimeStore) GetNotificationSettings(ctx context.Context) (NotificationSettings, error) {
	return notificationSettingsIn(ctx, s.db)
}

func (s *RuntimeStore) SaveNotificationSettings(ctx context.Context, settings NotificationSettings, actor string) (NotificationSettings, error) {
	settings, err := validateNotificationSettings(settings)
	if err != nil {
		return settings, err
	}
	data, err := json.Marshal(settings)
	if err != nil {
		return settings, fmt.Errorf("encode notification settings: %w", err)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return settings, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `INSERT INTO product_settings(id,data) VALUES(?,?) ON CONFLICT(id) DO UPDATE SET data=excluded.data`, notificationSettingsID, string(data)); err != nil {
		return settings, err
	}
	if err = logLocal(ctx, tx, actor, "update_notification_settings", "settings", notificationSettingsID, ""); err != nil {
		return settings, err
	}
	if err = tx.Commit(); err != nil {
		return settings, err
	}
	return settings, nil
}

func (s *RuntimeStore) ListNotificationDeliveries(ctx context.Context, limit, offset int) (NotificationDeliveryList, error) {
	if limit < 1 || limit > 200 {
		return NotificationDeliveryList{}, fmt.Errorf("%w: invalid delivery page size", ErrInvalidNotificationSettings)
	}
	if offset < 0 || offset > 1000000 {
		return NotificationDeliveryList{}, fmt.Errorf("%w: invalid delivery offset", ErrInvalidNotificationSettings)
	}
	var result NotificationDeliveryList
	if err := s.db.QueryRowContext(ctx, "SELECT count(*) FROM notification_deliveries").Scan(&result.Total); err != nil {
		return result, fmt.Errorf("count notification deliveries: %w", err)
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id,notification_id,state,attempts,next_attempt_at,last_error,delivered_at,created_at
		FROM notification_deliveries ORDER BY created_at DESC,id DESC LIMIT ? OFFSET ?`, limit, offset)
	if err != nil {
		return result, fmt.Errorf("list notification deliveries: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var item NotificationDelivery
		if err := rows.Scan(&item.ID, &item.NotificationID, &item.State, &item.Attempts, &item.NextAttemptAt, &item.LastError, &item.DeliveredAt, &item.CreatedAt); err != nil {
			return result, fmt.Errorf("scan notification delivery: %w", err)
		}
		result.Items = append(result.Items, item)
	}
	if err := rows.Err(); err != nil {
		return result, fmt.Errorf("iterate notification deliveries: %w", err)
	}
	return result, nil
}

type notificationDeliveryCandidate struct {
	ID             string
	NotificationID string
	Attempts       int
	Title          string
	Kind           string
	Severity       string
	Message        string
	ObjectType     string
	ObjectID       string
	CreatedAt      string
}

type webhookNotification struct {
	SchemaVersion int          `json:"schemaVersion"`
	Event         string       `json:"event"`
	Notification  Notification `json:"notification"`
}

// DispatchNotificationOutbox sends a bounded batch of safe notification
// summaries. It is intentionally opt-in: an empty or disabled webhook never
// causes a network request. The caller may run it periodically from Server.
func (s *RuntimeStore) DispatchNotificationOutbox(ctx context.Context) (int, error) {
	return s.dispatchNotificationOutbox(ctx, newNotificationHTTPClient(), time.Now().UTC())
}

func (s *RuntimeStore) dispatchNotificationOutbox(ctx context.Context, client *http.Client, now time.Time) (int, error) {
	settings, err := s.GetNotificationSettings(ctx)
	if err != nil {
		return 0, fmt.Errorf("read notification settings: %w", err)
	}
	if !settings.WebhookEnabled || settings.WebhookURL == "" {
		return 0, nil
	}
	if client == nil {
		client = newNotificationHTTPClient()
	}
	// A process can stop after claiming a row but before recording the HTTP
	// result. Requeue stale claims so one interrupted Server does not leave a
	// notification permanently stuck in SENDING.
	staleBefore := now.Add(-5 * time.Minute).Format(time.RFC3339Nano)
	if _, err := s.db.ExecContext(ctx, `UPDATE notification_deliveries
		SET state='FAILED',last_error='previous delivery interrupted',next_attempt_at=?
		WHERE state='SENDING' AND next_attempt_at<?`, now.Format(time.RFC3339Nano), staleBefore); err != nil {
		return 0, fmt.Errorf("recover stale notification deliveries: %w", err)
	}
	rows, err := s.db.QueryContext(ctx, `SELECT d.id,d.notification_id,d.attempts,n.title,n.kind,n.severity,n.message,n.object_type,n.object_id,n.created_at
		FROM notification_deliveries d JOIN notifications n ON n.id=d.notification_id
		WHERE d.state IN ('PENDING','FAILED') AND d.next_attempt_at<=?
		ORDER BY d.next_attempt_at ASC,d.created_at ASC,d.id ASC LIMIT ?`, now.Format(time.RFC3339Nano), notificationDeliveryBatch)
	if err != nil {
		return 0, fmt.Errorf("list notification outbox: %w", err)
	}
	candidates := make([]notificationDeliveryCandidate, 0, notificationDeliveryBatch)
	for rows.Next() {
		var candidate notificationDeliveryCandidate
		if err := rows.Scan(&candidate.ID, &candidate.NotificationID, &candidate.Attempts, &candidate.Title, &candidate.Kind, &candidate.Severity, &candidate.Message, &candidate.ObjectType, &candidate.ObjectID, &candidate.CreatedAt); err != nil {
			rows.Close()
			return 0, fmt.Errorf("scan notification outbox: %w", err)
		}
		candidates = append(candidates, candidate)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, fmt.Errorf("iterate notification outbox: %w", err)
	}
	rows.Close()

	delivered := 0
	for _, candidate := range candidates {
		claimed, err := s.claimNotificationDelivery(ctx, candidate.ID)
		if err != nil {
			return delivered, err
		}
		if !claimed {
			continue
		}
		notification := Notification{ID: candidate.NotificationID, Kind: candidate.Kind, Severity: candidate.Severity, Title: candidate.Title, Message: candidate.Message, ObjectType: candidate.ObjectType, ObjectID: candidate.ObjectID, CreatedAt: candidate.CreatedAt}
		body, err := json.Marshal(webhookNotification{SchemaVersion: 1, Event: "notification", Notification: notification})
		if err == nil {
			err = sendNotificationWebhook(ctx, client, settings.WebhookURL, body)
		}
		if err == nil {
			if err := s.finishNotificationDelivery(ctx, candidate.ID, true, "", now); err != nil {
				return delivered, err
			}
			delivered++
			continue
		}
		attempts := candidate.Attempts + 1
		if attempts >= notificationDeliveryMaxAttempts {
			if updateErr := s.finishNotificationDelivery(ctx, candidate.ID, false, safeNotificationDeliveryError(err), now); updateErr != nil {
				return delivered, updateErr
			}
			continue
		}
		next := now.Add(notificationDeliveryBackoff(attempts))
		if updateErr := s.retryNotificationDelivery(ctx, candidate.ID, safeNotificationDeliveryError(err), next); updateErr != nil {
			return delivered, updateErr
		}
	}
	return delivered, nil
}

func newNotificationHTTPClient() *http.Client {
	return &http.Client{
		Timeout:       5 * time.Second,
		Transport:     &http.Transport{Proxy: nil},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func sendNotificationWebhook(ctx context.Context, client *http.Client, endpoint string, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return errors.New("webhook request could not be constructed")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "scanner-platform-notification/1")
	req.Header.Set("X-Scanner-Event", "notification")
	response, err := client.Do(req)
	if err != nil {
		return errors.New("webhook request failed")
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("webhook returned HTTP %d", response.StatusCode)
	}
	return nil
}

func safeNotificationDeliveryError(err error) string {
	if err == nil {
		return ""
	}
	message := strings.TrimSpace(err.Error())
	if !strings.HasPrefix(message, "webhook returned HTTP ") {
		return "webhook request failed"
	}
	if len(message) > 240 {
		message = message[:240]
	}
	return message
}

func notificationDeliveryBackoff(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	backoff := 10 * time.Second
	for i := 1; i < attempt && backoff < 5*time.Minute; i++ {
		backoff *= 2
	}
	if backoff > 5*time.Minute {
		return 5 * time.Minute
	}
	return backoff
}

func (s *RuntimeStore) claimNotificationDelivery(ctx context.Context, id string) (bool, error) {
	result, err := s.db.ExecContext(ctx, `UPDATE notification_deliveries SET state='SENDING',attempts=attempts+1 WHERE id=? AND state IN ('PENDING','FAILED')`, id)
	if err != nil {
		return false, fmt.Errorf("claim notification delivery: %w", err)
	}
	count, err := result.RowsAffected()
	return count == 1, err
}

func (s *RuntimeStore) finishNotificationDelivery(ctx context.Context, id string, delivered bool, lastError string, now time.Time) error {
	if delivered {
		_, err := s.db.ExecContext(ctx, `UPDATE notification_deliveries SET state='DELIVERED',last_error='',delivered_at=? WHERE id=? AND state='SENDING'`, now.Format(time.RFC3339Nano), id)
		return err
	}
	_, err := s.db.ExecContext(ctx, `UPDATE notification_deliveries SET state='DEAD',last_error=? WHERE id=? AND state='SENDING'`, lastError, id)
	return err
}

func (s *RuntimeStore) retryNotificationDelivery(ctx context.Context, id, lastError string, next time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE notification_deliveries SET state='FAILED',last_error=?,next_attempt_at=? WHERE id=? AND state='SENDING'`, lastError, next.Format(time.RFC3339Nano), id)
	return err
}
