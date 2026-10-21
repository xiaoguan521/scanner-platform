package repo

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// RefreshNotifications creates deterministic in-product notices from the
// PostgreSQL projections. It never starts a scan, contacts a target, or
// includes target addresses and engine output in a notification.
func (s *PostgresRuntimeStore) RefreshNotifications(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin postgres notification refresh: %w", err)
	}
	defer tx.Rollback()
	now := time.Now().UTC()
	if err := s.refreshPostgresScopeNotifications(ctx, tx, now); err != nil {
		return err
	}
	if err := s.refreshPostgresFindingNotifications(ctx, tx, now); err != nil {
		return err
	}
	if err := s.refreshPostgresTaskNotifications(ctx, tx, now); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit postgres notification refresh: %w", err)
	}
	return nil
}

func (s *PostgresRuntimeStore) refreshPostgresScopeNotifications(ctx context.Context, tx *sql.Tx, now time.Time) error {
	rows, err := tx.QueryContext(ctx, `SELECT id,expires_at FROM authorized_scopes
		WHERE status='APPROVED' ORDER BY id LIMIT 1000`)
	if err != nil {
		return fmt.Errorf("list postgres notification scopes: %w", err)
	}
	type scopeExpiry struct {
		id      string
		expires time.Time
	}
	items := make([]scopeExpiry, 0, 1000)
	for rows.Next() {
		var item scopeExpiry
		if err := rows.Scan(&item.id, &item.expires); err != nil {
			rows.Close()
			return fmt.Errorf("scan postgres notification scope: %w", err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("iterate postgres notification scopes: %w", err)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("close postgres notification scopes: %w", err)
	}
	for _, item := range items {
		if item.expires.After(now.Add(notificationWindow)) {
			continue
		}
		kind, title, message, severity := "scope_expiring", "授权范围即将到期", "有一条已批准授权将在七天内到期，请提前续期并重新审批。", "warning"
		if !item.expires.After(now) {
			kind, title, message, severity = "scope_expired", "授权范围已到期", "有一条已批准授权已到期，相关任务不会使用该授权执行。", "error"
		}
		if err := insertPostgresNotificationTx(ctx, tx, Notification{
			ID: "notification-" + kind + "-" + item.id, Kind: kind, Severity: severity,
			Title: title, Message: message, ObjectType: "scope", ObjectID: item.id,
		}, now); err != nil {
			return err
		}
	}
	return nil
}

func (s *PostgresRuntimeStore) refreshPostgresFindingNotifications(ctx context.Context, tx *sql.Tx, now time.Time) error {
	rows, err := tx.QueryContext(ctx, `SELECT id,accepted_until FROM security_findings
		WHERE lifecycle_status='ACCEPTED_RISK' AND accepted_until IS NOT NULL
		ORDER BY id LIMIT 5000`)
	if err != nil {
		return fmt.Errorf("list postgres notification findings: %w", err)
	}
	type findingExpiry struct {
		id      string
		expires time.Time
	}
	items := make([]findingExpiry, 0, 5000)
	for rows.Next() {
		var item findingExpiry
		if err := rows.Scan(&item.id, &item.expires); err != nil {
			rows.Close()
			return fmt.Errorf("scan postgres notification finding: %w", err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("iterate postgres notification findings: %w", err)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("close postgres notification findings: %w", err)
	}
	for _, item := range items {
		if item.expires.After(now.Add(notificationWindow)) {
			continue
		}
		kind, title, message, severity := "risk_expiring", "接受风险即将到期", "有一条接受风险记录将在七天内到期，请复核并安排修复或重新评估。", "warning"
		if !item.expires.After(now) {
			kind, title, message, severity = "risk_expired", "接受风险已到期", "有一条接受风险记录已到期，漏洞已回到待处置状态。", "error"
		}
		if err := insertPostgresNotificationTx(ctx, tx, Notification{
			ID: "notification-" + kind + "-" + item.id, Kind: kind, Severity: severity,
			Title: title, Message: message, ObjectType: "finding", ObjectID: item.id,
		}, now); err != nil {
			return err
		}
	}
	return nil
}

func (s *PostgresRuntimeStore) refreshPostgresTaskNotifications(ctx context.Context, tx *sql.Tx, now time.Time) error {
	rows, err := tx.QueryContext(ctx, `SELECT id FROM scan_tasks
		WHERE status='FAILED' ORDER BY created_at DESC,id DESC LIMIT 500`)
	if err != nil {
		return fmt.Errorf("list postgres failed tasks for notifications: %w", err)
	}
	ids := make([]string, 0, 500)
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return fmt.Errorf("scan postgres failed task notification: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("iterate postgres failed task notifications: %w", err)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("close postgres failed task notifications: %w", err)
	}
	for _, id := range ids {
		if err := insertPostgresNotificationTx(ctx, tx, Notification{
			ID: "notification-task-failed-" + id, Kind: "task_failed", Severity: "error",
			Title: "扫描任务执行失败", Message: "有一条扫描任务执行失败，请查看任务详情中的安全日志。",
			ObjectType: "task", ObjectID: id,
		}, now); err != nil {
			return err
		}
	}
	return nil
}

func insertPostgresNotificationTx(ctx context.Context, tx *sql.Tx, n Notification, createdAt time.Time) error {
	if strings.TrimSpace(n.ID) == "" || strings.TrimSpace(n.Kind) == "" || strings.TrimSpace(n.Title) == "" || strings.TrimSpace(n.Message) == "" {
		return fmt.Errorf("invalid notification")
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO notifications
		(id,kind,severity,title,message,object_type,object_id,created_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(id) DO NOTHING`,
		n.ID, n.Kind, n.Severity, n.Title, n.Message, n.ObjectType, n.ObjectID, createdAt.UTC()); err != nil {
		return fmt.Errorf("insert postgres notification: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO notification_deliveries
		(id,notification_id,state,next_attempt_at,created_at)
		VALUES ($1,$2,'PENDING',$3,$3) ON CONFLICT(notification_id) DO NOTHING`,
		"delivery-"+n.ID, n.ID, createdAt.UTC()); err != nil {
		return fmt.Errorf("insert postgres notification delivery: %w", err)
	}
	return nil
}

func postgresNotificationTime(value sql.NullTime) *string {
	if !value.Valid {
		return nil
	}
	formatted := value.Time.UTC().Format(time.RFC3339Nano)
	return &formatted
}

func scanPostgresNotification(rows *sql.Rows) (Notification, error) {
	var item Notification
	var created, readAt sql.NullTime
	if err := rows.Scan(&item.ID, &item.Kind, &item.Severity, &item.Title, &item.Message, &item.ObjectType, &item.ObjectID, &created, &readAt); err != nil {
		return item, err
	}
	if !created.Valid {
		return item, errors.New("postgres notification has no creation time")
	}
	item.CreatedAt = created.Time.UTC().Format(time.RFC3339Nano)
	item.ReadAt = postgresNotificationTime(readAt)
	return item, nil
}

func (s *PostgresRuntimeStore) ListNotifications(ctx context.Context, unreadOnly bool) (NotificationList, error) {
	if err := s.RefreshNotifications(ctx); err != nil {
		return NotificationList{}, fmt.Errorf("refresh postgres notifications: %w", err)
	}
	where := "TRUE"
	if unreadOnly {
		where = "read_at IS NULL"
	}
	var result NotificationList
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM notifications WHERE "+where).Scan(&result.Total); err != nil {
		return result, fmt.Errorf("count postgres notifications: %w", err)
	}
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM notifications WHERE read_at IS NULL").Scan(&result.UnreadCount); err != nil {
		return result, fmt.Errorf("count postgres unread notifications: %w", err)
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id,kind,severity,title,message,object_type,object_id,created_at,read_at
		FROM notifications WHERE `+where+` ORDER BY CASE WHEN read_at IS NULL THEN 0 ELSE 1 END,created_at DESC,id DESC LIMIT $1`, 200)
	if err != nil {
		return result, fmt.Errorf("list postgres notifications: %w", err)
	}
	defer rows.Close()
	result.Items = make([]Notification, 0, 200)
	for rows.Next() {
		item, err := scanPostgresNotification(rows)
		if err != nil {
			return NotificationList{}, err
		}
		result.Items = append(result.Items, item)
	}
	if err := rows.Err(); err != nil {
		return NotificationList{}, err
	}
	return result, nil
}

func (s *PostgresRuntimeStore) ListNotificationsPage(ctx context.Context, query NotificationListQuery) (NotificationListPage, error) {
	page, pageSize, offset, err := normalizeNotificationPage(query.Page, query.PageSize)
	if err != nil {
		return NotificationListPage{}, err
	}
	if err := s.RefreshNotifications(ctx); err != nil {
		return NotificationListPage{}, fmt.Errorf("refresh postgres notifications: %w", err)
	}
	where := "TRUE"
	if query.UnreadOnly {
		where = "read_at IS NULL"
	}
	var result NotificationListPage
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM notifications WHERE "+where).Scan(&result.Total); err != nil {
		return result, fmt.Errorf("count postgres notifications: %w", err)
	}
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM notifications WHERE read_at IS NULL").Scan(&result.UnreadCount); err != nil {
		return result, fmt.Errorf("count postgres unread notifications: %w", err)
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id,kind,severity,title,message,object_type,object_id,created_at,read_at
		FROM notifications WHERE `+where+` ORDER BY CASE WHEN read_at IS NULL THEN 0 ELSE 1 END,created_at DESC,id DESC LIMIT $1 OFFSET $2`, pageSize, offset)
	if err != nil {
		return result, fmt.Errorf("list postgres notifications: %w", err)
	}
	defer rows.Close()
	result.Items = make([]Notification, 0, pageSize)
	for rows.Next() {
		item, err := scanPostgresNotification(rows)
		if err != nil {
			return NotificationListPage{}, err
		}
		result.Items = append(result.Items, item)
	}
	if err := rows.Err(); err != nil {
		return NotificationListPage{}, err
	}
	result.Page, result.PageSize = page, pageSize
	return result, nil
}

func (s *PostgresRuntimeStore) MarkNotificationRead(ctx context.Context, id string) error {
	if len(strings.TrimSpace(id)) < 1 || len(id) > 256 {
		return fmt.Errorf("%w: invalid notification id", ErrInvalidTask)
	}
	result, err := s.db.ExecContext(ctx, "UPDATE notifications SET read_at=$1 WHERE id=$2 AND read_at IS NULL", time.Now().UTC(), id)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count == 0 {
		var exists int
		if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM notifications WHERE id=$1", id).Scan(&exists); err != nil {
			return err
		}
		if exists == 0 {
			return ErrNotificationNotFound
		}
	}
	return nil
}

func (s *PostgresRuntimeStore) MarkAllNotificationsRead(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, "UPDATE notifications SET read_at=$1 WHERE read_at IS NULL", time.Now().UTC())
	return err
}

func (s *PostgresRuntimeStore) GetNotificationSettings(ctx context.Context) (NotificationSettings, error) {
	settings := defaultNotificationSettings()
	var raw string
	err := s.db.QueryRowContext(ctx, "SELECT data FROM product_settings WHERE id=$1", notificationSettingsID).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return settings, nil
	}
	if err != nil {
		return settings, err
	}
	if err := json.Unmarshal([]byte(raw), &settings); err != nil {
		return defaultNotificationSettings(), fmt.Errorf("decode postgres notification settings: %w", err)
	}
	return validateNotificationSettings(settings)
}

func (s *PostgresRuntimeStore) SaveNotificationSettings(ctx context.Context, settings NotificationSettings, actor string) (NotificationSettings, error) {
	settings, err := validateNotificationSettings(settings)
	if err != nil {
		return settings, err
	}
	if strings.TrimSpace(actor) == "" {
		return settings, ErrInvalidTask
	}
	data, err := json.Marshal(settings)
	if err != nil {
		return settings, fmt.Errorf("encode postgres notification settings: %w", err)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return settings, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `INSERT INTO product_settings(id,data) VALUES($1,$2)
		ON CONFLICT(id) DO UPDATE SET data=EXCLUDED.data`, notificationSettingsID, string(data)); err != nil {
		return settings, err
	}
	if err := s.postgresAuditTx(ctx, tx, actor, "update_notification_settings", "settings", notificationSettingsID, ""); err != nil {
		return settings, err
	}
	if err := tx.Commit(); err != nil {
		return settings, err
	}
	return settings, nil
}

func (s *PostgresRuntimeStore) ListNotificationDeliveries(ctx context.Context, limit, offset int) (NotificationDeliveryList, error) {
	if limit < 1 || limit > 200 || offset < 0 || offset > 1000000 {
		return NotificationDeliveryList{}, fmt.Errorf("%w: invalid delivery page size", ErrInvalidNotificationSettings)
	}
	var result NotificationDeliveryList
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM notification_deliveries").Scan(&result.Total); err != nil {
		return result, fmt.Errorf("count postgres notification deliveries: %w", err)
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id,notification_id,state,attempts,next_attempt_at,last_error,delivered_at,created_at
		FROM notification_deliveries ORDER BY created_at DESC,id DESC LIMIT $1 OFFSET $2`, limit, offset)
	if err != nil {
		return result, fmt.Errorf("list postgres notification deliveries: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var item NotificationDelivery
		var nextAttempt, delivered, created time.Time
		var deliveredAt sql.NullTime
		if err := rows.Scan(&item.ID, &item.NotificationID, &item.State, &item.Attempts, &nextAttempt, &item.LastError, &deliveredAt, &created); err != nil {
			return result, fmt.Errorf("scan postgres notification delivery: %w", err)
		}
		item.NextAttemptAt = nextAttempt.UTC().Format(time.RFC3339Nano)
		if deliveredAt.Valid {
			delivered = deliveredAt.Time.UTC()
			formatted := delivered.Format(time.RFC3339Nano)
			item.DeliveredAt = &formatted
		}
		item.CreatedAt = created.UTC().Format(time.RFC3339Nano)
		result.Items = append(result.Items, item)
	}
	if err := rows.Err(); err != nil {
		return result, fmt.Errorf("iterate postgres notification deliveries: %w", err)
	}
	return result, nil
}

func (s *PostgresRuntimeStore) DispatchNotificationOutbox(ctx context.Context) (int, error) {
	settings, err := s.GetNotificationSettings(ctx)
	if err != nil {
		return 0, fmt.Errorf("read postgres notification settings: %w", err)
	}
	if !settings.WebhookEnabled || settings.WebhookURL == "" {
		return 0, nil
	}
	now := time.Now().UTC()
	staleBefore := now.Add(-5 * time.Minute)
	if _, err := s.db.ExecContext(ctx, `UPDATE notification_deliveries
		SET state='FAILED',last_error=$1,next_attempt_at=$2
		WHERE state='SENDING' AND next_attempt_at<$3`, "previous delivery interrupted", now, staleBefore); err != nil {
		return 0, fmt.Errorf("recover stale postgres notification deliveries: %w", err)
	}
	rows, err := s.db.QueryContext(ctx, `SELECT d.id,d.notification_id,d.attempts,n.title,n.kind,n.severity,n.message,n.object_type,n.object_id,n.created_at
		FROM notification_deliveries d JOIN notifications n ON n.id=d.notification_id
		WHERE d.state IN ('PENDING','FAILED') AND d.next_attempt_at<=$1
		ORDER BY d.next_attempt_at ASC,d.created_at ASC,d.id ASC LIMIT $2`, now, notificationDeliveryBatch)
	if err != nil {
		return 0, fmt.Errorf("list postgres notification outbox: %w", err)
	}
	type candidate struct {
		id, notificationID   string
		attempts             int
		title, kind          string
		severity, message    string
		objectType, objectID string
		createdAt            string
	}
	candidates := make([]candidate, 0, notificationDeliveryBatch)
	for rows.Next() {
		var item candidate
		var created time.Time
		if err := rows.Scan(&item.id, &item.notificationID, &item.attempts, &item.title, &item.kind, &item.severity, &item.message, &item.objectType, &item.objectID, &created); err != nil {
			rows.Close()
			return 0, fmt.Errorf("scan postgres notification outbox: %w", err)
		}
		item.createdAt = created.UTC().Format(time.RFC3339Nano)
		candidates = append(candidates, item)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, fmt.Errorf("iterate postgres notification outbox: %w", err)
	}
	if err := rows.Close(); err != nil {
		return 0, err
	}

	delivered := 0
	client := newNotificationHTTPClient()
	for _, item := range candidates {
		claimed, err := s.claimPostgresNotificationDelivery(ctx, item.id)
		if err != nil {
			return delivered, err
		}
		if !claimed {
			continue
		}
		notification := Notification{ID: item.notificationID, Kind: item.kind, Severity: item.severity, Title: item.title, Message: item.message, ObjectType: item.objectType, ObjectID: item.objectID, CreatedAt: item.createdAt}
		body, sendErr := json.Marshal(webhookNotification{SchemaVersion: 1, Event: "notification", Notification: notification})
		if sendErr == nil {
			sendErr = sendNotificationWebhook(ctx, client, settings.WebhookURL, body)
		}
		if sendErr == nil {
			if err := s.finishPostgresNotificationDelivery(ctx, item.id, true, "", now); err != nil {
				return delivered, err
			}
			delivered++
			continue
		}
		attempts := item.attempts + 1
		if attempts >= notificationDeliveryMaxAttempts {
			if err := s.finishPostgresNotificationDelivery(ctx, item.id, false, safeNotificationDeliveryError(sendErr), now); err != nil {
				return delivered, err
			}
			continue
		}
		if err := s.retryPostgresNotificationDelivery(ctx, item.id, safeNotificationDeliveryError(sendErr), now.Add(notificationDeliveryBackoff(attempts))); err != nil {
			return delivered, err
		}
	}
	return delivered, nil
}

func (s *PostgresRuntimeStore) claimPostgresNotificationDelivery(ctx context.Context, id string) (bool, error) {
	result, err := s.db.ExecContext(ctx, `UPDATE notification_deliveries
		SET state='SENDING',attempts=attempts+1 WHERE id=$1 AND state IN ('PENDING','FAILED')`, id)
	if err != nil {
		return false, fmt.Errorf("claim postgres notification delivery: %w", err)
	}
	count, err := result.RowsAffected()
	return count == 1, err
}

func (s *PostgresRuntimeStore) finishPostgresNotificationDelivery(ctx context.Context, id string, delivered bool, lastError string, now time.Time) error {
	if delivered {
		_, err := s.db.ExecContext(ctx, `UPDATE notification_deliveries
			SET state='DELIVERED',last_error='',delivered_at=$1 WHERE id=$2 AND state='SENDING'`, now, id)
		return err
	}
	_, err := s.db.ExecContext(ctx, `UPDATE notification_deliveries
		SET state='DEAD',last_error=$1 WHERE id=$2 AND state='SENDING'`, lastError, id)
	return err
}

func (s *PostgresRuntimeStore) retryPostgresNotificationDelivery(ctx context.Context, id, lastError string, next time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE notification_deliveries
		SET state='FAILED',last_error=$1,next_attempt_at=$2 WHERE id=$3 AND state='SENDING'`, lastError, next, id)
	return err
}
