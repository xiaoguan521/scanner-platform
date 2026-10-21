package repo

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"scanner-platform/internal/taskflow"
)

var ErrNotificationNotFound = errors.New("notification not found")

// Notification is an in-product, read-only signal. It deliberately contains
// no target address, credentials, request/response evidence, or engine output.
type Notification struct {
	ID         string  `json:"id"`
	Kind       string  `json:"kind"`
	Severity   string  `json:"severity"`
	Title      string  `json:"title"`
	Message    string  `json:"message"`
	ObjectType string  `json:"objectType"`
	ObjectID   string  `json:"objectId"`
	CreatedAt  string  `json:"createdAt"`
	ReadAt     *string `json:"readAt,omitempty"`
}

type NotificationList struct {
	Items       []Notification `json:"items"`
	Total       int            `json:"total"`
	UnreadCount int            `json:"unreadCount"`
}

const notificationWindow = 7 * 24 * time.Hour

func notificationTableExists(ctx context.Context, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}) (bool, error) {
	var count int
	if err := q.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='authorized_scopes'").Scan(&count); err != nil {
		return false, err
	}
	return count == 1, nil
}

func insertNotification(ctx context.Context, tx *sql.Tx, n Notification) error {
	if strings.TrimSpace(n.ID) == "" || strings.TrimSpace(n.Kind) == "" || strings.TrimSpace(n.Title) == "" || strings.TrimSpace(n.Message) == "" {
		return fmt.Errorf("invalid notification")
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO notifications
		(id,kind,severity,title,message,object_type,object_id,created_at)
		VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(id) DO NOTHING`,
		n.ID, n.Kind, n.Severity, n.Title, n.Message, n.ObjectType, n.ObjectID, n.CreatedAt)
	return err
}

// RefreshNotifications creates deterministic in-product notices from current
// persisted state. Re-running it is idempotent and never starts a scan or
// contacts a target.
func (s *RuntimeStore) RefreshNotifications(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := time.Now().UTC()
	created := now.Format(time.RFC3339Nano)

	if hasScopes, err := notificationTableExists(ctx, tx); err != nil {
		return err
	} else if hasScopes {
		rows, err := tx.QueryContext(ctx, `SELECT id,expires_at FROM authorized_scopes WHERE status='APPROVED' ORDER BY id LIMIT 1000`)
		if err != nil {
			return err
		}
		for rows.Next() {
			var id, rawExpiry string
			if err := rows.Scan(&id, &rawExpiry); err != nil {
				rows.Close()
				return err
			}
			expires, err := time.Parse(time.RFC3339, rawExpiry)
			if err != nil || expires.After(now.Add(notificationWindow)) {
				continue
			}
			kind, title, message, severity := "scope_expiring", "授权范围即将到期", "有一条已批准授权将在七天内到期，请提前续期并重新审批。", "warning"
			if !expires.After(now) {
				kind, title, message, severity = "scope_expired", "授权范围已到期", "有一条已批准授权已到期，相关任务不会使用该授权执行。", "error"
			}
			if err := insertNotification(ctx, tx, Notification{ID: "notification-" + kind + "-" + id, Kind: kind, Severity: severity, Title: title, Message: message, ObjectType: "scope", ObjectID: id, CreatedAt: created}); err != nil {
				rows.Close()
				return err
			}
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return err
		}
		rows.Close()
	}

	rows, err := tx.QueryContext(ctx, `SELECT id,data FROM security_findings ORDER BY id LIMIT 5000`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var id, raw string
		if err := rows.Scan(&id, &raw); err != nil {
			rows.Close()
			return err
		}
		var finding taskflow.Finding
		if err := json.Unmarshal([]byte(raw), &finding); err != nil || finding.Status != "ACCEPTED_RISK" || finding.AcceptedUntil == nil {
			continue
		}
		if finding.AcceptedUntil.After(now.Add(notificationWindow)) {
			continue
		}
		kind, title, message, severity := "risk_expiring", "接受风险即将到期", "有一条接受风险记录将在七天内到期，请复核并安排修复或重新评估。", "warning"
		if !finding.AcceptedUntil.After(now) {
			kind, title, message, severity = "risk_expired", "接受风险已到期", "有一条接受风险记录已到期，漏洞已回到待处置状态。", "error"
		}
		if err := insertNotification(ctx, tx, Notification{ID: "notification-" + kind + "-" + id, Kind: kind, Severity: severity, Title: title, Message: message, ObjectType: "finding", ObjectID: id, CreatedAt: created}); err != nil {
			rows.Close()
			return err
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()

	rows, err = tx.QueryContext(ctx, `SELECT id FROM scan_tasks WHERE status='FAILED' ORDER BY created_at DESC,id DESC LIMIT 500`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		if err := insertNotification(ctx, tx, Notification{ID: "notification-task-failed-" + id, Kind: "task_failed", Severity: "error", Title: "扫描任务执行失败", Message: "有一条扫描任务执行失败，请查看任务详情中的安全日志。", ObjectType: "task", ObjectID: id, CreatedAt: created}); err != nil {
			rows.Close()
			return err
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()

	return tx.Commit()
}

func (s *RuntimeStore) ListNotifications(ctx context.Context, unreadOnly bool) (NotificationList, error) {
	if err := s.RefreshNotifications(ctx); err != nil {
		return NotificationList{}, fmt.Errorf("refresh notifications: %w", err)
	}
	where := "1=1"
	if unreadOnly {
		where = "read_at IS NULL"
	}
	var result NotificationList
	if err := s.db.QueryRowContext(ctx, "SELECT count(*) FROM notifications WHERE "+where).Scan(&result.Total); err != nil {
		return result, err
	}
	if err := s.db.QueryRowContext(ctx, "SELECT count(*) FROM notifications WHERE read_at IS NULL").Scan(&result.UnreadCount); err != nil {
		return result, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id,kind,severity,title,message,object_type,object_id,created_at,read_at
		FROM notifications WHERE `+where+` ORDER BY CASE WHEN read_at IS NULL THEN 0 ELSE 1 END,created_at DESC,id DESC LIMIT 200`)
	if err != nil {
		return result, err
	}
	defer rows.Close()
	for rows.Next() {
		var item Notification
		if err := rows.Scan(&item.ID, &item.Kind, &item.Severity, &item.Title, &item.Message, &item.ObjectType, &item.ObjectID, &item.CreatedAt, &item.ReadAt); err != nil {
			return result, err
		}
		result.Items = append(result.Items, item)
	}
	return result, rows.Err()
}

func (s *RuntimeStore) MarkNotificationRead(ctx context.Context, id string) error {
	if len(strings.TrimSpace(id)) < 1 || len(id) > 256 {
		return fmt.Errorf("%w: invalid notification id", ErrInvalidTask)
	}
	result, err := s.db.ExecContext(ctx, "UPDATE notifications SET read_at=? WHERE id=? AND read_at IS NULL", time.Now().UTC().Format(time.RFC3339Nano), id)
	if err != nil {
		return err
	}
	if count, _ := result.RowsAffected(); count == 0 {
		var exists int
		if err := s.db.QueryRowContext(ctx, "SELECT count(*) FROM notifications WHERE id=?", id).Scan(&exists); err != nil {
			return err
		}
		if exists == 0 {
			return ErrNotificationNotFound
		}
	}
	return nil
}

func (s *RuntimeStore) MarkAllNotificationsRead(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, "UPDATE notifications SET read_at=? WHERE read_at IS NULL", time.Now().UTC().Format(time.RFC3339Nano))
	return err
}
