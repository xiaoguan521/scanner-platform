package repo

import (
	"context"
	"fmt"
	"strings"
)

// AuditLog is the safe, queryable audit projection. Detail is intentionally
// omitted because historical audit rows may contain sensitive business data.
type AuditLog struct {
	ID         string `json:"id"`
	Actor      string `json:"actor"`
	Action     string `json:"action"`
	ObjectType string `json:"objectType"`
	ObjectID   string `json:"objectId"`
	CreatedAt  string `json:"createdAt"`
}

type AuditLogQuery struct {
	Actor      string
	Action     string
	ObjectType string
	From       string
	To         string
	Limit      int
	Offset     int
}

func (s *RuntimeStore) ListAuditLogs(ctx context.Context, query AuditLogQuery) ([]AuditLog, int, error) {
	where := []string{"1=1"}
	args := []any{}
	if query.Actor != "" {
		where = append(where, "actor=?")
		args = append(args, query.Actor)
	}
	if query.Action != "" {
		where = append(where, "action=?")
		args = append(args, query.Action)
	}
	if query.ObjectType != "" {
		where = append(where, "object_type=?")
		args = append(args, query.ObjectType)
	}
	if query.From != "" {
		where = append(where, "created_at>=?")
		args = append(args, query.From)
	}
	if query.To != "" {
		where = append(where, "created_at<=?")
		args = append(args, query.To)
	}
	condition := strings.Join(where, " AND ")
	var total int
	if err := s.db.QueryRowContext(ctx, "SELECT count(*) FROM audit_logs WHERE "+condition, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count audit logs: %w", err)
	}
	if query.Limit <= 0 {
		query.Limit = 50
	}
	if query.Offset < 0 {
		query.Offset = 0
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id,actor,action,object_type,object_id,created_at FROM audit_logs WHERE `+condition+` ORDER BY created_at DESC,id DESC LIMIT ? OFFSET ?`, append(args, query.Limit, query.Offset)...)
	if err != nil {
		return nil, 0, fmt.Errorf("list audit logs: %w", err)
	}
	defer rows.Close()
	items := make([]AuditLog, 0, query.Limit)
	for rows.Next() {
		var item AuditLog
		if err := rows.Scan(&item.ID, &item.Actor, &item.Action, &item.ObjectType, &item.ObjectID, &item.CreatedAt); err != nil {
			return nil, 0, fmt.Errorf("scan audit log: %w", err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("iterate audit logs: %w", err)
	}
	return items, total, nil
}
