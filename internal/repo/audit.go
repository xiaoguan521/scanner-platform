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

// TaskLog is a deliberately small task-history projection. It omits the
// audit detail column because that column may contain target or business data.
type TaskLog struct {
	ID        string `json:"id"`
	Actor     string `json:"actor"`
	Action    string `json:"action"`
	Message   string `json:"message"`
	CreatedAt string `json:"createdAt"`
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

// ListTaskLogs returns safe, static descriptions for audit events belonging
// to one task. The raw audit detail is never exposed through this endpoint.
func (s *RuntimeStore) ListTaskLogs(ctx context.Context, taskID string) ([]TaskLog, error) {
	if _, err := s.GetRuntimeTask(ctx, taskID); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id,actor,action,created_at
		FROM audit_logs WHERE object_type='task' AND object_id=?
		ORDER BY created_at ASC,id ASC LIMIT 100`, taskID)
	if err != nil {
		return nil, fmt.Errorf("list task logs: %w", err)
	}
	defer rows.Close()
	items := make([]TaskLog, 0, 16)
	for rows.Next() {
		var item TaskLog
		if err := rows.Scan(&item.ID, &item.Actor, &item.Action, &item.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan task log: %w", err)
		}
		item.Message = taskLogMessage(item.Action)
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate task logs: %w", err)
	}
	return items, nil
}

func taskLogMessage(action string) string {
	switch action {
	case "create_task":
		return "任务已创建"
	case "cancel_task":
		return "任务已取消"
	case "pause_task":
		return "任务已暂停"
	case "resume_task":
		return "任务已恢复到队列"
	case "archive_task":
		return "任务已归档"
	case "restore_task":
		return "任务已从归档恢复"
	case "report_engine_task":
		return "Worker 已回报执行结果"
	case "fence_drop_observed":
		return "围栏拦截了范围外连接尝试（详情已脱敏）"
	case "retest_finding":
		return "已创建漏洞复测任务"
	default:
		return "任务记录已更新"
	}
}
