package repo

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"scanner-platform/internal/taskflow"
)

// TaskListQuery is the bounded Server-side task list contract. PageSize=0 is
// reserved for internal callers that still need the complete historical list.
// TaskStatusQueued groups the statuses of tasks that are waiting to run, so
// the UI's "待执行" count can be used as a filter.
const TaskStatusQueued = "QUEUED"

func taskStatusSet(status string) []string {
	if status == TaskStatusQueued {
		return []string{"PENDING", "WAITING_WINDOW", "PAUSED_WINDOW"}
	}
	return []string{status}
}

type TaskListQuery struct {
	Page     int
	PageSize int
	Search   string
	Status   string
	Engine   string
	Archived string
	Sort     string
}

type TaskListPage struct {
	Items        []taskflow.Task `json:"items"`
	Total        int             `json:"total"`
	Page         int             `json:"page"`
	PageSize     int             `json:"pageSize"`
	StatusCounts map[string]int  `json:"statusCounts"`
}

const (
	DefaultTaskPageSize = 20
	MaxTaskPageSize     = 100
	MaxTaskPage         = 1_000_000
)

var ErrInvalidTaskListQuery = errors.New("invalid task list query")

func NormalizeTaskListQuery(in TaskListQuery) (TaskListQuery, error) {
	if in.Page < 0 || in.PageSize < 0 || in.Page > MaxTaskPage || len(in.Search) > 160 || strings.ContainsRune(in.Search, 0) {
		return TaskListQuery{}, ErrInvalidTaskListQuery
	}
	if in.Page == 0 {
		in.Page = 1
	}
	if in.PageSize > MaxTaskPageSize {
		return TaskListQuery{}, ErrInvalidTaskListQuery
	}
	switch in.Archived {
	case "", "true", "false", "all":
	default:
		return TaskListQuery{}, ErrInvalidTaskListQuery
	}
	switch in.Status {
	case "", "PENDING", "WAITING_WINDOW", "RUNNING", "PAUSED", "PAUSED_WINDOW", "COMPLETED", "FAILED", "CANCELED", TaskStatusQueued:
	default:
		return TaskListQuery{}, ErrInvalidTaskListQuery
	}
	switch in.Engine {
	case "", "auto", "port-probe", "nuclei", "trivy", "zap", "synthetic":
	default:
		return TaskListQuery{}, ErrInvalidTaskListQuery
	}
	if strings.HasPrefix(in.Sort, "+") {
		in.Sort = strings.TrimPrefix(in.Sort, "+")
	}
	sortKey := strings.TrimPrefix(in.Sort, "-")
	switch sortKey {
	case "", "created_at", "status", "engine":
	default:
		return TaskListQuery{}, ErrInvalidTaskListQuery
	}
	if in.PageSize > 0 && in.Page-1 > int(^uint(0)>>1)/in.PageSize {
		return TaskListQuery{}, ErrInvalidTaskListQuery
	}
	return in, nil
}

func (s *RuntimeStore) ListRuntimeTasksPage(ctx context.Context, in TaskListQuery) (TaskListPage, error) {
	query, err := NormalizeTaskListQuery(in)
	if err != nil {
		return TaskListPage{}, err
	}
	items, total, err := s.listRuntimeTaskRows(ctx, query)
	if err != nil {
		return TaskListPage{}, err
	}
	if err := s.attachRuntimeTaskPageMetadata(ctx, items); err != nil {
		return TaskListPage{}, err
	}
	statusCounts, err := s.runtimeTaskStatusCounts(ctx, query)
	if err != nil {
		return TaskListPage{}, err
	}
	pageSize := query.PageSize
	if pageSize == 0 {
		pageSize = len(items)
		if pageSize == 0 {
			pageSize = DefaultTaskPageSize
		}
	}
	return TaskListPage{Items: items, Total: total, Page: query.Page, PageSize: pageSize, StatusCounts: statusCounts}, nil
}

func (s *RuntimeStore) listRuntimeTaskRows(ctx context.Context, query TaskListQuery) ([]taskflow.Task, int, error) {
	where, args := taskListWhere(query, true)
	countRow := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM scan_tasks WHERE "+where, args...)
	var total int
	if err := countRow.Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count tasks: %w", err)
	}
	sortColumn := "created_at"
	sortKey := strings.TrimPrefix(query.Sort, "-")
	switch sortKey {
	case "status":
		sortColumn = "status"
	case "engine":
		sortColumn = "COALESCE(json_extract(details,'$.input.engine'),CASE WHEN COALESCE(json_extract(details,'$.input.synthetic'),0)=1 OR details='{}' THEN 'synthetic' ELSE '' END)"
	}
	direction := "ASC"
	if strings.HasPrefix(query.Sort, "-") || query.Sort == "" {
		direction = "DESC"
	}
	sqlQuery := "SELECT " + taskColumns + " FROM scan_tasks WHERE " + where + " ORDER BY " + sortColumn + " " + direction + ",id ASC"
	queryArgs := append([]any(nil), args...)
	if query.PageSize > 0 {
		sqlQuery += " LIMIT ? OFFSET ?"
		queryArgs = append(queryArgs, query.PageSize, (query.Page-1)*query.PageSize)
	}
	rows, err := s.db.QueryContext(ctx, sqlQuery, queryArgs...)
	if err != nil {
		return nil, 0, fmt.Errorf("list tasks: %w", err)
	}
	defer rows.Close()
	items := make([]taskflow.Task, 0)
	for rows.Next() {
		item, err := readRuntimeTask(rows)
		if err != nil {
			return nil, 0, err
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	return items, total, nil
}

func (s *RuntimeStore) runtimeTaskStatusCounts(ctx context.Context, query TaskListQuery) (map[string]int, error) {
	statusQuery := query
	statusQuery.Status = ""
	where, args := taskListWhere(statusQuery, false)
	rows, err := s.db.QueryContext(ctx, "SELECT status,COUNT(*) FROM scan_tasks WHERE "+where+" GROUP BY status", args...)
	if err != nil {
		return nil, fmt.Errorf("count task statuses: %w", err)
	}
	defer rows.Close()
	counts := map[string]int{}
	for rows.Next() {
		var status string
		var count int
		if err := rows.Scan(&status, &count); err != nil {
			return nil, fmt.Errorf("read task status count: %w", err)
		}
		counts[status] = count
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return counts, nil
}

func taskListWhere(query TaskListQuery, includeStatus bool) (string, []any) {
	where := []string{"1=1"}
	args := make([]any, 0, 8)
	switch query.Archived {
	case "true":
		where = append(where, "COALESCE(json_extract(details,'$.archived'),0)=1")
	case "false":
		where = append(where, "COALESCE(json_extract(details,'$.archived'),0)=0")
	}
	if includeStatus && query.Status != "" {
		statuses := taskStatusSet(query.Status)
		if len(statuses) == 1 {
			where = append(where, "status=?")
		} else {
			where = append(where, "status IN ("+strings.TrimSuffix(strings.Repeat("?,", len(statuses)), ",")+")")
		}
		for _, status := range statuses {
			args = append(args, status)
		}
	}
	if query.Engine != "" {
		if query.Engine == "synthetic" {
			where = append(where, "(COALESCE(json_extract(details,'$.input.engine'),'synthetic')='synthetic' OR COALESCE(json_extract(details,'$.input.synthetic'),0)=1)")
		} else {
			where = append(where, "json_extract(details,'$.input.engine')=?")
			args = append(args, query.Engine)
		}
	}
	if query.Search != "" {
		pattern := "%" + escapeTaskLike(query.Search) + "%"
		where = append(where, `(id LIKE ? ESCAPE '\' OR targets LIKE ? ESCAPE '\' OR COALESCE(json_extract(details,'$.input.inputPath'),'') LIKE ? ESCAPE '\')`)
		args = append(args, pattern, pattern, pattern)
	}
	return strings.Join(where, " AND "), args
}

func escapeTaskLike(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, `%`, `\%`)
	return strings.ReplaceAll(value, `_`, `\_`)
}

func (s *RuntimeStore) attachRuntimeTaskPageMetadata(ctx context.Context, items []taskflow.Task) error {
	if len(items) == 0 {
		return nil
	}
	ids := make([]any, len(items))
	placeholders := make([]string, len(items))
	for index := range items {
		ids[index] = items[index].ID
		placeholders[index] = "?"
	}
	countsRows, err := s.db.QueryContext(ctx, `SELECT task_id,COUNT(*) FROM (
		SELECT task_id,finding_id FROM task_finding_observations
		UNION
		SELECT task_id,id FROM security_findings
	) WHERE task_id IN (`+strings.Join(placeholders, ",")+") GROUP BY task_id", ids...)
	if err != nil {
		return fmt.Errorf("count paged task findings: %w", err)
	}
	counts := map[string]int{}
	for countsRows.Next() {
		var taskID string
		var count int
		if err := countsRows.Scan(&taskID, &count); err != nil {
			countsRows.Close()
			return err
		}
		counts[taskID] = count
	}
	if err := countsRows.Err(); err != nil {
		countsRows.Close()
		return err
	}
	countsRows.Close()
	progressQuery := `SELECT task_id,phase,completed,total,updated_at,history FROM scan_task_progress WHERE task_id IN (` + strings.Join(placeholders, ",") + `)`
	progressRows, err := s.db.QueryContext(ctx, progressQuery, ids...)
	if err != nil {
		return fmt.Errorf("list paged task progress: %w", err)
	}
	progress := map[string]taskflow.TaskProgress{}
	for progressRows.Next() {
		var taskID, phase, updatedAt, history string
		var completed, total int
		if err := progressRows.Scan(&taskID, &phase, &completed, &total, &updatedAt, &history); err != nil {
			progressRows.Close()
			return err
		}
		updated, err := time.Parse(time.RFC3339Nano, updatedAt)
		if err != nil {
			progressRows.Close()
			return fmt.Errorf("parse task progress time: %w", err)
		}
		progress[taskID] = taskflow.TaskProgress{Phase: phase, Completed: completed, Total: total, UpdatedAt: updated, Phases: decodePhaseHistory(history)}
	}
	if err := progressRows.Err(); err != nil {
		progressRows.Close()
		return err
	}
	progressRows.Close()
	for index := range items {
		items[index].FindingCount = counts[items[index].ID]
		if current, ok := progress[items[index].ID]; ok {
			items[index].Progress = &current
		}
	}
	return nil
}
