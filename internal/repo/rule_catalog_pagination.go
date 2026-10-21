package repo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"scanner-platform/internal/rules"
)

type RuleJobListQuery struct {
	Page     int
	PageSize int
	Search   string
	Status   string
	Kind     string
	Sort     string
}

type RuleJobListPage struct {
	Items    []rules.Job `json:"items"`
	Total    int         `json:"total"`
	Page     int         `json:"page"`
	PageSize int         `json:"pageSize"`
}

type CustomRuleListQuery struct {
	Page     int
	PageSize int
	Search   string
	Severity string
	Enabled  string
	Sort     string
}

type CustomRuleListPage struct {
	Items    []rules.CustomRule `json:"items"`
	Total    int                `json:"total"`
	Page     int                `json:"page"`
	PageSize int                `json:"pageSize"`
}

var (
	ErrInvalidRuleJobListQuery    = errors.New("invalid rule job list query")
	ErrInvalidCustomRuleListQuery = errors.New("invalid custom rule list query")
)

func NormalizeRuleJobListQuery(in RuleJobListQuery) (RuleJobListQuery, error) {
	page, pageSize, sort, err := normalizeSystemList(in.Page, in.PageSize, in.Search, in.Sort, []string{"", "created_at", "status", "kind", "version"}, ErrInvalidRuleJobListQuery)
	if err != nil {
		return RuleJobListQuery{}, err
	}
	if in.Status != "" && !oneOf(in.Status, "PENDING", "RUNNING", "COMPLETED", "FAILED") {
		return RuleJobListQuery{}, ErrInvalidRuleJobListQuery
	}
	if in.Kind != "" && !oneOf(in.Kind, "IMPORT", "FETCH", "ACTIVATE") {
		return RuleJobListQuery{}, ErrInvalidRuleJobListQuery
	}
	in.Page, in.PageSize, in.Sort = page, pageSize, sort
	return in, nil
}

func NormalizeCustomRuleListQuery(in CustomRuleListQuery) (CustomRuleListQuery, error) {
	page, pageSize, sort, err := normalizeSystemList(in.Page, in.PageSize, in.Search, in.Sort, []string{"", "updated_at", "name", "severity", "id"}, ErrInvalidCustomRuleListQuery)
	if err != nil {
		return CustomRuleListQuery{}, err
	}
	if in.Severity != "" && !oneOf(in.Severity, "info", "low", "medium", "high", "critical") {
		return CustomRuleListQuery{}, ErrInvalidCustomRuleListQuery
	}
	if in.Enabled != "" && !oneOf(in.Enabled, "true", "false") {
		return CustomRuleListQuery{}, ErrInvalidCustomRuleListQuery
	}
	in.Page, in.PageSize, in.Sort = page, pageSize, sort
	return in, nil
}

func (s *RuntimeStore) ListRuleJobsPage(ctx context.Context, in RuleJobListQuery) (RuleJobListPage, error) {
	query, err := NormalizeRuleJobListQuery(in)
	if err != nil {
		return RuleJobListPage{}, err
	}
	where, args := ruleJobListWhere(query)
	var total int
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM rule_jobs WHERE "+where, args...).Scan(&total); err != nil {
		return RuleJobListPage{}, fmt.Errorf("count rule jobs: %w", err)
	}
	sortColumn := "created_at"
	switch strings.TrimPrefix(query.Sort, "-") {
	case "status", "kind", "version":
		sortColumn = strings.TrimPrefix(query.Sort, "-")
		if sortColumn == "kind" {
			sortColumn = "COALESCE(json_extract(data,'$.kind'),'')"
		} else if sortColumn == "version" {
			sortColumn = "COALESCE(json_extract(data,'$.version'),'')"
		}
	}
	direction := "DESC"
	if query.Sort != "" && !strings.HasPrefix(query.Sort, "-") {
		direction = "ASC"
	}
	queryArgs := append([]any(nil), args...)
	statement := "SELECT data,status FROM rule_jobs WHERE " + where + " ORDER BY " + sortColumn + " " + direction + ",id"
	if query.PageSize > 0 {
		statement += " LIMIT ? OFFSET ?"
		queryArgs = append(queryArgs, query.PageSize, (query.Page-1)*query.PageSize)
	}
	rows, err := s.db.QueryContext(ctx, statement, queryArgs...)
	if err != nil {
		return RuleJobListPage{}, fmt.Errorf("list rule jobs: %w", err)
	}
	defer rows.Close()
	items := make([]rules.Job, 0)
	for rows.Next() {
		var data, status string
		var job rules.Job
		if err := rows.Scan(&data, &status); err != nil {
			return RuleJobListPage{}, fmt.Errorf("scan rule job: %w", err)
		}
		if err := json.Unmarshal([]byte(data), &job); err != nil {
			return RuleJobListPage{}, fmt.Errorf("decode rule job: %w", err)
		}
		job.Status = status
		items = append(items, job)
	}
	if err := rows.Err(); err != nil {
		return RuleJobListPage{}, fmt.Errorf("iterate rule jobs: %w", err)
	}
	return RuleJobListPage{Items: items, Total: total, Page: query.Page, PageSize: pageSizeOrDefault(query.PageSize, len(items))}, nil
}

func ruleJobListWhere(query RuleJobListQuery) (string, []any) {
	where := []string{"1=1"}
	args := make([]any, 0, 6)
	if query.Status != "" {
		where = append(where, "status=?")
		args = append(args, query.Status)
	}
	if query.Kind != "" {
		where = append(where, "COALESCE(json_extract(data,'$.kind'),'')=?")
		args = append(args, query.Kind)
	}
	if query.Search != "" {
		pattern := "%" + escapeFindingLike(query.Search) + "%"
		where = append(where, `(id LIKE ? ESCAPE '\' OR COALESCE(json_extract(data,'$.kind'),'') LIKE ? ESCAPE '\' OR COALESCE(json_extract(data,'$.version'),'') LIKE ? ESCAPE '\' OR COALESCE(json_extract(data,'$.message'),'') LIKE ? ESCAPE '\')`)
		args = append(args, pattern, pattern, pattern, pattern)
	}
	return strings.Join(where, " AND "), args
}

func (s *RuntimeStore) ListCustomRulesPage(ctx context.Context, in CustomRuleListQuery) (CustomRuleListPage, error) {
	query, err := NormalizeCustomRuleListQuery(in)
	if err != nil {
		return CustomRuleListPage{}, err
	}
	where, args := customRuleListWhere(query)
	var total int
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM custom_rules WHERE "+where, args...).Scan(&total); err != nil {
		return CustomRuleListPage{}, fmt.Errorf("count custom rules: %w", err)
	}
	sortColumn := "updated_at"
	switch strings.TrimPrefix(query.Sort, "-") {
	case "name":
		sortColumn = "COALESCE(json_extract(data,'$.name'),'')"
	case "severity":
		sortColumn = "COALESCE(json_extract(data,'$.severity'),'')"
	case "id":
		sortColumn = "id"
	}
	direction := "DESC"
	if query.Sort != "" && !strings.HasPrefix(query.Sort, "-") {
		direction = "ASC"
	}
	queryArgs := append([]any(nil), args...)
	statement := "SELECT data FROM custom_rules WHERE " + where + " ORDER BY " + sortColumn + " " + direction + ",id"
	if query.PageSize > 0 {
		statement += " LIMIT ? OFFSET ?"
		queryArgs = append(queryArgs, query.PageSize, (query.Page-1)*query.PageSize)
	}
	rows, err := s.db.QueryContext(ctx, statement, queryArgs...)
	if err != nil {
		return CustomRuleListPage{}, fmt.Errorf("list custom rules: %w", err)
	}
	defer rows.Close()
	items := make([]rules.CustomRule, 0)
	for rows.Next() {
		var data string
		var rule rules.CustomRule
		if err := rows.Scan(&data); err != nil {
			return CustomRuleListPage{}, fmt.Errorf("scan custom rule: %w", err)
		}
		if err := json.Unmarshal([]byte(data), &rule); err != nil {
			return CustomRuleListPage{}, fmt.Errorf("decode custom rule: %w", err)
		}
		items = append(items, rule)
	}
	if err := rows.Err(); err != nil {
		return CustomRuleListPage{}, fmt.Errorf("iterate custom rules: %w", err)
	}
	return CustomRuleListPage{Items: items, Total: total, Page: query.Page, PageSize: pageSizeOrDefault(query.PageSize, len(items))}, nil
}

func customRuleListWhere(query CustomRuleListQuery) (string, []any) {
	where := []string{"1=1"}
	args := make([]any, 0, 5)
	if query.Severity != "" {
		where = append(where, "COALESCE(json_extract(data,'$.severity'),'')=?")
		args = append(args, query.Severity)
	}
	if query.Enabled != "" {
		where = append(where, "enabled=?")
		args = append(args, query.Enabled == "true")
	}
	if query.Search != "" {
		pattern := "%" + escapeFindingLike(query.Search) + "%"
		where = append(where, `(id LIKE ? ESCAPE '\' OR COALESCE(json_extract(data,'$.name'),'') LIKE ? ESCAPE '\' OR COALESCE(json_extract(data,'$.description'),'') LIKE ? ESCAPE '\')`)
		args = append(args, pattern, pattern, pattern)
	}
	return strings.Join(where, " AND "), args
}

func pageSizeOrDefault(size, itemCount int) int {
	if size > 0 {
		return size
	}
	if itemCount > 0 {
		return itemCount
	}
	return DefaultSystemListPageSize
}
