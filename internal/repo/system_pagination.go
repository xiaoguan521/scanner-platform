package repo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"scanner-platform/internal/rules"
)

// NodeListQuery is the bounded Server-side local-node list contract.
type NodeListQuery struct {
	Page     int
	PageSize int
	Search   string
	Sort     string
}

type NodeListPage struct {
	Items    []LocalNode `json:"items"`
	Total    int         `json:"total"`
	Page     int         `json:"page"`
	PageSize int         `json:"pageSize"`
}

// RuleListQuery is the bounded Server-side rule-bundle list contract.
type RuleListQuery struct {
	Page     int
	PageSize int
	Search   string
	Sort     string
}

type RuleListPage struct {
	Items    []rules.Bundle `json:"items"`
	Total    int            `json:"total"`
	Page     int            `json:"page"`
	PageSize int            `json:"pageSize"`
}

const (
	DefaultSystemListPageSize = 20
	MaxSystemListPageSize     = 100
	MaxSystemListPage         = 1_000_000
)

var (
	ErrInvalidNodeListQuery = errors.New("invalid node list query")
	ErrInvalidRuleListQuery = errors.New("invalid rule list query")
)

func normalizeSystemList(page, pageSize int, search, sort string, allowed []string, invalid error) (int, int, string, error) {
	if page < 0 || pageSize < 0 || page > MaxSystemListPage || len(search) > 160 || strings.ContainsRune(search, 0) {
		return 0, 0, "", invalid
	}
	if page == 0 {
		page = 1
	}
	if pageSize > MaxSystemListPageSize {
		return 0, 0, "", invalid
	}
	if strings.HasPrefix(sort, "+") {
		sort = strings.TrimPrefix(sort, "+")
	}
	key := strings.TrimPrefix(sort, "-")
	if !oneOf(key, allowed...) {
		return 0, 0, "", invalid
	}
	if pageSize > 0 && page-1 > int(^uint(0)>>1)/pageSize {
		return 0, 0, "", invalid
	}
	return page, pageSize, sort, nil
}

func NormalizeNodeListQuery(in NodeListQuery) (NodeListQuery, error) {
	page, pageSize, sort, err := normalizeSystemList(in.Page, in.PageSize, in.Search, in.Sort, []string{"", "id", "kind", "status", "last_heartbeat"}, ErrInvalidNodeListQuery)
	if err != nil {
		return NodeListQuery{}, err
	}
	in.Page, in.PageSize, in.Sort = page, pageSize, sort
	return in, nil
}

func NormalizeRuleListQuery(in RuleListQuery) (RuleListQuery, error) {
	page, pageSize, sort, err := normalizeSystemList(in.Page, in.PageSize, in.Search, in.Sort, []string{"", "version", "channel", "published_at"}, ErrInvalidRuleListQuery)
	if err != nil {
		return RuleListQuery{}, err
	}
	in.Page, in.PageSize, in.Sort = page, pageSize, sort
	return in, nil
}

func (s *RuntimeStore) ListNodesPage(ctx context.Context, in NodeListQuery) (NodeListPage, error) {
	query, err := NormalizeNodeListQuery(in)
	if err != nil {
		return NodeListPage{}, err
	}
	where, args := nodeListWhere(query)
	var total int
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM local_nodes WHERE "+where, args...).Scan(&total); err != nil {
		return NodeListPage{}, fmt.Errorf("count nodes: %w", err)
	}
	sortColumn := "id"
	switch strings.TrimPrefix(query.Sort, "-") {
	case "kind":
		sortColumn = "COALESCE(json_extract(data,'$.kind'),'')"
	case "status":
		sortColumn = "COALESCE(json_extract(data,'$.status'),'')"
	case "last_heartbeat":
		sortColumn = "COALESCE(json_extract(data,'$.lastHeartbeat'),'')"
	}
	direction := "ASC"
	if strings.HasPrefix(query.Sort, "-") {
		direction = "DESC"
	}
	queryArgs := append([]any(nil), args...)
	statement := "SELECT data FROM local_nodes WHERE " + where + " ORDER BY " + sortColumn + " " + direction + ",id"
	if query.PageSize > 0 {
		statement += " LIMIT ? OFFSET ?"
		queryArgs = append(queryArgs, query.PageSize, (query.Page-1)*query.PageSize)
	}
	rows, err := s.db.QueryContext(ctx, statement, queryArgs...)
	if err != nil {
		return NodeListPage{}, fmt.Errorf("list nodes: %w", err)
	}
	defer rows.Close()
	items := make([]LocalNode, 0)
	for rows.Next() {
		var data string
		var node LocalNode
		if err := rows.Scan(&data); err != nil {
			return NodeListPage{}, fmt.Errorf("scan node: %w", err)
		}
		if err := unmarshalNode(data, &node); err != nil {
			return NodeListPage{}, err
		}
		items = append(items, node)
	}
	if err := rows.Err(); err != nil {
		return NodeListPage{}, fmt.Errorf("iterate nodes: %w", err)
	}
	pageSize := query.PageSize
	if pageSize == 0 {
		pageSize = len(items)
		if pageSize == 0 {
			pageSize = DefaultSystemListPageSize
		}
	}
	return NodeListPage{Items: items, Total: total, Page: query.Page, PageSize: pageSize}, nil
}

func unmarshalNode(data string, node *LocalNode) error {
	if err := json.Unmarshal([]byte(data), node); err != nil {
		return fmt.Errorf("decode node: %w", err)
	}
	if time.Since(node.LastHeartbeat) > 10*time.Second {
		node.Status = "OFFLINE"
	}
	return nil
}

func nodeListWhere(query NodeListQuery) (string, []any) {
	if query.Search == "" {
		return "1=1", nil
	}
	pattern := "%" + escapeFindingLike(query.Search) + "%"
	return `(id LIKE ? ESCAPE '\' OR COALESCE(json_extract(data,'$.kind'),'') LIKE ? ESCAPE '\' OR COALESCE(json_extract(data,'$.hostId'),'') LIKE ? ESCAPE '\')`, []any{pattern, pattern, pattern}
}

func (s *RuntimeStore) ListRulesPage(ctx context.Context, in RuleListQuery) (RuleListPage, error) {
	query, err := NormalizeRuleListQuery(in)
	if err != nil {
		return RuleListPage{}, err
	}
	where, args := ruleListWhere(query)
	var total int
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM local_rule_bundles WHERE "+where, args...).Scan(&total); err != nil {
		return RuleListPage{}, fmt.Errorf("count rule bundles: %w", err)
	}
	sortColumn := "version"
	switch strings.TrimPrefix(query.Sort, "-") {
	case "channel":
		sortColumn = "COALESCE(json_extract(data,'$.channel'),'')"
	case "published_at":
		sortColumn = "COALESCE(json_extract(data,'$.publishedAt'),'')"
	}
	direction := "DESC"
	if query.Sort != "" && !strings.HasPrefix(query.Sort, "-") {
		direction = "ASC"
	}
	queryArgs := append([]any(nil), args...)
	statement := "SELECT data FROM local_rule_bundles WHERE " + where + " ORDER BY " + sortColumn + " " + direction + ",version DESC"
	if query.PageSize > 0 {
		statement += " LIMIT ? OFFSET ?"
		queryArgs = append(queryArgs, query.PageSize, (query.Page-1)*query.PageSize)
	}
	rows, err := s.db.QueryContext(ctx, statement, queryArgs...)
	if err != nil {
		return RuleListPage{}, fmt.Errorf("list rule bundles: %w", err)
	}
	defer rows.Close()
	items := make([]rules.Bundle, 0)
	for rows.Next() {
		var data string
		var bundle rules.Bundle
		if err := rows.Scan(&data); err != nil {
			return RuleListPage{}, fmt.Errorf("scan rule bundle: %w", err)
		}
		if err := json.Unmarshal([]byte(data), &bundle); err != nil {
			return RuleListPage{}, fmt.Errorf("decode rule bundle: %w", err)
		}
		items = append(items, bundle)
	}
	if err := rows.Err(); err != nil {
		return RuleListPage{}, fmt.Errorf("iterate rule bundles: %w", err)
	}
	pageSize := query.PageSize
	if pageSize == 0 {
		pageSize = len(items)
		if pageSize == 0 {
			pageSize = DefaultSystemListPageSize
		}
	}
	return RuleListPage{Items: items, Total: total, Page: query.Page, PageSize: pageSize}, nil
}

func ruleListWhere(query RuleListQuery) (string, []any) {
	if query.Search == "" {
		return "1=1", nil
	}
	pattern := "%" + escapeFindingLike(query.Search) + "%"
	return `(version LIKE ? ESCAPE '\' OR COALESCE(json_extract(data,'$.channel'),'') LIKE ? ESCAPE '\')`, []any{pattern, pattern}
}
