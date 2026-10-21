package repo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"scanner-platform/internal/findings"
)

var ErrInvalidKnowledgeListQuery = errors.New("invalid knowledge list query")

type KnowledgeListQuery struct {
	Page     int
	PageSize int
	Search   string
}

type KnowledgeListPage struct {
	Items    []findings.KnowledgeEntry `json:"items"`
	Total    int                       `json:"total"`
	Page     int                       `json:"page"`
	PageSize int                       `json:"pageSize"`
}

const (
	defaultKnowledgePageSize = 25
	maxKnowledgePageSize     = 100
	maxKnowledgePage         = 100000
)

func normalizeKnowledgeListQuery(query KnowledgeListQuery) (int, int, int, string, error) {
	page, pageSize := query.Page, query.PageSize
	if page == 0 {
		page = 1
	}
	if pageSize == 0 {
		pageSize = defaultKnowledgePageSize
	}
	search := strings.TrimSpace(query.Search)
	if page < 1 || page > maxKnowledgePage || pageSize < 1 || pageSize > maxKnowledgePageSize || len(search) > 160 || strings.IndexByte(search, 0) >= 0 {
		return 0, 0, 0, "", ErrInvalidKnowledgeListQuery
	}
	return page, pageSize, (page - 1) * pageSize, search, nil
}

func (s *RuntimeStore) ListKnowledgePage(ctx context.Context, query KnowledgeListQuery) (KnowledgeListPage, error) {
	page, pageSize, offset, search, err := normalizeKnowledgeListQuery(query)
	if err != nil {
		return KnowledgeListPage{}, err
	}
	where := "1=1"
	args := []any{}
	if search != "" {
		where += ` AND LOWER(data) LIKE ? ESCAPE '\'`
		args = append(args, "%"+escapeKnowledgeLike(strings.ToLower(search))+"%")
	}
	var total int
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM vulnerability_knowledge WHERE "+where, args...).Scan(&total); err != nil {
		return KnowledgeListPage{}, fmt.Errorf("count knowledge: %w", err)
	}
	rows, err := s.db.QueryContext(ctx, `SELECT data FROM vulnerability_knowledge WHERE `+where+` ORDER BY id LIMIT ? OFFSET ?`, append(args, pageSize, offset)...)
	if err != nil {
		return KnowledgeListPage{}, fmt.Errorf("list knowledge page: %w", err)
	}
	defer rows.Close()
	items := make([]findings.KnowledgeEntry, 0, pageSize)
	for rows.Next() {
		var raw string
		var item findings.KnowledgeEntry
		if err := rows.Scan(&raw); err != nil {
			return KnowledgeListPage{}, fmt.Errorf("scan knowledge page: %w", err)
		}
		if err := json.Unmarshal([]byte(raw), &item); err != nil {
			return KnowledgeListPage{}, fmt.Errorf("decode knowledge page: %w", err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return KnowledgeListPage{}, fmt.Errorf("iterate knowledge page: %w", err)
	}
	return KnowledgeListPage{Items: items, Total: total, Page: page, PageSize: pageSize}, nil
}

func escapeKnowledgeLike(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, "%", `\%`)
	return strings.ReplaceAll(value, "_", `\_`)
}
