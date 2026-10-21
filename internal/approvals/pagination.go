package approvals

import (
	"context"
	"fmt"
	"strings"
	"time"
)

const (
	defaultApprovalPageSize = 25
	maxApprovalPageSize     = 100
	maxApprovalPage         = 100000
	maxApprovalSearch       = 160
)

// ScopeListQuery is the bounded Server-side list contract for authorization
// records. The legacy ListScopes method remains available for callers that do
// not send list parameters.
type ScopeListQuery struct {
	Page     int
	PageSize int
	Expiry   string
}

type ScopeListPage struct {
	Items         []Scope
	Total         int
	Page          int
	PageSize      int
	ExpiringCount int
	ExpiredCount  int
}

type ScopePageRepository interface {
	ListScopesPage(context.Context, ScopeListQuery) (ScopeListPage, error)
}

// PortRequestListQuery is the bounded Server-side list contract for explicit
// port approval records. Search is limited to the registered asset address or
// opaque asset ID; approval notes and other audit fields are not searchable.
type PortRequestListQuery struct {
	Page     int
	PageSize int
	Status   string
	Search   string
}

type PortRequestListPage struct {
	Items    []PortRequest
	Total    int
	Page     int
	PageSize int
}

type PortRequestPageRepository interface {
	ListPortRequestsPage(context.Context, PortRequestListQuery) (PortRequestListPage, error)
}

func normalizeApprovalPage(page, pageSize int) (int, int, int, error) {
	if page == 0 {
		page = 1
	}
	if pageSize == 0 {
		pageSize = defaultApprovalPageSize
	}
	if page < 1 || page > maxApprovalPage || pageSize < 1 || pageSize > maxApprovalPageSize {
		return 0, 0, 0, ErrInvalid
	}
	return page, pageSize, (page - 1) * pageSize, nil
}

func normalizeScopeListQuery(query ScopeListQuery) (ScopeListQuery, int, error) {
	page, pageSize, offset, err := normalizeApprovalPage(query.Page, query.PageSize)
	if err != nil {
		return ScopeListQuery{}, 0, err
	}
	query.Page, query.PageSize = page, pageSize
	query.Expiry = strings.ToLower(strings.TrimSpace(query.Expiry))
	if query.Expiry == "" {
		query.Expiry = "all"
	}
	switch query.Expiry {
	case "all", "expiring", "expired":
	default:
		return ScopeListQuery{}, 0, ErrInvalid
	}
	return query, offset, nil
}

func (s *Store) ListScopesPage(ctx context.Context, query ScopeListQuery) (ScopeListPage, error) {
	query, offset, err := normalizeScopeListQuery(query)
	if err != nil {
		return ScopeListPage{}, err
	}
	now := time.Now().UTC()
	nowText := now.Format(time.RFC3339)
	warningText := now.Add(scopeExpiryWarning).Format(time.RFC3339)
	where, args := scopeExpiryWhere(query.Expiry, nowText, warningText)

	var total int
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM authorized_scopes"+where, args...).Scan(&total); err != nil {
		return ScopeListPage{}, fmt.Errorf("count scopes page: %w", err)
	}
	var expiringCount, expiredCount int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM authorized_scopes
WHERE status='APPROVED' AND expires_at > ? AND expires_at <= ?`, nowText, warningText).Scan(&expiringCount); err != nil {
		return ScopeListPage{}, fmt.Errorf("count expiring scopes: %w", err)
	}
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM authorized_scopes
WHERE status='APPROVED' AND expires_at <= ?`, nowText).Scan(&expiredCount); err != nil {
		return ScopeListPage{}, fmt.Errorf("count expired scopes: %w", err)
	}

	rows, err := s.db.QueryContext(ctx, "SELECT "+scopeFields+" FROM authorized_scopes"+where+" ORDER BY created_at DESC,id LIMIT ? OFFSET ?", append(args, query.PageSize, offset)...)
	if err != nil {
		return ScopeListPage{}, fmt.Errorf("list scopes page: %w", err)
	}
	defer rows.Close()
	items := make([]Scope, 0, query.PageSize)
	for rows.Next() {
		item, err := readScope(rows)
		if err != nil {
			return ScopeListPage{}, fmt.Errorf("decode scope page: %w", err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return ScopeListPage{}, fmt.Errorf("list scopes page rows: %w", err)
	}
	return ScopeListPage{Items: items, Total: total, Page: query.Page, PageSize: query.PageSize,
		ExpiringCount: expiringCount, ExpiredCount: expiredCount}, nil
}

func scopeExpiryWhere(expiry, nowText, warningText string) (string, []any) {
	switch expiry {
	case "expiring":
		return " WHERE status='APPROVED' AND expires_at > ? AND expires_at <= ?", []any{nowText, warningText}
	case "expired":
		return " WHERE status='APPROVED' AND expires_at <= ?", []any{nowText}
	default:
		return "", nil
	}
}

func normalizePortRequestListQuery(query PortRequestListQuery) (PortRequestListQuery, int, error) {
	page, pageSize, offset, err := normalizeApprovalPage(query.Page, query.PageSize)
	if err != nil {
		return PortRequestListQuery{}, 0, err
	}
	query.Page, query.PageSize = page, pageSize
	query.Status = strings.ToUpper(strings.TrimSpace(query.Status))
	if query.Status == "" {
		query.Status = "ALL"
	}
	switch query.Status {
	case "ALL", "PENDING", "APPROVED", "REJECTED":
	default:
		return PortRequestListQuery{}, 0, ErrInvalid
	}
	query.Search = strings.TrimSpace(query.Search)
	if len(query.Search) > maxApprovalSearch || strings.IndexByte(query.Search, 0) >= 0 {
		return PortRequestListQuery{}, 0, ErrInvalid
	}
	return query, offset, nil
}

func (s *Store) ListPortRequestsPage(ctx context.Context, query PortRequestListQuery) (PortRequestListPage, error) {
	query, offset, err := normalizePortRequestListQuery(query)
	if err != nil {
		return PortRequestListPage{}, err
	}
	where, args := portRequestWhere(query)
	var total int
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) "+portListFrom+where, args...).Scan(&total); err != nil {
		return PortRequestListPage{}, fmt.Errorf("count port requests page: %w", err)
	}
	rows, err := s.db.QueryContext(ctx, portListQuery+where+" ORDER BY a.address,r.port LIMIT ? OFFSET ?", append(args, query.PageSize, offset)...)
	if err != nil {
		return PortRequestListPage{}, fmt.Errorf("list port requests page: %w", err)
	}
	defer rows.Close()
	items := make([]PortRequest, 0, query.PageSize)
	for rows.Next() {
		item, err := readPort(rows)
		if err != nil {
			return PortRequestListPage{}, fmt.Errorf("decode port request page: %w", err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return PortRequestListPage{}, fmt.Errorf("list port request page rows: %w", err)
	}
	return PortRequestListPage{Items: items, Total: total, Page: query.Page, PageSize: query.PageSize}, nil
}

func portRequestWhere(query PortRequestListQuery) (string, []any) {
	clauses := make([]string, 0, 2)
	args := make([]any, 0, 3)
	if query.Status != "ALL" {
		clauses = append(clauses, "COALESCE(v.status,'PENDING')=?")
		args = append(args, query.Status)
	}
	if query.Search != "" {
		pattern := "%" + escapeApprovalLike(strings.ToLower(query.Search)) + "%"
		clauses = append(clauses, "(LOWER(a.address) LIKE ? ESCAPE '\\' OR LOWER(r.asset_id) LIKE ? ESCAPE '\\')")
		args = append(args, pattern, pattern)
	}
	if len(clauses) == 0 {
		return "", args
	}
	return " WHERE " + strings.Join(clauses, " AND "), args
}

func escapeApprovalLike(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, "%", `\%`)
	return strings.ReplaceAll(value, "_", `\_`)
}
