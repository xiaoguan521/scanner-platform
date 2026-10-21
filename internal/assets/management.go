package assets

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// BusinessGroup is the stable, non-sensitive summary used by the asset
// management UI. It deliberately contains no asset addresses or scan data.
type BusinessGroup struct {
	Name       string `json:"name"`
	AssetCount int    `json:"assetCount"`
	CreatedAt  string `json:"createdAt"`
}

// ImportHistory is an audit-safe summary of a completed CSV import. Raw CSV
// rows are never retained in this resource.
type ImportHistory struct {
	ID        string `json:"id"`
	Actor     string `json:"actor"`
	Imported  int    `json:"imported"`
	Total     int    `json:"total"`
	CreatedAt string `json:"createdAt"`
}

var (
	ErrBusinessGroupInvalid = errors.New("invalid business group")
	ErrBusinessGroupExists  = errors.New("business group already exists")
)

type BusinessGroupRepository interface {
	ListBusinessGroups(context.Context) ([]BusinessGroup, error)
	CreateBusinessGroup(context.Context, string, string) (BusinessGroup, error)
}

type ImportHistoryRepository interface {
	ListImportHistory(context.Context) ([]ImportHistory, error)
}

// BusinessGroupListQuery and ImportHistoryListQuery are the bounded list
// contracts used by the Server UI. The legacy list methods remain available
// for older callers that do not send pagination parameters.
type BusinessGroupListQuery struct {
	Page     int
	PageSize int
	Search   string
}

type BusinessGroupListPage struct {
	Items    []BusinessGroup
	Total    int
	Page     int
	PageSize int
}

type ImportHistoryListQuery struct {
	Page     int
	PageSize int
	Search   string
}

type ImportHistoryListPage struct {
	Items    []ImportHistory
	Total    int
	Page     int
	PageSize int
}

type BusinessGroupPageRepository interface {
	ListBusinessGroupsPage(context.Context, BusinessGroupListQuery) (BusinessGroupListPage, error)
}

type ImportHistoryPageRepository interface {
	ListImportHistoryPage(context.Context, ImportHistoryListQuery) (ImportHistoryListPage, error)
}

func normalizeBusinessGroup(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 100 || !utf8.ValidString(name) || strings.ContainsFunc(name, unicode.IsControl) {
		return "", ErrBusinessGroupInvalid
	}
	return name, nil
}

func ensureBusinessGroupTx(ctx context.Context, tx *sql.Tx, actor, name, createdAt string) error {
	name, err := normalizeBusinessGroup(name)
	if err != nil {
		return err
	}
	groupID, err := newID()
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO asset_business_groups(id,name,created_by,created_at)
VALUES(?,?,?,?) ON CONFLICT(name) DO NOTHING`, groupID, name, actor, createdAt)
	return err
}

func (s *Store) ListBusinessGroups(ctx context.Context) ([]BusinessGroup, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT g.name,COUNT(a.id),g.created_at
FROM asset_business_groups g LEFT JOIN assets a ON a.business_group=g.name
GROUP BY g.name,g.created_at ORDER BY LOWER(g.name),g.name`)
	if err != nil {
		return nil, fmt.Errorf("list business groups: %w", err)
	}
	defer rows.Close()
	groups := make([]BusinessGroup, 0)
	for rows.Next() {
		var group BusinessGroup
		if err := rows.Scan(&group.Name, &group.AssetCount, &group.CreatedAt); err != nil {
			return nil, fmt.Errorf("decode business group: %w", err)
		}
		groups = append(groups, group)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list business groups rows: %w", err)
	}
	return groups, nil
}

func (s *Store) ListBusinessGroupsPage(ctx context.Context, query BusinessGroupListQuery) (BusinessGroupListPage, error) {
	page, pageSize, offset, search, err := normalizeManagementPage(query.Page, query.PageSize, query.Search)
	if err != nil {
		return BusinessGroupListPage{}, err
	}
	where := "1=1"
	args := []any{}
	if search != "" {
		where += ` AND LOWER(g.name) LIKE ? ESCAPE '\'`
		args = append(args, "%"+escapeLike(strings.ToLower(search))+"%")
	}
	var total int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM asset_business_groups g WHERE `+where, args...).Scan(&total); err != nil {
		return BusinessGroupListPage{}, fmt.Errorf("count business groups: %w", err)
	}
	rows, err := s.db.QueryContext(ctx, `SELECT g.name,COUNT(a.id),g.created_at
FROM asset_business_groups g LEFT JOIN assets a ON a.business_group=g.name
WHERE `+where+`
GROUP BY g.name,g.created_at ORDER BY LOWER(g.name),g.name LIMIT ? OFFSET ?`, append(args, pageSize, offset)...)
	if err != nil {
		return BusinessGroupListPage{}, fmt.Errorf("list business groups page: %w", err)
	}
	defer rows.Close()
	items := make([]BusinessGroup, 0, pageSize)
	for rows.Next() {
		var group BusinessGroup
		if err := rows.Scan(&group.Name, &group.AssetCount, &group.CreatedAt); err != nil {
			return BusinessGroupListPage{}, fmt.Errorf("decode business group page: %w", err)
		}
		items = append(items, group)
	}
	if err := rows.Err(); err != nil {
		return BusinessGroupListPage{}, fmt.Errorf("list business groups page rows: %w", err)
	}
	return BusinessGroupListPage{Items: items, Total: total, Page: page, PageSize: pageSize}, nil
}

func (s *Store) CreateBusinessGroup(ctx context.Context, actor, name string) (BusinessGroup, error) {
	if strings.TrimSpace(actor) == "" {
		return BusinessGroup{}, ErrInvalid
	}
	name, err := normalizeBusinessGroup(name)
	if err != nil {
		return BusinessGroup{}, err
	}
	createdAt := time.Now().UTC().Format(time.RFC3339Nano)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return BusinessGroup{}, fmt.Errorf("begin business group: %w", err)
	}
	defer tx.Rollback()
	groupID, err := newID()
	if err != nil {
		return BusinessGroup{}, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO asset_business_groups(id,name,created_by,created_at) VALUES(?,?,?,?)`, groupID, name, actor, createdAt); err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return BusinessGroup{}, ErrBusinessGroupExists
		}
		return BusinessGroup{}, fmt.Errorf("create business group: %w", err)
	}
	auditID, err := newID()
	if err != nil {
		return BusinessGroup{}, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO audit_logs(id,actor,action,object_type,object_id,detail,created_at)
VALUES(?,?,'create_business_group','asset_business_group',?,'',?)`, auditID, actor, groupID, createdAt); err != nil {
		return BusinessGroup{}, fmt.Errorf("audit business group: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return BusinessGroup{}, fmt.Errorf("commit business group: %w", err)
	}
	return BusinessGroup{Name: name, CreatedAt: createdAt}, nil
}

func (s *Store) ListImportHistory(ctx context.Context) ([]ImportHistory, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,actor,imported,total,created_at
FROM asset_import_history ORDER BY created_at DESC,id DESC LIMIT 200`)
	if err != nil {
		return nil, fmt.Errorf("list asset import history: %w", err)
	}
	defer rows.Close()
	history := make([]ImportHistory, 0)
	for rows.Next() {
		var item ImportHistory
		if err := rows.Scan(&item.ID, &item.Actor, &item.Imported, &item.Total, &item.CreatedAt); err != nil {
			return nil, fmt.Errorf("decode asset import history: %w", err)
		}
		history = append(history, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list asset import history rows: %w", err)
	}
	return history, nil
}

func (s *Store) ListImportHistoryPage(ctx context.Context, query ImportHistoryListQuery) (ImportHistoryListPage, error) {
	page, pageSize, offset, search, err := normalizeManagementPage(query.Page, query.PageSize, query.Search)
	if err != nil {
		return ImportHistoryListPage{}, err
	}
	where := "1=1"
	args := []any{}
	if search != "" {
		where += ` AND LOWER(actor) LIKE ? ESCAPE '\'`
		args = append(args, "%"+escapeLike(strings.ToLower(search))+"%")
	}
	var total int
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM asset_import_history WHERE "+where, args...).Scan(&total); err != nil {
		return ImportHistoryListPage{}, fmt.Errorf("count import history: %w", err)
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id,actor,imported,total,created_at
FROM asset_import_history WHERE `+where+` ORDER BY created_at DESC,id DESC LIMIT ? OFFSET ?`, append(args, pageSize, offset)...)
	if err != nil {
		return ImportHistoryListPage{}, fmt.Errorf("list import history page: %w", err)
	}
	defer rows.Close()
	items := make([]ImportHistory, 0, pageSize)
	for rows.Next() {
		var item ImportHistory
		if err := rows.Scan(&item.ID, &item.Actor, &item.Imported, &item.Total, &item.CreatedAt); err != nil {
			return ImportHistoryListPage{}, fmt.Errorf("decode import history page: %w", err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return ImportHistoryListPage{}, fmt.Errorf("list import history page rows: %w", err)
	}
	return ImportHistoryListPage{Items: items, Total: total, Page: page, PageSize: pageSize}, nil
}

const (
	managementDefaultPageSize = 25
	managementMaxPageSize     = 100
	managementMaxPage         = 100000
)

func normalizeManagementPage(page, pageSize int, search string) (int, int, int, string, error) {
	if page == 0 {
		page = 1
	}
	if pageSize == 0 {
		pageSize = managementDefaultPageSize
	}
	search = strings.TrimSpace(search)
	if page < 1 || page > managementMaxPage || pageSize < 1 || pageSize > managementMaxPageSize || len(search) > 160 || strings.IndexByte(search, 0) >= 0 {
		return 0, 0, 0, "", ErrInvalid
	}
	return page, pageSize, (page - 1) * pageSize, search, nil
}
