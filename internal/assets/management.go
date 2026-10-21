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
