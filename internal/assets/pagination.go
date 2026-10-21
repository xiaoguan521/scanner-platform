package assets

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

// ListQuery is the server-side asset list contract. PageSize=0 is reserved
// for internal full snapshots used by reports and dashboard aggregation.
type ListQuery struct {
	Page     int
	PageSize int
	Search   string
	Sort     string
}

type ListPage struct {
	Items    []Asset `json:"items"`
	Total    int     `json:"total"`
	Page     int     `json:"page"`
	PageSize int     `json:"pageSize"`
}

const (
	DefaultPageSize = 20
	MaxPageSize     = 100
)

func NormalizeListQuery(in ListQuery) (ListQuery, error) {
	if in.Page < 0 || in.PageSize < 0 || len(in.Search) > 160 || strings.ContainsRune(in.Search, 0) {
		return ListQuery{}, ErrInvalid
	}
	if in.Page == 0 {
		in.Page = 1
	}
	if in.PageSize == 0 && (in.Page != 1 || in.Search != "" || in.Sort != "") {
		in.PageSize = DefaultPageSize
	}
	if in.PageSize != 0 && in.PageSize > MaxPageSize {
		return ListQuery{}, ErrInvalid
	}
	if strings.HasPrefix(in.Sort, "+") {
		in.Sort = strings.TrimPrefix(in.Sort, "+")
	}
	sortKey := strings.TrimPrefix(in.Sort, "-")
	switch sortKey {
	case "", "created_at", "address", "business_group", "owner", "name":
	default:
		return ListQuery{}, ErrInvalid
	}
	return in, nil
}

func (s *Store) ListPage(ctx context.Context, in ListQuery) (ListPage, error) {
	query, err := NormalizeListQuery(in)
	if err != nil {
		return ListPage{}, err
	}
	items, total, err := listAssetRows(ctx, s.db, query)
	if err != nil {
		return ListPage{}, err
	}
	if err := populateAssetRelations(ctx, s.db, items); err != nil {
		return ListPage{}, err
	}
	if query.PageSize == 0 {
		query.PageSize = len(items)
		if query.PageSize == 0 {
			query.PageSize = DefaultPageSize
		}
	}
	return ListPage{Items: items, Total: total, Page: query.Page, PageSize: query.PageSize}, nil
}

func listAssetRows(ctx context.Context, q SnapshotQuerier, query ListQuery) ([]Asset, int, error) {
	where := []string{"1=1"}
	args := []any{}
	if query.Search != "" {
		pattern := "%" + escapeLike(query.Search) + "%"
		where = append(where, `(assets.address LIKE ? ESCAPE '\' OR assets.business_group LIKE ? ESCAPE '\' OR assets.owner LIKE ? ESCAPE '\' OR COALESCE(json_extract(p.data,'$.name'),'') LIKE ? ESCAPE '\')`)
		args = append(args, pattern, pattern, pattern, pattern)
	}
	whereSQL := strings.Join(where, " AND ")
	countRow := q.QueryRowContext(ctx, "SELECT COUNT(*) FROM assets LEFT JOIN asset_profiles p ON p.asset_id=assets.id WHERE "+whereSQL, args...)
	var total int
	if err := countRow.Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count assets: %w", err)
	}
	sortColumn := "assets.created_at"
	sortKey := strings.TrimPrefix(query.Sort, "-")
	switch sortKey {
	case "address":
		sortColumn = "assets.address"
	case "business_group":
		sortColumn = "assets.business_group"
	case "owner":
		sortColumn = "assets.owner"
	case "name":
		sortColumn = "COALESCE(json_extract(p.data,'$.name'),'')"
	}
	direction := "ASC"
	if strings.HasPrefix(query.Sort, "-") || query.Sort == "" {
		direction = "DESC"
	}
	sqlQuery := "SELECT " + columns + " FROM assets LEFT JOIN asset_profiles p ON p.asset_id=assets.id WHERE " + whereSQL + " ORDER BY " + sortColumn + " " + direction + ",assets.id ASC"
	if query.PageSize > 0 {
		sqlQuery += " LIMIT ? OFFSET ?"
		args = append(args, query.PageSize, (query.Page-1)*query.PageSize)
	}
	rows, err := q.QueryContext(ctx, sqlQuery, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("query assets: %w", err)
	}
	defer rows.Close()
	result := []Asset{}
	for rows.Next() {
		item, err := decodeAsset(rows)
		if err != nil {
			return nil, 0, err
		}
		result = append(result, item)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	return result, total, nil
}

func escapeLike(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, `%`, `\%`)
	return strings.ReplaceAll(value, `_`, `\_`)
}

func populateAssetRelations(ctx context.Context, q SnapshotQuerier, result []Asset) error {
	for i := range result {
		ports, err := q.QueryContext(ctx, "SELECT port FROM asset_port_requests WHERE asset_id=? ORDER BY port", result[i].ID)
		if err != nil {
			return err
		}
		for ports.Next() {
			var port int
			if err := ports.Scan(&port); err != nil {
				ports.Close()
				return err
			}
			result[i].RequestedPorts = append(result[i].RequestedPorts, port)
		}
		err = ports.Err()
		ports.Close()
		if err != nil {
			return err
		}
	}
	for i := range result {
		approved, err := q.QueryContext(ctx, `SELECT p.port,p.kind,p.source FROM asset_ports p
        WHERE p.asset_id=? AND NOT EXISTS(
          SELECT 1 FROM port_quarantine q
           WHERE q.asset_id=p.asset_id AND q.port=p.port AND q.status='ACTIVE'
        ) ORDER BY p.port`, result[i].ID)
		if err != nil {
			return err
		}
		for approved.Next() {
			var item Port
			if err := approved.Scan(&item.Port, &item.Kind, &item.Source); err != nil {
				approved.Close()
				return err
			}
			result[i].Ports = append(result[i].Ports, item)
			if item.Kind == "EXCLUDED_PROXY" {
				result[i].SkippedPorts = append(result[i].SkippedPorts, item.Port)
			}
		}
		err = approved.Err()
		approved.Close()
		if err != nil {
			return err
		}
		quarantine, err := q.QueryContext(ctx, "SELECT port FROM port_quarantine WHERE asset_id=? AND status='ACTIVE' ORDER BY port", result[i].ID)
		if err != nil {
			return err
		}
		for quarantine.Next() {
			var port int
			if err := quarantine.Scan(&port); err != nil {
				quarantine.Close()
				return err
			}
			result[i].QuarantinedPorts = append(result[i].QuarantinedPorts, port)
		}
		err = quarantine.Err()
		quarantine.Close()
		if err != nil {
			return err
		}
	}
	if err := loadProfiles(ctx, q, result); err != nil {
		return err
	}
	return nil
}

// SnapshotQuerier implementations are *sql.DB and *sql.Tx. Keep this
// assertion close to the pagination code so future repositories can add the
// same projection without exposing their database handle.
var _ SnapshotQuerier = (*sql.DB)(nil)
