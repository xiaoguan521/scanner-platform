package assets

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

var _ ImportRepository = (*PostgresStore)(nil)
var _ BusinessGroupRepository = (*PostgresStore)(nil)
var _ BusinessGroupPageRepository = (*PostgresStore)(nil)
var _ ImportHistoryRepository = (*PostgresStore)(nil)
var _ ImportHistoryPageRepository = (*PostgresStore)(nil)

func (s *PostgresStore) ListBusinessGroups(ctx context.Context) ([]BusinessGroup, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT g.name,COUNT(a.id),g.created_at
		FROM asset_business_groups g LEFT JOIN assets a ON a.business_group=g.name
		GROUP BY g.name,g.created_at ORDER BY LOWER(g.name),g.name`)
	if err != nil {
		return nil, fmt.Errorf("list postgres business groups: %w", err)
	}
	defer rows.Close()
	items := make([]BusinessGroup, 0)
	for rows.Next() {
		var item BusinessGroup
		var createdAt time.Time
		if err := rows.Scan(&item.Name, &item.AssetCount, &createdAt); err != nil {
			return nil, fmt.Errorf("decode postgres business group: %w", err)
		}
		item.CreatedAt = createdAt.UTC().Format(time.RFC3339Nano)
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list postgres business group rows: %w", err)
	}
	return items, nil
}

func (s *PostgresStore) ListBusinessGroupsPage(ctx context.Context, query BusinessGroupListQuery) (BusinessGroupListPage, error) {
	page, pageSize, offset, search, err := normalizeManagementPage(query.Page, query.PageSize, query.Search)
	if err != nil {
		return BusinessGroupListPage{}, err
	}
	where := ""
	args := make([]any, 0, 1)
	if search != "" {
		where = " WHERE LOWER(g.name) LIKE $1 ESCAPE '\\'"
		args = append(args, "%"+escapeLike(strings.ToLower(search))+"%")
	}
	var total int
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM asset_business_groups g"+where, args...).Scan(&total); err != nil {
		return BusinessGroupListPage{}, fmt.Errorf("count postgres business groups: %w", err)
	}
	limitArg, offsetArg := len(args)+1, len(args)+2
	selectArgs := append(append([]any{}, args...), pageSize, offset)
	rows, err := s.db.QueryContext(ctx, fmt.Sprintf(`SELECT g.name,COUNT(a.id),g.created_at
		FROM asset_business_groups g LEFT JOIN assets a ON a.business_group=g.name%s
		GROUP BY g.name,g.created_at ORDER BY LOWER(g.name),g.name LIMIT $%d OFFSET $%d`, where, limitArg, offsetArg), selectArgs...)
	if err != nil {
		return BusinessGroupListPage{}, fmt.Errorf("list postgres business groups page: %w", err)
	}
	defer rows.Close()
	items := make([]BusinessGroup, 0, pageSize)
	for rows.Next() {
		var item BusinessGroup
		var createdAt time.Time
		if err := rows.Scan(&item.Name, &item.AssetCount, &createdAt); err != nil {
			return BusinessGroupListPage{}, fmt.Errorf("decode postgres business group page: %w", err)
		}
		item.CreatedAt = createdAt.UTC().Format(time.RFC3339Nano)
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return BusinessGroupListPage{}, err
	}
	return BusinessGroupListPage{Items: items, Total: total, Page: page, PageSize: pageSize}, nil
}

func (s *PostgresStore) CreateBusinessGroup(ctx context.Context, actor, name string) (BusinessGroup, error) {
	if strings.TrimSpace(actor) == "" {
		return BusinessGroup{}, ErrInvalid
	}
	name, err := normalizeBusinessGroup(name)
	if err != nil {
		return BusinessGroup{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return BusinessGroup{}, fmt.Errorf("begin postgres business group: %w", err)
	}
	defer tx.Rollback()
	id, err := newID()
	if err != nil {
		return BusinessGroup{}, err
	}
	createdAt := time.Now().UTC()
	if _, err := tx.ExecContext(ctx, `INSERT INTO asset_business_groups(id,name,created_by,created_at)
		VALUES ($1,$2,$3,$4)`, id, name, actor, createdAt); err != nil {
		if isPostgresAssetUnique(err) {
			return BusinessGroup{}, ErrBusinessGroupExists
		}
		return BusinessGroup{}, fmt.Errorf("create postgres business group: %w", err)
	}
	if err := postgresManagementAudit(ctx, tx, actor, "create_business_group", "asset_business_group", id, ""); err != nil {
		return BusinessGroup{}, err
	}
	if err := tx.Commit(); err != nil {
		return BusinessGroup{}, fmt.Errorf("commit postgres business group: %w", err)
	}
	return BusinessGroup{Name: name, CreatedAt: createdAt.Format(time.RFC3339Nano)}, nil
}

func (s *PostgresStore) ListImportHistory(ctx context.Context) ([]ImportHistory, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,actor,imported,total,created_at
		FROM asset_import_history ORDER BY created_at DESC,id DESC LIMIT 200`)
	if err != nil {
		return nil, fmt.Errorf("list postgres import history: %w", err)
	}
	defer rows.Close()
	items := make([]ImportHistory, 0)
	for rows.Next() {
		item, err := scanPostgresImportHistory(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list postgres import history rows: %w", err)
	}
	return items, nil
}

func scanPostgresImportHistory(row interface{ Scan(...any) error }) (ImportHistory, error) {
	var item ImportHistory
	var createdAt time.Time
	if err := row.Scan(&item.ID, &item.Actor, &item.Imported, &item.Total, &createdAt); err != nil {
		return ImportHistory{}, fmt.Errorf("decode postgres import history: %w", err)
	}
	item.CreatedAt = createdAt.UTC().Format(time.RFC3339Nano)
	return item, nil
}

func (s *PostgresStore) ListImportHistoryPage(ctx context.Context, query ImportHistoryListQuery) (ImportHistoryListPage, error) {
	page, pageSize, offset, search, err := normalizeManagementPage(query.Page, query.PageSize, query.Search)
	if err != nil {
		return ImportHistoryListPage{}, err
	}
	where := ""
	args := make([]any, 0, 1)
	if search != "" {
		where = " WHERE LOWER(actor) LIKE $1 ESCAPE '\\'"
		args = append(args, "%"+escapeLike(strings.ToLower(search))+"%")
	}
	var total int
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM asset_import_history"+where, args...).Scan(&total); err != nil {
		return ImportHistoryListPage{}, fmt.Errorf("count postgres import history: %w", err)
	}
	limitArg, offsetArg := len(args)+1, len(args)+2
	selectArgs := append(append([]any{}, args...), pageSize, offset)
	rows, err := s.db.QueryContext(ctx, fmt.Sprintf(`SELECT id,actor,imported,total,created_at
		FROM asset_import_history%s ORDER BY created_at DESC,id DESC LIMIT $%d OFFSET $%d`, where, limitArg, offsetArg), selectArgs...)
	if err != nil {
		return ImportHistoryListPage{}, fmt.Errorf("list postgres import history page: %w", err)
	}
	defer rows.Close()
	items := make([]ImportHistory, 0, pageSize)
	for rows.Next() {
		item, err := scanPostgresImportHistory(rows)
		if err != nil {
			return ImportHistoryListPage{}, err
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return ImportHistoryListPage{}, err
	}
	return ImportHistoryListPage{Items: items, Total: total, Page: page, PageSize: pageSize}, nil
}

func (s *PostgresStore) PreviewImport(ctx context.Context, actor string, data []byte) (ImportPreview, error) {
	if strings.TrimSpace(actor) == "" {
		return ImportPreview{}, ErrInvalid
	}
	preview, err := parseImportCSV(data)
	if err != nil {
		return ImportPreview{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ImportPreview{}, fmt.Errorf("begin postgres import preview: %w", err)
	}
	defer tx.Rollback()
	for i := range preview.Rows {
		row := &preview.Rows[i]
		if row.Reason == "" {
			var count int
			if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM assets WHERE kind=$1 AND address=$2", row.Kind, row.Address).Scan(&count); err != nil {
				return ImportPreview{}, fmt.Errorf("check postgres import duplicate: %w", err)
			}
			if count != 0 {
				row.Reason = "资产已存在"
			}
		}
		if row.Reason == "" {
			preview.Valid++
		} else {
			preview.Invalid++
		}
	}
	now := time.Now().UTC()
	if _, err := tx.ExecContext(ctx, "DELETE FROM asset_import_previews WHERE actor=$1 OR expires_at<=$2", actor, now.Unix()); err != nil {
		return ImportPreview{}, fmt.Errorf("clear postgres import previews: %w", err)
	}
	if preview.Invalid == 0 {
		preview.PreviewID, err = newID()
		if err != nil {
			return ImportPreview{}, err
		}
		expires := now.Add(ImportTTL)
		preview.ExpiresAt = expires.Format(time.RFC3339)
		encoded, err := json.Marshal(preview.Rows)
		if err != nil {
			return ImportPreview{}, fmt.Errorf("encode postgres import rows: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO asset_import_previews
			(id,actor,rows_json,expires_at,state) VALUES ($1,$2,$3,$4,'PENDING')`, preview.PreviewID, actor, string(encoded), expires.Unix()); err != nil {
			return ImportPreview{}, fmt.Errorf("stage postgres import preview: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return ImportPreview{}, fmt.Errorf("commit postgres import preview: %w", err)
	}
	return preview, nil
}

func (s *PostgresStore) ConfirmImport(ctx context.Context, actor, id string) (ImportResult, error) {
	if strings.TrimSpace(actor) == "" || strings.TrimSpace(id) == "" || len(id) > 128 {
		return ImportResult{}, ErrImportUnavailable
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ImportResult{}, fmt.Errorf("begin postgres import confirmation: %w", err)
	}
	defer tx.Rollback()
	claim, err := tx.ExecContext(ctx, `UPDATE asset_import_previews SET state='CONFIRMED'
		WHERE id=$1 AND actor=$2 AND state='PENDING' AND expires_at>$3`, id, actor, time.Now().UTC().Unix())
	if err != nil {
		return ImportResult{}, fmt.Errorf("claim postgres import preview: %w", err)
	}
	count, err := claim.RowsAffected()
	if err != nil || count != 1 {
		return ImportResult{}, ErrImportUnavailable
	}
	var encoded string
	if err := tx.QueryRowContext(ctx, "SELECT rows_json FROM asset_import_previews WHERE id=$1", id).Scan(&encoded); err != nil {
		return ImportResult{}, fmt.Errorf("read postgres import preview: %w", err)
	}
	var rows []ImportRow
	if len(encoded) > MaxImportBytes*8 || json.Unmarshal([]byte(encoded), &rows) != nil || len(rows) == 0 || len(rows) > MaxImportRows {
		return ImportResult{}, ErrImportUnavailable
	}
	createdAt := time.Now().UTC()
	for _, row := range rows {
		in, err := normalize(importInput(row))
		if err != nil || row.Reason != "" {
			return ImportResult{}, ErrImportUnavailable
		}
		assetID, err := newID()
		if err != nil {
			return ImportResult{}, err
		}
		resolved := ""
		if in.Kind == "host" {
			resolved = in.Address
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO assets
			(id,kind,address,resolved_ip,business_group,owner,created_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7)`, assetID, in.Kind, in.Address, resolved, in.BusinessGroup, in.Owner, createdAt); err != nil {
			if isPostgresAssetUnique(err) {
				return ImportResult{}, ErrImportConflict
			}
			return ImportResult{}, fmt.Errorf("insert postgres imported asset: %w", err)
		}
		if err := savePostgresProfile(ctx, tx, assetID, in); err != nil {
			return ImportResult{}, fmt.Errorf("insert postgres imported profile: %w", err)
		}
		if err := ensurePostgresBusinessGroup(ctx, tx, actor, in.BusinessGroup, createdAt); err != nil {
			return ImportResult{}, fmt.Errorf("register postgres imported business group: %w", err)
		}
	}
	detail := fmt.Sprintf(`{"imported":%d}`, len(rows))
	if err := postgresManagementAudit(ctx, tx, actor, "import_assets", "asset_import", "", detail); err != nil {
		return ImportResult{}, err
	}
	historyID, err := newID()
	if err != nil {
		return ImportResult{}, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO asset_import_history
		(id,actor,imported,total,created_at) VALUES ($1,$2,$3,$4,$5)`, historyID, actor, len(rows), len(rows), createdAt); err != nil {
		return ImportResult{}, fmt.Errorf("record postgres import history: %w", err)
	}
	if _, err := tx.ExecContext(ctx, "UPDATE asset_import_previews SET rows_json='[]' WHERE id=$1", id); err != nil {
		return ImportResult{}, fmt.Errorf("clear postgres confirmed import: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return ImportResult{}, fmt.Errorf("commit postgres import: %w", err)
	}
	return ImportResult{Imported: len(rows)}, nil
}

func ensurePostgresBusinessGroup(ctx context.Context, tx *sql.Tx, actor, name string, createdAt time.Time) error {
	name, err := normalizeBusinessGroup(name)
	if err != nil {
		return err
	}
	id, err := newID()
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO asset_business_groups(id,name,created_by,created_at)
		VALUES ($1,$2,$3,$4) ON CONFLICT(name) DO NOTHING`, id, name, actor, createdAt)
	return err
}

func postgresManagementAudit(ctx context.Context, tx *sql.Tx, actor, action, objectType, objectID, detail string) error {
	id, err := newID()
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO audit_logs
		(id,actor,action,object_type,object_id,detail,created_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7)`, id, actor, action, objectType, objectID, detail, time.Now().UTC())
	return err
}
