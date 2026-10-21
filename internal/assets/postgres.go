package assets

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"scanner-platform/internal/inventory"
)

// PostgresStore is the Server-owned PostgreSQL asset repository. It implements
// the same core asset contract as Store; import history and scan-result
// projections are added by later adapters rather than silently falling back to
// SQLite.
type PostgresStore struct {
	db     *sql.DB
	pinger Pinger
}

var _ Repository = (*PostgresStore)(nil)

func NewPostgres(db *sql.DB) (*PostgresStore, error) {
	return NewPostgresWithPinger(db, systemPing)
}

func NewPostgresWithPinger(db *sql.DB, pinger Pinger) (*PostgresStore, error) {
	if db == nil {
		return nil, fmt.Errorf("%w: missing postgres database", ErrInvalid)
	}
	if pinger == nil {
		pinger = systemPing
	}
	return &PostgresStore{db: db, pinger: pinger}, nil
}

func (s *PostgresStore) SQLDB() *sql.DB { return s.db }

const postgresAssetColumns = `assets.id,assets.kind,assets.address,assets.resolved_ip,
	assets.business_group,assets.owner,assets.created_at,
	COALESCE((SELECT status FROM asset_reachability r WHERE r.asset_id=assets.id),'UNCHECKED'),
	COALESCE((SELECT checked_at FROM asset_reachability r WHERE r.asset_id=assets.id),'')`

func decodePostgresAsset(row interface{ Scan(...any) error }) (Asset, error) {
	var asset Asset
	var resolved sql.NullString
	var created time.Time
	var checkedAt string
	if err := row.Scan(&asset.ID, &asset.Kind, &asset.Address, &resolved,
		&asset.BusinessGroup, &asset.Owner, &created, &asset.ReachabilityStatus, &checkedAt); err != nil {
		return Asset{}, err
	}
	if resolved.Valid {
		asset.ResolvedIP = resolved.String
	}
	asset.CreatedAt = created.UTC().Format(time.RFC3339Nano)
	asset.ReachabilityCheckedAt = checkedAt
	if asset.ReachabilityStatus == "" {
		asset.ReachabilityStatus = "UNCHECKED"
	}
	asset.Ports = []Port{}
	asset.RequestedPorts = []int{}
	asset.QuarantinedPorts = []int{}
	asset.SkippedPorts = []int{}
	asset.Services = []inventory.Service{}
	asset.LoginEntries = []inventory.LoginEntry{}
	return asset, nil
}

func (s *PostgresStore) List(ctx context.Context) ([]Asset, error) {
	page, err := s.ListPage(ctx, ListQuery{Page: 1})
	if err != nil {
		return nil, err
	}
	return page.Items, nil
}

func (s *PostgresStore) ListPage(ctx context.Context, input ListQuery) (ListPage, error) {
	query, err := NormalizeListQuery(input)
	if err != nil {
		return ListPage{}, err
	}
	where := []string{"TRUE"}
	args := make([]any, 0, 6)
	addArg := func(value any) string {
		args = append(args, value)
		return fmt.Sprintf("$%d", len(args))
	}
	if query.Search != "" {
		pattern := "%" + escapeLike(query.Search) + "%"
		p1, p2, p3, p4 := addArg(pattern), addArg(pattern), addArg(pattern), addArg(pattern)
		where = append(where, fmt.Sprintf(`(assets.address LIKE %s ESCAPE '\' OR assets.business_group LIKE %s ESCAPE '\' OR assets.owner LIKE %s ESCAPE '\' OR COALESCE((p.data::jsonb ->> 'name'),'') LIKE %s ESCAPE '\')`, p1, p2, p3, p4))
	}
	whereSQL := strings.Join(where, " AND ")
	var total int
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM assets LEFT JOIN asset_profiles p ON p.asset_id=assets.id WHERE "+whereSQL, args...).Scan(&total); err != nil {
		return ListPage{}, fmt.Errorf("count postgres assets: %w", err)
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
		sortColumn = "COALESCE((p.data::jsonb ->> 'name'),'')"
	}
	direction := "ASC"
	if strings.HasPrefix(query.Sort, "-") || query.Sort == "" {
		direction = "DESC"
	}
	selectArgs := append([]any{}, args...)
	sqlQuery := "SELECT " + postgresAssetColumns + " FROM assets LEFT JOIN asset_profiles p ON p.asset_id=assets.id WHERE " + whereSQL + " ORDER BY " + sortColumn + " " + direction + ",assets.id ASC"
	if query.PageSize > 0 {
		limit := len(selectArgs) + 1
		offset := len(selectArgs) + 2
		sqlQuery += fmt.Sprintf(" LIMIT $%d OFFSET $%d", limit, offset)
		selectArgs = append(selectArgs, query.PageSize, (query.Page-1)*query.PageSize)
	}
	rows, err := s.db.QueryContext(ctx, sqlQuery, selectArgs...)
	if err != nil {
		return ListPage{}, fmt.Errorf("query postgres assets: %w", err)
	}
	items := make([]Asset, 0)
	for rows.Next() {
		item, scanErr := decodePostgresAsset(rows)
		if scanErr != nil {
			rows.Close()
			return ListPage{}, fmt.Errorf("decode postgres asset: %w", scanErr)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return ListPage{}, err
	}
	if err := rows.Close(); err != nil {
		return ListPage{}, err
	}
	if err := populatePostgresRelations(ctx, s.db, items); err != nil {
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

func populatePostgresRelations(ctx context.Context, q interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}, items []Asset) error {
	indices := make(map[string]int, len(items))
	for i := range items {
		indices[items[i].ID] = i
	}
	for i := range items {
		rows, err := q.QueryContext(ctx, "SELECT port FROM asset_port_requests WHERE asset_id=$1 ORDER BY port", items[i].ID)
		if err != nil {
			return err
		}
		for rows.Next() {
			var port int
			if err := rows.Scan(&port); err != nil {
				rows.Close()
				return err
			}
			items[i].RequestedPorts = append(items[i].RequestedPorts, port)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return err
		}
		rows.Close()
		approved, err := q.QueryContext(ctx, `SELECT p.port,p.kind,p.source FROM asset_ports p
			WHERE p.asset_id=$1 AND NOT EXISTS(
			SELECT 1 FROM port_quarantine q WHERE q.asset_id=p.asset_id AND q.port=p.port AND q.status='ACTIVE'
			) ORDER BY p.port`, items[i].ID)
		if err != nil {
			return err
		}
		for approved.Next() {
			var port Port
			if err := approved.Scan(&port.Port, &port.Kind, &port.Source); err != nil {
				approved.Close()
				return err
			}
			items[i].Ports = append(items[i].Ports, port)
			if port.Kind == "EXCLUDED_PROXY" {
				items[i].SkippedPorts = append(items[i].SkippedPorts, port.Port)
			}
		}
		if err := approved.Err(); err != nil {
			approved.Close()
			return err
		}
		approved.Close()
		quarantine, err := q.QueryContext(ctx, "SELECT port FROM port_quarantine WHERE asset_id=$1 AND status='ACTIVE' ORDER BY port", items[i].ID)
		if err != nil {
			return err
		}
		for quarantine.Next() {
			var port int
			if err := quarantine.Scan(&port); err != nil {
				quarantine.Close()
				return err
			}
			items[i].QuarantinedPorts = append(items[i].QuarantinedPorts, port)
		}
		if err := quarantine.Err(); err != nil {
			quarantine.Close()
			return err
		}
		quarantine.Close()
	}
	rows, err := q.QueryContext(ctx, "SELECT asset_id,data FROM asset_profiles ORDER BY asset_id")
	if err != nil {
		return err
	}
	for rows.Next() {
		var id, data string
		if err := rows.Scan(&id, &data); err != nil {
			rows.Close()
			return err
		}
		if index, ok := indices[id]; ok {
			if err := json.Unmarshal([]byte(data), &items[index]); err != nil {
				rows.Close()
				return fmt.Errorf("decode postgres asset profile: %w", err)
			}
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	return rows.Close()
}

func (s *PostgresStore) Create(ctx context.Context, actor string, input Input) (Asset, error) {
	if strings.TrimSpace(actor) == "" {
		return Asset{}, ErrInvalid
	}
	input, err := normalize(input)
	if err != nil {
		return Asset{}, err
	}
	id, err := newID()
	if err != nil {
		return Asset{}, err
	}
	now := time.Now().UTC()
	resolved := ""
	if input.Kind == "host" {
		resolved = input.Address
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Asset{}, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `INSERT INTO assets
		(id,kind,address,resolved_ip,business_group,owner,created_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7)`, id, input.Kind, input.Address, resolved, input.BusinessGroup, input.Owner, now); err != nil {
		if isPostgresAssetUnique(err) {
			return Asset{}, ErrDuplicate
		}
		return Asset{}, fmt.Errorf("create postgres asset: %w", err)
	}
	groupID, err := newID()
	if err != nil {
		return Asset{}, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO asset_business_groups(id,name,created_by,created_at)
		VALUES ($1,$2,$3,$4) ON CONFLICT(name) DO NOTHING`, groupID, input.BusinessGroup, actor, now); err != nil {
		return Asset{}, fmt.Errorf("create postgres business group: %w", err)
	}
	if err := postgresStoreRequests(ctx, tx, id, actor, input.RequestedPorts); err != nil {
		return Asset{}, err
	}
	if err := postgresStoreSkipped(ctx, tx, id, input.SkippedPorts); err != nil {
		return Asset{}, err
	}
	if err := savePostgresProfile(ctx, tx, id, input); err != nil {
		return Asset{}, err
	}
	if err := postgresAssetAudit(ctx, tx, actor, "create_asset", id); err != nil {
		return Asset{}, err
	}
	if err := tx.Commit(); err != nil {
		return Asset{}, err
	}
	result := Asset{ID: id, Kind: input.Kind, Address: input.Address, ResolvedIP: resolved, BusinessGroup: input.BusinessGroup, Owner: input.Owner, CreatedAt: now.Format(time.RFC3339Nano), Ports: skippedPortRecords(input.SkippedPorts), RequestedPorts: input.RequestedPorts, SkippedPorts: input.SkippedPorts, QuarantinedPorts: []int{}, Services: []inventory.Service{}, LoginEntries: []inventory.LoginEntry{}}
	applyProfile(&result, input)
	return result, nil
}

func isPostgresAssetUnique(err error) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), "duplicate key")
}

func savePostgresProfile(ctx context.Context, tx *sql.Tx, id string, value any) error {
	data, err := profileBytes(value)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO asset_profiles(asset_id,data) VALUES ($1,$2)
		ON CONFLICT(asset_id) DO UPDATE SET data=excluded.data`, id, string(data))
	return err
}

func postgresAssetAudit(ctx context.Context, tx *sql.Tx, actor, action, id string) error {
	key, err := newID()
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO audit_logs
		(id,actor,action,object_type,object_id,detail,created_at)
		VALUES ($1,$2,$3,'asset',$4,'',CURRENT_TIMESTAMP)`, key, actor, action, id)
	return err
}

func postgresStoreRequests(ctx context.Context, tx *sql.Tx, id, actor string, ports []int) error {
	for _, port := range ports {
		if _, err := tx.ExecContext(ctx, `INSERT INTO asset_port_requests(asset_id,port) VALUES ($1,$2)`, id, port); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO asset_port_request_authors(asset_id,port,requested_by) VALUES ($1,$2,$3)`, id, port, actor); err != nil {
			return err
		}
	}
	return nil
}

func postgresStoreSkipped(ctx context.Context, tx *sql.Tx, id string, ports []int) error {
	for _, port := range ports {
		if _, err := tx.ExecContext(ctx, `INSERT INTO asset_ports(asset_id,port,kind,source) VALUES ($1,$2,'EXCLUDED_PROXY','manual_skip')`, id, port); err != nil {
			return err
		}
	}
	return nil
}

func (s *PostgresStore) Update(ctx context.Context, actor, id string, edit Edit) (Asset, error) {
	if strings.TrimSpace(actor) == "" || strings.TrimSpace(id) == "" || !validProfile(edit) {
		return Asset{}, ErrInvalid
	}
	edit.Address = strings.TrimSpace(edit.Address)
	edit.BusinessGroup = strings.TrimSpace(edit.BusinessGroup)
	edit.Owner = strings.TrimSpace(edit.Owner)
	if !validFields(edit.BusinessGroup, edit.Owner) {
		return Asset{}, ErrInvalid
	}
	ports, err := canonicalPorts(edit.RequestedPorts)
	if err != nil {
		return Asset{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Asset{}, err
	}
	defer tx.Rollback()
	asset, err := decodePostgresAsset(tx.QueryRowContext(ctx, "SELECT "+postgresAssetColumns+" FROM assets WHERE assets.id=$1", id))
	if errors.Is(err, sql.ErrNoRows) {
		return Asset{}, ErrNotFound
	}
	if err != nil {
		return Asset{}, err
	}
	if edit.Address == "" {
		edit.Address = asset.Address
	}
	normalized, err := normalize(Input{Kind: asset.Kind, Address: edit.Address, BusinessGroup: edit.BusinessGroup, Owner: edit.Owner, RequestedPorts: ports, SkippedPorts: edit.SkippedPorts})
	if err != nil {
		return Asset{}, err
	}
	resolved := ""
	if normalized.Kind == "host" {
		resolved = normalized.Address
	}
	addressChanged := normalized.Address != asset.Address
	if _, err := tx.ExecContext(ctx, `UPDATE assets SET address=$1,resolved_ip=$2,business_group=$3,owner=$4 WHERE id=$5`, normalized.Address, resolved, normalized.BusinessGroup, normalized.Owner, id); err != nil {
		if isPostgresAssetUnique(err) {
			return Asset{}, ErrDuplicate
		}
		return Asset{}, err
	}
	groupID, err := newID()
	if err != nil {
		return Asset{}, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO asset_business_groups(id,name,created_by,created_at)
		VALUES ($1,$2,$3,CURRENT_TIMESTAMP) ON CONFLICT(name) DO NOTHING`, groupID, normalized.BusinessGroup, actor); err != nil {
		return Asset{}, err
	}
	if addressChanged {
		for _, table := range []string{"asset_services", "asset_login_entries", "port_quarantine", "asset_reachability"} {
			if _, err := tx.ExecContext(ctx, "DELETE FROM "+table+" WHERE asset_id=$1", id); err != nil {
				return Asset{}, err
			}
		}
		if _, err := tx.ExecContext(ctx, `UPDATE authorized_scopes SET status='REVOKED'
			WHERE asset_id=$1 AND status IN ('PENDING','APPROVED')`, id); err != nil {
			return Asset{}, err
		}
	}
	for _, table := range []string{"asset_ports", "asset_port_reviews", "asset_port_request_authors", "asset_port_requests"} {
		if _, err := tx.ExecContext(ctx, "DELETE FROM "+table+" WHERE asset_id=$1", id); err != nil {
			return Asset{}, err
		}
	}
	if err := postgresStoreRequests(ctx, tx, id, actor, ports); err != nil {
		return Asset{}, err
	}
	if err := postgresStoreSkipped(ctx, tx, id, normalized.SkippedPorts); err != nil {
		return Asset{}, err
	}
	if err := savePostgresProfile(ctx, tx, id, edit); err != nil {
		return Asset{}, err
	}
	if err := postgresAssetAudit(ctx, tx, actor, "update_asset", id); err != nil {
		return Asset{}, err
	}
	if err := tx.Commit(); err != nil {
		return Asset{}, err
	}
	applyProfile(&asset, edit)
	asset.Address, asset.BusinessGroup, asset.Owner, asset.ResolvedIP = normalized.Address, normalized.BusinessGroup, normalized.Owner, resolved
	asset.RequestedPorts = ports
	asset.Ports = skippedPortRecords(normalized.SkippedPorts)
	asset.SkippedPorts = normalized.SkippedPorts
	if addressChanged {
		asset.ReachabilityStatus = "UNCHECKED"
		asset.ReachabilityCheckedAt = ""
	}
	return asset, nil
}

func (s *PostgresStore) RequestPort(ctx context.Context, actor, id string, port int) error {
	return s.RequestPorts(ctx, actor, id, []int{port})
}

func (s *PostgresStore) RequestPorts(ctx context.Context, actor, id string, ports []int) error {
	if strings.TrimSpace(actor) == "" || strings.TrimSpace(id) == "" || len(ports) == 0 || len(ports) > MaxPortRequestBatch {
		return ErrInvalid
	}
	seen := map[int]bool{}
	for _, port := range ports {
		if port < 1 || port > 65535 || seen[port] {
			return ErrInvalid
		}
		seen[port] = true
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var kind string
	if err := tx.QueryRowContext(ctx, "SELECT kind FROM assets WHERE id=$1", id).Scan(&kind); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}
	if kind != "host" {
		return ErrInvalid
	}
	for _, port := range ports {
		var count int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM asset_port_requests WHERE asset_id=$1 AND port=$2`, id, port).Scan(&count); err != nil {
			return err
		}
		if count != 0 {
			return ErrPortRequested
		}
		if err := tx.QueryRowContext(ctx, `SELECT
			(SELECT COUNT(*) FROM asset_ports WHERE asset_id=$1 AND port=$2 AND kind='EXCLUDED_PROXY')+
			(SELECT COUNT(*) FROM port_quarantine WHERE asset_id=$1 AND port=$2 AND status='ACTIVE')`, id, port).Scan(&count); err != nil {
			return err
		}
		if count != 0 {
			return ErrPortExcluded
		}
	}
	if err := postgresStoreRequests(ctx, tx, id, actor, ports); err != nil {
		return err
	}
	if err := postgresAssetAudit(ctx, tx, actor, "request_asset_ports", id); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *PostgresStore) Delete(ctx context.Context, actor, id string) error {
	if strings.TrimSpace(actor) == "" || strings.TrimSpace(id) == "" {
		return ErrInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var count int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM assets WHERE id=$1", id).Scan(&count); err != nil {
		return err
	}
	if count == 0 {
		return ErrNotFound
	}
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM authorized_scopes WHERE asset_id=$1", id).Scan(&count); err != nil {
		return err
	}
	if count != 0 {
		return ErrInUse
	}
	if err := postgresAssetAudit(ctx, tx, actor, "delete_asset", id); err != nil {
		return err
	}
	for _, table := range []string{"asset_profiles", "asset_services", "asset_login_entries", "asset_reachability", "port_quarantine", "asset_ports", "asset_port_reviews", "asset_port_request_authors", "asset_port_requests"} {
		if _, err := tx.ExecContext(ctx, "DELETE FROM "+table+" WHERE asset_id=$1", id); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM assets WHERE id=$1", id); err != nil {
		return err
	}
	return tx.Commit()
}

func probePostgresReachability(ctx context.Context, pinger Pinger, address string) (Reachability, error) {
	checkCtx, cancel := context.WithTimeout(ctx, 2500*time.Millisecond)
	defer cancel()
	reachable, pingErr := pinger(checkCtx, address)
	if err := ctx.Err(); err != nil {
		return Reachability{}, err
	}
	status := "CHECK_FAILED"
	if pingErr == nil || errors.Is(checkCtx.Err(), context.DeadlineExceeded) {
		status = "NO_RESPONSE"
		if reachable && pingErr == nil {
			status = "REACHABLE"
		}
	}
	return Reachability{Status: status, CheckedAt: time.Now().UTC().Format(time.RFC3339Nano)}, nil
}

func (s *PostgresStore) CheckReachability(ctx context.Context, actor, id string) (Reachability, error) {
	if strings.TrimSpace(actor) == "" || strings.TrimSpace(id) == "" {
		return Reachability{}, ErrInvalid
	}
	var address, kind string
	if err := s.db.QueryRowContext(ctx, "SELECT address,kind FROM assets WHERE id=$1", id).Scan(&address, &kind); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Reachability{}, ErrNotFound
		}
		return Reachability{}, err
	}
	if kind != "host" {
		return Reachability{}, ErrInvalid
	}
	result, err := probePostgresReachability(ctx, s.pinger, address)
	if err != nil {
		return Reachability{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Reachability{}, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `INSERT INTO asset_reachability(asset_id,status,checked_at)
		VALUES ($1,$2,$3) ON CONFLICT(asset_id) DO UPDATE SET status=excluded.status,checked_at=excluded.checked_at`, id, result.Status, result.CheckedAt); err != nil {
		return Reachability{}, err
	}
	if err := postgresAssetAudit(ctx, tx, actor, "check_asset_reachability", id); err != nil {
		return Reachability{}, err
	}
	if err := tx.Commit(); err != nil {
		return Reachability{}, err
	}
	return result, nil
}

func (s *PostgresStore) TestReachability(ctx context.Context, address string) (Reachability, error) {
	address = strings.TrimSpace(address)
	ip := net.ParseIP(address)
	if ip == nil || ip.IsUnspecified() || ip.IsMulticast() || ip.Equal(net.IPv4bcast) {
		return Reachability{}, ErrInvalid
	}
	return probePostgresReachability(ctx, s.pinger, ip.String())
}

func (s *PostgresStore) RefreshReachability(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx, "SELECT id,address FROM assets WHERE kind='host' ORDER BY id")
	if err != nil {
		return err
	}
	type target struct{ id, address string }
	targets := make([]target, 0)
	for rows.Next() {
		var item target
		if err := rows.Scan(&item.id, &item.address); err != nil {
			rows.Close()
			return err
		}
		targets = append(targets, item)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, item := range targets {
		if err := ctx.Err(); err != nil {
			return err
		}
		result, err := probePostgresReachability(ctx, s.pinger, item.address)
		if err != nil {
			return err
		}
		if _, err := s.db.ExecContext(ctx, `INSERT INTO asset_reachability(asset_id,status,checked_at)
			SELECT id,$1,$2 FROM assets WHERE id=$3 AND kind='host' AND address=$4
			ON CONFLICT(asset_id) DO UPDATE SET status=excluded.status,checked_at=excluded.checked_at`, result.Status, result.CheckedAt, item.id, item.address); err != nil {
			return fmt.Errorf("store postgres reachability: %w", err)
		}
	}
	return nil
}
