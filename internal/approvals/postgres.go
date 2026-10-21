package approvals

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

// PostgresStore implements the Server-owned authorization repository. It
// persists the same human approval state as the SQLite store, while keeping
// PostgreSQL timestamps typed as timestamptz and using numbered parameters.
type PostgresStore struct {
	db *sql.DB
}

var _ Repository = (*PostgresStore)(nil)
var _ ScopePageRepository = (*PostgresStore)(nil)
var _ PortRequestPageRepository = (*PostgresStore)(nil)

func NewPostgres(db *sql.DB) (*PostgresStore, error) {
	if db == nil {
		return nil, ErrInvalid
	}
	return &PostgresStore{db: db}, nil
}

func (s *PostgresStore) SQLDB() *sql.DB { return s.db }

func (s *PostgresStore) ListScopes(ctx context.Context) ([]Scope, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT "+scopeFields+" FROM authorized_scopes ORDER BY created_at DESC,id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]Scope, 0)
	for rows.Next() {
		item, err := readPostgresScope(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func readPostgresScope(row interface{ Scan(...any) error }) (Scope, error) {
	var item Scope
	var windows string
	var expiresAt time.Time
	if err := row.Scan(&item.ID, &item.AssetID, &item.CIDROrHost, &item.MaxTargets,
		&windows, &item.RequestedBy, &item.ApprovedBy, &item.ApprovalTicket,
		&expiresAt, &item.Status, &item.ReviewNote); err != nil {
		return Scope{}, err
	}
	if err := json.Unmarshal([]byte(windows), &item.TimeWindows); err != nil {
		return Scope{}, fmt.Errorf("decode postgres scope windows: %w", err)
	}
	item.ExpiresAt = expiresAt.UTC().Format(time.RFC3339)
	item.ExpiryState = scopeExpiryState(item.Status, expiresAt, time.Now().UTC())
	item.IsActive = item.ExpiryState == "ACTIVE" || item.ExpiryState == "EXPIRING"
	return item, nil
}

func (s *PostgresStore) RequestScope(ctx context.Context, actor string, input ScopeInput) (Scope, error) {
	if strings.TrimSpace(actor) == "" {
		return Scope{}, ErrInvalid
	}
	in, err := normalizeScopeInput(input)
	if err != nil {
		return Scope{}, err
	}
	expiresAt, err := time.Parse(time.RFC3339, in.ExpiresAt)
	if err != nil {
		return Scope{}, ErrInvalid
	}
	windows, err := json.Marshal(in.TimeWindows)
	if err != nil {
		return Scope{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Scope{}, err
	}
	defer tx.Rollback()
	var address, kind string
	if err := tx.QueryRowContext(ctx, "SELECT address,kind FROM assets WHERE id=$1", in.AssetID).Scan(&address, &kind); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Scope{}, ErrMissing
		}
		return Scope{}, err
	}
	if kind != "host" || net.ParseIP(address) == nil {
		return Scope{}, ErrInvalid
	}
	id, err := newID()
	if err != nil {
		return Scope{}, err
	}
	createdAt := time.Now().UTC()
	if _, err := tx.ExecContext(ctx, `INSERT INTO authorized_scopes
		(id,asset_id,cidr_or_host,max_targets,time_windows,requested_by,expires_at,created_at)
		VALUES ($1,$2,$3,1,$4,$5,$6,$7)`, id, in.AssetID, address, string(windows), actor, expiresAt.UTC(), createdAt); err != nil {
		return Scope{}, err
	}
	if err := postgresAudit(ctx, tx, actor, "request_scope", "scope", id); err != nil {
		return Scope{}, err
	}
	if err := tx.Commit(); err != nil {
		return Scope{}, err
	}
	return Scope{ID: id, AssetID: in.AssetID, CIDROrHost: address, MaxTargets: 1,
		TimeWindows: in.TimeWindows, RequestedBy: actor, ExpiresAt: expiresAt.UTC().Format(time.RFC3339),
		Status: "PENDING", ExpiryState: "NOT_APPLICABLE"}, nil
}

// UpdateScope replaces a request and resets its approval to PENDING. This
// prevents edits to an approved time window from retaining the old approval.
func (s *PostgresStore) UpdateScope(ctx context.Context, actor, id string, input ScopeInput) (Scope, error) {
	if strings.TrimSpace(actor) == "" || strings.TrimSpace(id) == "" {
		return Scope{}, ErrInvalid
	}
	in, err := normalizeScopeInput(input)
	if err != nil {
		return Scope{}, err
	}
	expiresAt, err := time.Parse(time.RFC3339, in.ExpiresAt)
	if err != nil {
		return Scope{}, ErrInvalid
	}
	windows, err := json.Marshal(in.TimeWindows)
	if err != nil {
		return Scope{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Scope{}, err
	}
	defer tx.Rollback()
	current, err := readPostgresScope(tx.QueryRowContext(ctx, "SELECT "+scopeFields+" FROM authorized_scopes WHERE id=$1", id))
	if errors.Is(err, sql.ErrNoRows) {
		return Scope{}, ErrMissing
	}
	if err != nil {
		return Scope{}, err
	}
	if current.Status != "PENDING" && current.Status != "APPROVED" {
		return Scope{}, ErrConflict
	}
	var address, kind string
	if err := tx.QueryRowContext(ctx, "SELECT address,kind FROM assets WHERE id=$1", in.AssetID).Scan(&address, &kind); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Scope{}, ErrMissing
		}
		return Scope{}, err
	}
	if kind != "host" || net.ParseIP(address) == nil {
		return Scope{}, ErrInvalid
	}
	if _, err := tx.ExecContext(ctx, `UPDATE authorized_scopes SET
		asset_id=$1,cidr_or_host=$2,max_targets=1,time_windows=$3,expires_at=$4,
		status='PENDING',approved_by='',approval_ticket='',review_note=''
		WHERE id=$5`, in.AssetID, address, string(windows), expiresAt.UTC(), id); err != nil {
		return Scope{}, err
	}
	if err := postgresAudit(ctx, tx, actor, "update_scope_reset_approval", "scope", id); err != nil {
		return Scope{}, err
	}
	if err := tx.Commit(); err != nil {
		return Scope{}, err
	}
	current.AssetID = in.AssetID
	current.CIDROrHost = address
	current.MaxTargets = 1
	current.TimeWindows = in.TimeWindows
	current.ExpiresAt = expiresAt.UTC().Format(time.RFC3339)
	current.Status = "PENDING"
	current.ApprovedBy = ""
	current.ApprovalTicket = ""
	current.ReviewNote = ""
	current.IsActive = false
	current.ExpiryState = "NOT_APPLICABLE"
	return current, nil
}

func (s *PostgresStore) DeleteScope(ctx context.Context, actor, id string) error {
	if strings.TrimSpace(actor) == "" || strings.TrimSpace(id) == "" {
		return ErrInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var status string
	if err := tx.QueryRowContext(ctx, "SELECT status FROM authorized_scopes WHERE id=$1", id).Scan(&status); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrMissing
		}
		return err
	}
	if status == "APPROVED" {
		return ErrConflict
	}
	if err := postgresAudit(ctx, tx, actor, "delete_scope", "scope", id); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM authorized_scopes WHERE id=$1", id); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *PostgresStore) RevokeScope(ctx context.Context, actor, id string) (Scope, error) {
	if strings.TrimSpace(actor) == "" || strings.TrimSpace(id) == "" {
		return Scope{}, ErrInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Scope{}, err
	}
	defer tx.Rollback()
	scope, err := readPostgresScope(tx.QueryRowContext(ctx, "SELECT "+scopeFields+" FROM authorized_scopes WHERE id=$1", id))
	if errors.Is(err, sql.ErrNoRows) {
		return Scope{}, ErrMissing
	}
	if err != nil {
		return Scope{}, err
	}
	if scope.Status != "APPROVED" {
		return Scope{}, ErrConflict
	}
	if _, err := tx.ExecContext(ctx, "UPDATE authorized_scopes SET status='REVOKED' WHERE id=$1", id); err != nil {
		return Scope{}, err
	}
	if err := postgresAudit(ctx, tx, actor, "revoke_scope", "scope", id); err != nil {
		return Scope{}, err
	}
	if err := tx.Commit(); err != nil {
		return Scope{}, err
	}
	scope.Status = "REVOKED"
	scope.IsActive = false
	scope.ExpiryState = "NOT_APPLICABLE"
	return scope, nil
}

func (s *PostgresStore) ReviewScope(ctx context.Context, actor, id string, d Decision) (Scope, error) {
	if strings.TrimSpace(actor) == "" || strings.TrimSpace(id) == "" || !validDecision(d) {
		return Scope{}, ErrInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Scope{}, err
	}
	defer tx.Rollback()
	scope, err := readPostgresScope(tx.QueryRowContext(ctx, "SELECT "+scopeFields+" FROM authorized_scopes WHERE id=$1", id))
	if errors.Is(err, sql.ErrNoRows) {
		return Scope{}, ErrMissing
	}
	if err != nil {
		return Scope{}, err
	}
	if scope.Status != "PENDING" {
		return Scope{}, ErrConflict
	}
	if scope.RequestedBy == actor {
		return Scope{}, ErrForbidden
	}
	expiresAt, err := time.Parse(time.RFC3339, scope.ExpiresAt)
	if err != nil || !expiresAt.After(time.Now().UTC()) {
		return Scope{}, ErrConflict
	}
	status := "REJECTED"
	if d.Decision == "APPROVE" {
		var address, kind string
		if err := tx.QueryRowContext(ctx, "SELECT address,kind FROM assets WHERE id=$1", scope.AssetID).Scan(&address, &kind); err != nil || kind != "host" || address != scope.CIDROrHost {
			return Scope{}, ErrConflict
		}
		status = "APPROVED"
	}
	result, err := tx.ExecContext(ctx, `UPDATE authorized_scopes SET
		status=$1,approved_by=$2,approval_ticket=$3,review_note=$4
		WHERE id=$5 AND status='PENDING'`, status, actor, strings.TrimSpace(d.ApprovalTicket), d.Note, id)
	if err != nil {
		return Scope{}, err
	}
	if count, err := result.RowsAffected(); err != nil || count != 1 {
		return Scope{}, ErrConflict
	}
	if err := postgresAudit(ctx, tx, actor, "review_scope_"+strings.ToLower(d.Decision), "scope", id); err != nil {
		return Scope{}, err
	}
	if err := tx.Commit(); err != nil {
		return Scope{}, err
	}
	scope.Status = status
	scope.ApprovedBy = actor
	scope.ApprovalTicket = strings.TrimSpace(d.ApprovalTicket)
	scope.ReviewNote = d.Note
	scope.ExpiryState = scopeExpiryState(status, expiresAt, time.Now().UTC())
	scope.IsActive = scope.ExpiryState == "ACTIVE" || scope.ExpiryState == "EXPIRING"
	return scope, nil
}

func (s *PostgresStore) ListScopesPage(ctx context.Context, query ScopeListQuery) (ScopeListPage, error) {
	query, offset, err := normalizeScopeListQuery(query)
	if err != nil {
		return ScopeListPage{}, err
	}
	where, args := postgresScopeExpiryWhere(query.Expiry)
	var total int
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM authorized_scopes"+where, args...).Scan(&total); err != nil {
		return ScopeListPage{}, fmt.Errorf("count postgres scopes: %w", err)
	}
	var expiringCount, expiredCount int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM authorized_scopes
		WHERE status='APPROVED' AND expires_at > CURRENT_TIMESTAMP
		AND expires_at <= CURRENT_TIMESTAMP + INTERVAL '7 days'`).Scan(&expiringCount); err != nil {
		return ScopeListPage{}, fmt.Errorf("count postgres expiring scopes: %w", err)
	}
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM authorized_scopes
		WHERE status='APPROVED' AND expires_at <= CURRENT_TIMESTAMP`).Scan(&expiredCount); err != nil {
		return ScopeListPage{}, fmt.Errorf("count postgres expired scopes: %w", err)
	}
	selectArgs := append([]any{}, args...)
	limitArg, offsetArg := len(selectArgs)+1, len(selectArgs)+2
	selectArgs = append(selectArgs, query.PageSize, offset)
	rows, err := s.db.QueryContext(ctx, fmt.Sprintf("SELECT %s FROM authorized_scopes%s ORDER BY created_at DESC,id LIMIT $%d OFFSET $%d", scopeFields, where, limitArg, offsetArg), selectArgs...)
	if err != nil {
		return ScopeListPage{}, fmt.Errorf("list postgres scopes: %w", err)
	}
	defer rows.Close()
	items := make([]Scope, 0, query.PageSize)
	for rows.Next() {
		item, err := readPostgresScope(rows)
		if err != nil {
			return ScopeListPage{}, fmt.Errorf("decode postgres scope: %w", err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return ScopeListPage{}, err
	}
	return ScopeListPage{Items: items, Total: total, Page: query.Page, PageSize: query.PageSize,
		ExpiringCount: expiringCount, ExpiredCount: expiredCount}, nil
}

func postgresScopeExpiryWhere(expiry string) (string, []any) {
	now := time.Now().UTC()
	switch expiry {
	case "expiring":
		return " WHERE status='APPROVED' AND expires_at > $1 AND expires_at <= $2", []any{now, now.Add(scopeExpiryWarning)}
	case "expired":
		return " WHERE status='APPROVED' AND expires_at <= $1", []any{now}
	default:
		return "", nil
	}
}

const postgresPortListFrom = `FROM asset_port_requests r JOIN assets a ON a.id=r.asset_id
	LEFT JOIN asset_port_reviews v ON v.asset_id=r.asset_id AND v.port=r.port
	LEFT JOIN asset_port_request_authors author ON author.asset_id=r.asset_id AND author.port=r.port
	LEFT JOIN asset_ports ap ON ap.asset_id=r.asset_id AND ap.port=r.port`

const postgresPortListQuery = `SELECT r.asset_id,a.address,r.port,
	COALESCE(v.status,'PENDING'),COALESCE(author.requested_by,''),COALESCE(v.reviewed_by,''),
	COALESCE(v.approval_ticket,''),COALESCE(v.reviewed_at::text,''),
	COALESCE(v.review_note,''),COALESCE(ap.kind,'') ` + postgresPortListFrom

func (s *PostgresStore) ListPortRequests(ctx context.Context) ([]PortRequest, error) {
	rows, err := s.db.QueryContext(ctx, postgresPortListQuery+" ORDER BY a.address,r.port")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]PortRequest, 0)
	for rows.Next() {
		item, err := readPort(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *PostgresStore) ReviewPort(ctx context.Context, actor, assetID string, port int, d Decision) (PortRequest, error) {
	if strings.TrimSpace(actor) == "" || strings.TrimSpace(assetID) == "" || port < 1 || port > 65535 || !validDecision(d) {
		return PortRequest{}, ErrInvalid
	}
	if d.Decision == "APPROVE" && d.Kind != "WEB" && d.Kind != "NON_WEB" {
		return PortRequest{}, ErrInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return PortRequest{}, err
	}
	defer tx.Rollback()
	var address, kind, requester string
	if err := tx.QueryRowContext(ctx, `SELECT a.address,a.kind,author.requested_by
		FROM asset_port_requests r JOIN assets a ON a.id=r.asset_id
		JOIN asset_port_request_authors author ON author.asset_id=r.asset_id AND author.port=r.port
		WHERE r.asset_id=$1 AND r.port=$2`, assetID, port).Scan(&address, &kind, &requester); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return PortRequest{}, ErrMissing
		}
		return PortRequest{}, err
	}
	if kind != "host" {
		return PortRequest{}, ErrInvalid
	}
	if actor == requester {
		return PortRequest{}, ErrForbidden
	}
	var reviewed int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM asset_port_reviews WHERE asset_id=$1 AND port=$2", assetID, port).Scan(&reviewed); err != nil {
		return PortRequest{}, err
	}
	if reviewed != 0 {
		return PortRequest{}, ErrConflict
	}
	var skipped int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM asset_ports
		WHERE asset_id=$1 AND port=$2 AND kind='EXCLUDED_PROXY'`, assetID, port).Scan(&skipped); err != nil {
		return PortRequest{}, err
	}
	if skipped > 0 {
		return PortRequest{}, ErrConflict
	}
	var quarantined int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM port_quarantine
		WHERE asset_id=$1 AND port=$2 AND status='ACTIVE'`, assetID, port).Scan(&quarantined); err != nil {
		return PortRequest{}, err
	}
	if quarantined > 0 && d.Decision == "APPROVE" {
		return PortRequest{}, ErrConflict
	}
	status := "REJECTED"
	if d.Decision == "APPROVE" {
		status = "APPROVED"
	}
	reviewedAt := time.Now().UTC()
	if _, err := tx.ExecContext(ctx, `INSERT INTO asset_port_reviews
		(asset_id,port,status,reviewed_by,approval_ticket,reviewed_at,review_note)
		VALUES ($1,$2,$3,$4,$5,$6,$7)`, assetID, port, status, actor, strings.TrimSpace(d.ApprovalTicket), reviewedAt, d.Note); err != nil {
		return PortRequest{}, fmt.Errorf("save postgres port review: %w", err)
	}
	if status == "APPROVED" {
		if _, err := tx.ExecContext(ctx, `INSERT INTO asset_ports(asset_id,port,kind,source)
			VALUES ($1,$2,$3,'manual_approval')`, assetID, port, d.Kind); err != nil {
			return PortRequest{}, err
		}
	}
	if err := postgresAudit(ctx, tx, actor, "review_port_"+strings.ToLower(d.Decision), "asset_port", fmt.Sprintf("%s:%d", assetID, port)); err != nil {
		return PortRequest{}, err
	}
	if err := tx.Commit(); err != nil {
		return PortRequest{}, err
	}
	return PortRequest{AssetID: assetID, Address: address, Port: port, RequestedBy: requester, Kind: d.Kind,
		Status: status, ReviewedBy: actor, ApprovalTicket: strings.TrimSpace(d.ApprovalTicket),
		ReviewedAt: reviewedAt.Format(time.RFC3339Nano), ReviewNote: d.Note}, nil
}

func (s *PostgresStore) ListPortRequestsPage(ctx context.Context, query PortRequestListQuery) (PortRequestListPage, error) {
	query, offset, err := normalizePortRequestListQuery(query)
	if err != nil {
		return PortRequestListPage{}, err
	}
	where, args := postgresPortRequestWhere(query)
	var total int
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) "+postgresPortListFrom+where, args...).Scan(&total); err != nil {
		return PortRequestListPage{}, fmt.Errorf("count postgres port requests: %w", err)
	}
	selectArgs := append([]any{}, args...)
	limitArg, offsetArg := len(selectArgs)+1, len(selectArgs)+2
	selectArgs = append(selectArgs, query.PageSize, offset)
	rows, err := s.db.QueryContext(ctx, fmt.Sprintf("%s%s ORDER BY a.address,r.port LIMIT $%d OFFSET $%d", postgresPortListQuery, where, limitArg, offsetArg), selectArgs...)
	if err != nil {
		return PortRequestListPage{}, fmt.Errorf("list postgres port requests: %w", err)
	}
	defer rows.Close()
	items := make([]PortRequest, 0, query.PageSize)
	for rows.Next() {
		item, err := readPort(rows)
		if err != nil {
			return PortRequestListPage{}, fmt.Errorf("decode postgres port request: %w", err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return PortRequestListPage{}, err
	}
	return PortRequestListPage{Items: items, Total: total, Page: query.Page, PageSize: query.PageSize}, nil
}

func postgresPortRequestWhere(query PortRequestListQuery) (string, []any) {
	clauses := make([]string, 0, 2)
	args := make([]any, 0, 3)
	addArg := func(value any) string {
		args = append(args, value)
		return fmt.Sprintf("$%d", len(args))
	}
	if query.Status != "ALL" {
		clauses = append(clauses, "COALESCE(v.status,'PENDING')="+addArg(query.Status))
	}
	if query.Search != "" {
		pattern := "%" + escapeApprovalLike(strings.ToLower(query.Search)) + "%"
		p1, p2 := addArg(pattern), addArg(pattern)
		clauses = append(clauses, "(LOWER(a.address) LIKE "+p1+" ESCAPE '\\' OR LOWER(r.asset_id) LIKE "+p2+" ESCAPE '\\')")
	}
	if len(clauses) == 0 {
		return "", args
	}
	return " WHERE " + strings.Join(clauses, " AND "), args
}

func postgresAudit(ctx context.Context, tx *sql.Tx, actor, action, objectType, objectID string) error {
	id, err := newID()
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO audit_logs
		(id,actor,action,object_type,object_id,detail,created_at)
		VALUES ($1,$2,$3,$4,$5,'',$6)`, id, actor, action, objectType, objectID, time.Now().UTC())
	return err
}
