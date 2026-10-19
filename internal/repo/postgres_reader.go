package repo

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ErrPostgresReaderUnconfigured indicates that the Server has not supplied
// an authenticated PostgreSQL connection. This adapter never creates its own
// connection or tries to discover database credentials.
var ErrPostgresReaderUnconfigured = errors.New("postgres reader: database connection is not configured")

// PostgresAssetScopeReader is the initial, read-only PostgreSQL implementation
// of AssetReader. The caller owns the *sql.DB and its connection lifecycle.
//
// This is NOT a scanning authorization service: a scope's Active flag only
// describes stored human approval and expiry. Execution still requires the
// Server's independent target, port, time-window, lease and fence checks.
type PostgresAssetScopeReader struct {
	db *sql.DB
}

var _ AssetReader = (*PostgresAssetScopeReader)(nil)

// NewPostgresAssetScopeReader accepts a database/sql connection backed by a
// PostgreSQL driver. It does not open, migrate, or modify a database.
func NewPostgresAssetScopeReader(db *sql.DB) (*PostgresAssetScopeReader, error) {
	if db == nil {
		return nil, ErrPostgresReaderUnconfigured
	}
	return &PostgresAssetScopeReader{db: db}, nil
}

// ListAssets returns registered assets only; registered assets are not a
// target allowlist, and this method does not query approved/blocked ports.
func (r *PostgresAssetScopeReader) ListAssets(ctx context.Context) ([]Asset, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT id,kind,address,resolved_ip,business_group,owner
		FROM public.assets ORDER BY address,id`)
	if err != nil {
		return nil, fmt.Errorf("list postgres assets: %w", err)
	}
	defer rows.Close()

	result := make([]Asset, 0)
	for rows.Next() {
		var asset Asset
		var resolvedIP sql.NullString
		if err := rows.Scan(&asset.ID, &asset.Kind, &asset.Address,
			&resolvedIP, &asset.BusinessGroup, &asset.Owner); err != nil {
			return nil, fmt.Errorf("scan postgres asset: %w", err)
		}
		if resolvedIP.Valid {
			asset.ResolvedIP = resolvedIP.String
		}
		result = append(result, asset)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate postgres assets: %w", err)
	}
	return result, nil
}

// GetScope returns a persisted application and its approval/expiry status.
// It intentionally does NOT mark a scope executable based on approval alone.
func (r *PostgresAssetScopeReader) GetScope(ctx context.Context, id string) (AuthorizedScope, error) {
	if strings.TrimSpace(id) == "" {
		return AuthorizedScope{}, errors.New("postgres scope id must not be blank")
	}
	var scope AuthorizedScope
	var status string
	err := r.db.QueryRowContext(ctx, `SELECT id,cidr_or_host,max_targets,
			approved_by,approval_ticket,expires_at,status
		FROM public.authorized_scopes WHERE id=$1`, id).Scan(
		&scope.ID, &scope.CIDROrHost, &scope.MaxTargets,
		&scope.ApprovedBy, &scope.ApprovalTicket,
		&scope.ExpiresAt, &status)
	if err != nil {
		return AuthorizedScope{}, fmt.Errorf("get postgres scope: %w", err)
	}
	scope.Active = status == "APPROVED" &&
		scope.ApprovedBy != "" && scope.ApprovalTicket != "" &&
		scope.ExpiresAt.After(time.Now())
	return scope, nil
}
