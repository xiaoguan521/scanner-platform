// Package approvals owns proposed scopes and explicit port authorizations.
// Neither authorizes the disabled scanning executor directly.
package approvals

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"scanner-platform/internal/scheduler"
	"strings"
	"time"
)

var (
	ErrInvalid   = errors.New("invalid approval")
	ErrMissing   = errors.New("approval not found")
	ErrConflict  = errors.New("approval state conflict")
	ErrForbidden = errors.New("approval forbidden")
)

type TimeWindow = scheduler.Window
type Scope struct {
	ID             string       `json:"id"`
	AssetID        string       `json:"assetId"`
	CIDROrHost     string       `json:"cidrOrHost"`
	MaxTargets     int          `json:"maxTargets"`
	TimeWindows    []TimeWindow `json:"timeWindows"`
	RequestedBy    string       `json:"requestedBy"`
	ApprovedBy     string       `json:"approvedBy"`
	ApprovalTicket string       `json:"approvalTicket"`
	ExpiresAt      string       `json:"expiresAt"`
	IsActive       bool         `json:"isActive"`
	Status         string       `json:"status"`
	ReviewNote     string       `json:"reviewNote"`
}
type ScopeInput struct {
	AssetID     string       `json:"assetId"`
	TimeWindows []TimeWindow `json:"timeWindows"`
	ExpiresAt   string       `json:"expiresAt"`
}
type Decision struct {
	Decision       string `json:"decision"`
	ApprovalTicket string `json:"approvalTicket"`
	Note           string `json:"note"`
	Kind           string `json:"kind,omitempty"` // Explicit human port classification.
}
type PortRequest struct {
	AssetID        string `json:"assetId"`
	Address        string `json:"address"`
	Port           int    `json:"port"`
	Kind           string `json:"kind"`
	RequestedBy    string `json:"requestedBy"`
	Status         string `json:"status"`
	ReviewedBy     string `json:"reviewedBy"`
	ApprovalTicket string `json:"approvalTicket"`
	ReviewedAt     string `json:"reviewedAt"`
	ReviewNote     string `json:"reviewNote"`
}
type Repository interface {
	ListScopes(context.Context) ([]Scope, error)
	RequestScope(context.Context, string, ScopeInput) (Scope, error)
	UpdateScope(context.Context, string, string, ScopeInput) (Scope, error)
	DeleteScope(context.Context, string, string) error
	RevokeScope(context.Context, string, string) (Scope, error)
	ReviewScope(context.Context, string, string, Decision) (Scope, error)
	ListPortRequests(context.Context) ([]PortRequest, error)
	ReviewPort(context.Context, string, string, int, Decision) (PortRequest, error)
}
type Store struct{ db *sql.DB }

func New(db *sql.DB) (*Store, error) {
	if db == nil {
		return nil, ErrInvalid
	}
	for _, q := range []string{
		`CREATE TABLE IF NOT EXISTS authorized_scopes (
   id TEXT PRIMARY KEY,asset_id TEXT NOT NULL REFERENCES assets(id),
   cidr_or_host TEXT NOT NULL,max_targets INTEGER NOT NULL DEFAULT 1,
   time_windows TEXT NOT NULL,requested_by TEXT NOT NULL REFERENCES users(id),
   approved_by TEXT NOT NULL DEFAULT '',approval_ticket TEXT NOT NULL DEFAULT '',
   expires_at TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'PENDING'
     CHECK (status IN ('PENDING','APPROVED','REJECTED','REVOKED')),
   review_note TEXT NOT NULL DEFAULT '',created_at TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS asset_port_reviews (
   asset_id TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
   port INTEGER NOT NULL CHECK(port BETWEEN 1 AND 65535),
   status TEXT NOT NULL CHECK(status IN ('APPROVED','REJECTED')),
   reviewed_by TEXT NOT NULL REFERENCES users(id),
   approval_ticket TEXT NOT NULL,reviewed_at TEXT NOT NULL,
   review_note TEXT NOT NULL DEFAULT '',PRIMARY KEY(asset_id,port))`,
	} {
		if _, err := db.Exec(q); err != nil {
			return nil, fmt.Errorf("create approval schema: %w", err)
		}
	}
	return &Store{db: db}, nil
}
func newID() (string, error) { return rand.Text(), nil }
func audit(ctx context.Context, tx *sql.Tx, actor, action, objectType, objectID string) error {
	id, err := newID()
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO audit_logs(id,actor,action,object_type,object_id,detail,created_at)
  VALUES(?,?,?,?,?,'',?)`, id, actor, action, objectType, objectID, time.Now().UTC().Format(time.RFC3339Nano))
	return err
}
func validDecision(d Decision) bool {
	return (d.Decision == "APPROVE" || d.Decision == "REJECT") &&
		len(strings.TrimSpace(d.ApprovalTicket)) >= 3 && len(d.ApprovalTicket) <= 120 &&
		len(d.Note) <= 400
}
func validWindows(windows []TimeWindow) bool {
	return len(windows) > 0 && scheduler.ValidateWindows(windows) == nil
}
func normalizeScopeInput(in ScopeInput) (ScopeInput, error) {
	in.AssetID = strings.TrimSpace(in.AssetID)
	if in.AssetID == "" || len(in.AssetID) > 128 || !validWindows(in.TimeWindows) {
		return ScopeInput{}, ErrInvalid
	}
	expiry, err := time.Parse(time.RFC3339, in.ExpiresAt)
	if err != nil || !expiry.After(time.Now().Add(time.Minute)) || expiry.After(time.Now().Add(366*24*time.Hour)) {
		return ScopeInput{}, ErrInvalid
	}
	in.ExpiresAt = expiry.UTC().Format(time.RFC3339)
	return in, nil
}
func readScope(row interface{ Scan(...any) error }) (Scope, error) {
	var a Scope
	var windows string
	err := row.Scan(&a.ID, &a.AssetID, &a.CIDROrHost, &a.MaxTargets, &windows,
		&a.RequestedBy, &a.ApprovedBy, &a.ApprovalTicket, &a.ExpiresAt, &a.Status, &a.ReviewNote)
	if err != nil {
		return Scope{}, err
	}
	if err := json.Unmarshal([]byte(windows), &a.TimeWindows); err != nil {
		return Scope{}, err
	}
	expires, err := time.Parse(time.RFC3339, a.ExpiresAt)
	if err != nil {
		return Scope{}, err
	}
	a.IsActive = a.Status == "APPROVED" && expires.After(time.Now())
	return a, nil
}

const scopeFields = "id,asset_id,cidr_or_host,max_targets,time_windows,requested_by,approved_by,approval_ticket,expires_at,status,review_note"

func (s *Store) ListScopes(ctx context.Context) ([]Scope, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT "+scopeFields+" FROM authorized_scopes ORDER BY created_at DESC,id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []Scope{}
	for rows.Next() {
		a, err := readScope(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, a)
	}
	return result, rows.Err()
}
func (s *Store) RequestScope(ctx context.Context, actor string, input ScopeInput) (Scope, error) {
	in, err := normalizeScopeInput(input)
	if err != nil {
		return Scope{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Scope{}, err
	}
	defer tx.Rollback()
	var address, kind string
	err = tx.QueryRowContext(ctx, "SELECT address,kind FROM assets WHERE id=?", in.AssetID).Scan(&address, &kind)
	if errors.Is(err, sql.ErrNoRows) {
		return Scope{}, ErrMissing
	}
	if err != nil {
		return Scope{}, err
	}
	// MVP: one registered numeric host IP, no CIDR expansion.
	if kind != "host" || net.ParseIP(address) == nil {
		return Scope{}, ErrInvalid
	}
	windows, err := json.Marshal(in.TimeWindows)
	if err != nil {
		return Scope{}, err
	}
	id, err := newID()
	if err != nil {
		return Scope{}, err
	}
	created := time.Now().UTC().Format(time.RFC3339Nano)
	_, err = tx.ExecContext(ctx, `INSERT INTO authorized_scopes
   (id,asset_id,cidr_or_host,max_targets,time_windows,requested_by,expires_at,created_at)
   VALUES (?,?,?,1,?,?,?,?)`, id, in.AssetID, address, string(windows), actor, in.ExpiresAt, created)
	if err != nil {
		return Scope{}, err
	}
	if err := audit(ctx, tx, actor, "request_scope", "scope", id); err != nil {
		return Scope{}, err
	}
	if err := tx.Commit(); err != nil {
		return Scope{}, err
	}
	return Scope{ID: id, AssetID: in.AssetID, CIDROrHost: address, MaxTargets: 1,
		TimeWindows: in.TimeWindows, RequestedBy: actor, ApprovedBy: "", ApprovalTicket: "",
		ExpiresAt: in.ExpiresAt, IsActive: false, Status: "PENDING", ReviewNote: ""}, nil
}

// UpdateScope replaces a request and resets its approval to PENDING. This
// prevents edits to an approved time window from retaining the old approval.
func (s *Store) UpdateScope(ctx context.Context, actor, id string, input ScopeInput) (Scope, error) {
	if strings.TrimSpace(actor) == "" || strings.TrimSpace(id) == "" {
		return Scope{}, ErrInvalid
	}
	in, err := normalizeScopeInput(input)
	if err != nil {
		return Scope{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Scope{}, err
	}
	defer tx.Rollback()
	current, err := readScope(tx.QueryRowContext(ctx, "SELECT "+scopeFields+" FROM authorized_scopes WHERE id=?", id))
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
	if err := tx.QueryRowContext(ctx, "SELECT address,kind FROM assets WHERE id=?", in.AssetID).Scan(&address, &kind); errors.Is(err, sql.ErrNoRows) {
		return Scope{}, ErrMissing
	} else if err != nil {
		return Scope{}, err
	}
	if kind != "host" || net.ParseIP(address) == nil {
		return Scope{}, ErrInvalid
	}
	windows, err := json.Marshal(in.TimeWindows)
	if err != nil {
		return Scope{}, err
	}
	_, err = tx.ExecContext(ctx, `UPDATE authorized_scopes SET asset_id=?,cidr_or_host=?,max_targets=1,
 time_windows=?,expires_at=?,status='PENDING',approved_by='',approval_ticket='',review_note=''
 WHERE id=?`, in.AssetID, address, string(windows), in.ExpiresAt, id)
	if err != nil {
		return Scope{}, err
	}
	if err := audit(ctx, tx, actor, "update_scope_reset_approval", "scope", id); err != nil {
		return Scope{}, err
	}
	if err := tx.Commit(); err != nil {
		return Scope{}, err
	}
	current.AssetID = in.AssetID
	current.CIDROrHost = address
	current.MaxTargets = 1
	current.TimeWindows = in.TimeWindows
	current.ExpiresAt = in.ExpiresAt
	current.Status = "PENDING"
	current.ApprovedBy = ""
	current.ApprovalTicket = ""
	current.ReviewNote = ""
	current.IsActive = false
	return current, nil
}

func (s *Store) DeleteScope(ctx context.Context, actor, id string) error {
	if strings.TrimSpace(actor) == "" || strings.TrimSpace(id) == "" {
		return ErrInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var status string
	if err := tx.QueryRowContext(ctx, "SELECT status FROM authorized_scopes WHERE id=?", id).Scan(&status); errors.Is(err, sql.ErrNoRows) {
		return ErrMissing
	} else if err != nil {
		return err
	}
	if status == "APPROVED" {
		return ErrConflict
	}
	if err := audit(ctx, tx, actor, "delete_scope", "scope", id); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM authorized_scopes WHERE id=?", id); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) RevokeScope(ctx context.Context, actor, id string) (Scope, error) {
	if strings.TrimSpace(actor) == "" || strings.TrimSpace(id) == "" {
		return Scope{}, ErrInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Scope{}, err
	}
	defer tx.Rollback()
	scope, err := readScope(tx.QueryRowContext(ctx, "SELECT "+scopeFields+" FROM authorized_scopes WHERE id=?", id))
	if errors.Is(err, sql.ErrNoRows) {
		return Scope{}, ErrMissing
	}
	if err != nil {
		return Scope{}, err
	}
	if scope.Status != "APPROVED" {
		return Scope{}, ErrConflict
	}
	if _, err := tx.ExecContext(ctx, "UPDATE authorized_scopes SET status='REVOKED' WHERE id=?", id); err != nil {
		return Scope{}, err
	}
	if err := audit(ctx, tx, actor, "revoke_scope", "scope", id); err != nil {
		return Scope{}, err
	}
	if err := tx.Commit(); err != nil {
		return Scope{}, err
	}
	scope.Status = "REVOKED"
	scope.IsActive = false
	return scope, nil
}

func (s *Store) ReviewScope(ctx context.Context, actor, id string, d Decision) (Scope, error) {
	if id == "" || !validDecision(d) {
		return Scope{}, ErrInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Scope{}, err
	}
	defer tx.Rollback()
	scope, err := readScope(tx.QueryRowContext(ctx, "SELECT "+scopeFields+" FROM authorized_scopes WHERE id=?", id))
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
	expiry, err := time.Parse(time.RFC3339, scope.ExpiresAt)
	if err != nil || !expiry.After(time.Now()) {
		return Scope{}, ErrConflict
	}
	status := "REJECTED"
	if d.Decision == "APPROVE" {
		var address, kind string
		err = tx.QueryRowContext(ctx, "SELECT address,kind FROM assets WHERE id=?", scope.AssetID).Scan(&address, &kind)
		if err != nil || kind != "host" || address != scope.CIDROrHost {
			return Scope{}, ErrConflict
		}
		status = "APPROVED"
	}
	res, err := tx.ExecContext(ctx, `UPDATE authorized_scopes SET status=?,approved_by=?,approval_ticket=?,review_note=?
   WHERE id=? AND status='PENDING'`, status, actor, strings.TrimSpace(d.ApprovalTicket), d.Note, id)
	if err != nil {
		return Scope{}, err
	}
	n, err := res.RowsAffected()
	if err != nil || n != 1 {
		return Scope{}, ErrConflict
	}
	if err := audit(ctx, tx, actor, "review_scope_"+strings.ToLower(d.Decision), "scope", id); err != nil {
		return Scope{}, err
	}
	if err := tx.Commit(); err != nil {
		return Scope{}, err
	}
	scope.Status = status
	scope.ApprovedBy = actor
	scope.ApprovalTicket = strings.TrimSpace(d.ApprovalTicket)
	scope.ReviewNote = d.Note
	scope.IsActive = status == "APPROVED"
	return scope, nil
}
