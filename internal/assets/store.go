package assets

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"regexp"
	"scanner-platform/internal/inventory"
	"sort"
	"strings"
	"time"
)

var (
	ErrInvalid       = errors.New("invalid asset")
	ErrDuplicate     = errors.New("asset already exists")
	ErrNotFound      = errors.New("asset not found")
	ErrPortRequested = errors.New("port already requested")
	ErrPortExcluded  = errors.New("port is skipped or quarantined")
	ErrInUse         = errors.New("asset is referenced by authorization records")
)

type Asset struct {
	Name          string `json:"name,omitempty"`
	IsCore        bool   `json:"isCore"`
	Department    string `json:"department,omitempty"`
	Phone         string `json:"phone,omitempty"`
	MAC           string `json:"mac,omitempty"`
	OSName        string `json:"osName,omitempty"`
	OSFamily      string `json:"osFamily,omitempty"`
	DeviceType    string `json:"deviceType,omitempty"`
	DeviceSubtype string `json:"deviceSubtype,omitempty"`
	Vendor        string `json:"vendor,omitempty"`
	Model         string `json:"model,omitempty"`

	Services     []inventory.Service    `json:"services"`
	LoginEntries []inventory.LoginEntry `json:"loginEntries"`

	ID                    string `json:"id"`
	Kind                  string `json:"kind"`
	Address               string `json:"address"`
	ResolvedIP            string `json:"resolvedIp,omitempty"`
	BusinessGroup         string `json:"businessGroup"`
	Owner                 string `json:"owner"`
	CreatedAt             string `json:"createdAt"`
	Ports                 []Port `json:"ports"`
	RequestedPorts        []int  `json:"requestedPorts"`
	QuarantinedPorts      []int  `json:"quarantinedPorts"`
	SkippedPorts          []int  `json:"skippedPorts"`
	ReachabilityStatus    string `json:"reachabilityStatus"`
	ReachabilityCheckedAt string `json:"reachabilityCheckedAt,omitempty"`
}
type Port struct {
	Port   int    `json:"port"`
	Kind   string `json:"kind"`
	Source string `json:"source"`
}
type Input struct {
	Name          string `json:"name,omitempty"`
	IsCore        bool   `json:"isCore"`
	Department    string `json:"department,omitempty"`
	Phone         string `json:"phone,omitempty"`
	MAC           string `json:"mac,omitempty"`
	OSName        string `json:"osName,omitempty"`
	OSFamily      string `json:"osFamily,omitempty"`
	DeviceType    string `json:"deviceType,omitempty"`
	DeviceSubtype string `json:"deviceSubtype,omitempty"`
	Vendor        string `json:"vendor,omitempty"`
	Model         string `json:"model,omitempty"`

	Kind           string `json:"kind"`
	Address        string `json:"address"`
	BusinessGroup  string `json:"businessGroup"`
	Owner          string `json:"owner"`
	RequestedPorts []int  `json:"requestedPorts"`
	SkippedPorts   []int  `json:"skippedPorts"`
}
type Edit struct {
	Name          string `json:"name,omitempty"`
	IsCore        bool   `json:"isCore"`
	Department    string `json:"department,omitempty"`
	Phone         string `json:"phone,omitempty"`
	MAC           string `json:"mac,omitempty"`
	OSName        string `json:"osName,omitempty"`
	OSFamily      string `json:"osFamily,omitempty"`
	DeviceType    string `json:"deviceType,omitempty"`
	DeviceSubtype string `json:"deviceSubtype,omitempty"`
	Vendor        string `json:"vendor,omitempty"`
	Model         string `json:"model,omitempty"`

	Address        string `json:"address"`
	BusinessGroup  string `json:"businessGroup"`
	Owner          string `json:"owner"`
	RequestedPorts []int  `json:"requestedPorts"`
	SkippedPorts   []int  `json:"skippedPorts"`
}
type Repository interface {
	List(context.Context) ([]Asset, error)
	Create(context.Context, string, Input) (Asset, error)
	Update(context.Context, string, string, Edit) (Asset, error)
	RequestPort(context.Context, string, string, int) error
	RequestPorts(context.Context, string, string, []int) error
	Delete(context.Context, string, string) error
	CheckReachability(context.Context, string, string) (Reachability, error)
}
type Store struct {
	db     *sql.DB
	pinger Pinger
}

const (
	maxPorts            = 65535
	MaxPortRequestBatch = 1024
)

var imageRepoPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._:/-]{0,254}$`)

func New(db *sql.DB) (*Store, error) {
	return NewWithPinger(db, systemPing)
}

func NewWithPinger(db *sql.DB, pinger Pinger) (*Store, error) {
	if db == nil {
		return nil, fmt.Errorf("%w: missing database", ErrInvalid)
	}
	// Preserve the unused asset table created by the first synthetic runtime.
	// Never drop its contents when upgrading an existing local database.
	rows, err := db.Query("PRAGMA table_info(assets)")
	if err != nil {
		return nil, err
	}
	legacy, current := false, false
	for rows.Next() {
		var cid, notnull, pk int
		var name, kind string
		var def any
		if err := rows.Scan(&cid, &name, &kind, &notnull, &def, &pk); err != nil {
			rows.Close()
			return nil, err
		}
		legacy = legacy || name == "data"
		current = current || name == "kind"
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	if legacy && !current {
		if _, err := db.Exec("ALTER TABLE assets RENAME TO assets_legacy_runtime"); err != nil {
			return nil, fmt.Errorf("preserve legacy assets: %w", err)
		}
	}
	for _, stmt := range []string{
		`CREATE TABLE IF NOT EXISTS assets (
    id TEXT PRIMARY KEY,kind TEXT NOT NULL CHECK(kind IN ('host','image_repo')),
    address TEXT NOT NULL,resolved_ip TEXT,business_group TEXT NOT NULL,
    owner TEXT NOT NULL,created_at TEXT NOT NULL,
    UNIQUE(kind,address))`,
		`CREATE TABLE IF NOT EXISTS asset_import_previews(id TEXT PRIMARY KEY,actor TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,rows_json TEXT NOT NULL,expires_at INTEGER NOT NULL,state TEXT NOT NULL CHECK(state IN ('PENDING','CONFIRMED')))`,
		`CREATE TABLE IF NOT EXISTS asset_business_groups(id TEXT PRIMARY KEY,name TEXT NOT NULL UNIQUE,created_by TEXT NOT NULL,created_at TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS asset_import_history(id TEXT PRIMARY KEY,actor TEXT NOT NULL,imported INTEGER NOT NULL CHECK(imported > 0),total INTEGER NOT NULL CHECK(total >= imported),created_at TEXT NOT NULL)`,
		`CREATE INDEX IF NOT EXISTS idx_asset_business_groups_name ON asset_business_groups(name)`,
		`CREATE INDEX IF NOT EXISTS idx_asset_import_history_created_at ON asset_import_history(created_at DESC,id DESC)`,
		`CREATE TABLE IF NOT EXISTS asset_profiles(asset_id TEXT PRIMARY KEY REFERENCES assets(id) ON DELETE CASCADE,data TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS asset_services(asset_id TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,port INTEGER NOT NULL,data TEXT NOT NULL,PRIMARY KEY(asset_id,port))`,
		`CREATE TABLE IF NOT EXISTS asset_login_entries(asset_id TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,entry_key TEXT NOT NULL,data TEXT NOT NULL,PRIMARY KEY(asset_id,entry_key))`,
		`CREATE TABLE IF NOT EXISTS asset_port_requests (
    asset_id TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    port INTEGER NOT NULL CHECK(port BETWEEN 1 AND 65535),
    PRIMARY KEY(asset_id,port))`,
		`CREATE TABLE IF NOT EXISTS asset_port_request_authors (
    asset_id TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    port INTEGER NOT NULL CHECK(port BETWEEN 1 AND 65535),
    requested_by TEXT NOT NULL REFERENCES users(id),
    PRIMARY KEY(asset_id,port))`,
		`CREATE TABLE IF NOT EXISTS asset_ports (
    asset_id TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    port INTEGER NOT NULL CHECK(port BETWEEN 1 AND 65535),
    kind TEXT NOT NULL CHECK(kind IN ('WEB','NON_WEB','EXCLUDED_PROXY')),
    source TEXT NOT NULL,
    PRIMARY KEY(asset_id,port))`,
		`CREATE TABLE IF NOT EXISTS port_quarantine (
    asset_id TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    port INTEGER NOT NULL CHECK(port BETWEEN 1 AND 65535),
    reason TEXT NOT NULL, detected_at TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'ACTIVE' CHECK(status IN ('ACTIVE','RELEASED')),
    reviewed_by TEXT, reviewed_at TEXT,
    PRIMARY KEY(asset_id,port))`,
		`CREATE TABLE IF NOT EXISTS asset_port_reviews (
    asset_id TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    port INTEGER NOT NULL CHECK(port BETWEEN 1 AND 65535),
    status TEXT NOT NULL CHECK(status IN ('APPROVED','REJECTED')),
    reviewed_by TEXT NOT NULL REFERENCES users(id),
    approval_ticket TEXT NOT NULL,reviewed_at TEXT NOT NULL,
    review_note TEXT NOT NULL DEFAULT '',PRIMARY KEY(asset_id,port))`,
		`CREATE TABLE IF NOT EXISTS asset_reachability (
	    asset_id TEXT PRIMARY KEY REFERENCES assets(id) ON DELETE CASCADE,
	    status TEXT NOT NULL CHECK(status IN ('REACHABLE','NO_RESPONSE','CHECK_FAILED')),
	    checked_at TEXT NOT NULL)`,
	} {
		if _, err := db.Exec(stmt); err != nil {
			return nil, fmt.Errorf("initialize asset schema: %w", err)
		}
	}
	// Keep groups as a first-class resource while preserving assets registered
	// by older versions of the local runtime.
	if _, err := db.Exec(`INSERT INTO asset_business_groups(id,name,created_by,created_at)
SELECT lower(hex(randomblob(16))),business_group,'',MIN(created_at)
FROM assets GROUP BY business_group
ON CONFLICT(name) DO NOTHING`); err != nil {
		return nil, fmt.Errorf("backfill asset business groups: %w", err)
	}
	if pinger == nil {
		pinger = systemPing
	}
	return &Store{db: db, pinger: pinger}, nil
}
func validFields(group, owner string) bool {
	return len(strings.TrimSpace(group)) >= 1 && len(strings.TrimSpace(group)) <= 100 &&
		len(strings.TrimSpace(owner)) >= 1 && len(strings.TrimSpace(owner)) <= 100
}
func canonicalPorts(ports []int) ([]int, error) {
	if len(ports) > maxPorts {
		return nil, ErrInvalid
	}
	seen := make(map[int]bool, len(ports))
	for _, v := range ports {
		if v < 1 || v > 65535 || seen[v] {
			return nil, ErrInvalid
		}
		seen[v] = true
	}
	out := append([]int{}, ports...)
	sort.Ints(out)
	return out, nil
}
func normalize(in Input) (Input, error) {
	if !validProfile(in) {
		return Input{}, ErrInvalid
	}
	in.Address = strings.TrimSpace(in.Address)
	in.BusinessGroup = strings.TrimSpace(in.BusinessGroup)
	in.Owner = strings.TrimSpace(in.Owner)
	if !validFields(in.BusinessGroup, in.Owner) {
		return Input{}, ErrInvalid
	}
	switch in.Kind {
	case "host":
		ip := net.ParseIP(in.Address)
		if ip == nil || ip.IsUnspecified() || ip.IsMulticast() || ip.Equal(net.IPv4bcast) {
			return Input{}, ErrInvalid
		}
		in.Address = ip.String()
	case "image_repo":
		if !imageRepoPattern.MatchString(in.Address) || strings.Contains(in.Address, "..") ||
			strings.Contains(in.Address, "//") || strings.Contains(in.Address, "://") ||
			strings.Contains(in.Address, "@") {
			return Input{}, ErrInvalid
		}
	default:
		return Input{}, ErrInvalid
	}
	ports, err := canonicalPorts(in.RequestedPorts)
	if err != nil {
		return Input{}, err
	}
	in.RequestedPorts = ports
	in.SkippedPorts, err = canonicalPorts(in.SkippedPorts)
	if err != nil {
		return Input{}, err
	}
	if len(in.SkippedPorts) > 0 && in.Kind != "host" {
		return Input{}, ErrInvalid
	}
	return in, nil
}

func storeSkipped(ctx context.Context, tx *sql.Tx, id string, ports []int) error {
	for _, port := range ports {
		if _, err := tx.ExecContext(ctx, "INSERT INTO asset_ports(asset_id,port,kind,source) VALUES (?,?,'EXCLUDED_PROXY','manual_skip')", id, port); err != nil {
			return err
		}
	}
	return nil
}
func newID() (string, error) { return rand.Text(), nil }
func auditTx(ctx context.Context, tx *sql.Tx, actor, action, id string) error {
	key, err := newID()
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO audit_logs(id,actor,action,object_type,object_id,detail,created_at)
 VALUES (?,?,?,'asset',?,'',?)`, key, actor, action, id, time.Now().UTC().Format(time.RFC3339Nano))
	return err
}
func storeRequests(ctx context.Context, tx *sql.Tx, id, actor string, ports []int) error {
	for _, port := range ports {
		if _, err := tx.ExecContext(ctx, "INSERT INTO asset_port_requests(asset_id,port) VALUES (?,?)", id, port); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO asset_port_request_authors(asset_id,port,requested_by) VALUES (?,?,?)", id, port, actor); err != nil {
			return err
		}
	}
	return nil
}
func decodeAsset(row interface{ Scan(...any) error }) (Asset, error) {
	var a Asset
	var resolved, checkedAt sql.NullString
	err := row.Scan(&a.ID, &a.Kind, &a.Address, &resolved, &a.BusinessGroup, &a.Owner, &a.CreatedAt,
		&a.ReachabilityStatus, &checkedAt)
	if err != nil {
		return a, err
	}
	if resolved.Valid {
		a.ResolvedIP = resolved.String
	}
	if checkedAt.Valid {
		a.ReachabilityCheckedAt = checkedAt.String
	}
	a.Ports = []Port{}
	a.RequestedPorts = []int{}
	a.QuarantinedPorts = []int{}
	a.SkippedPorts = []int{}
	if a.ReachabilityStatus == "" {
		a.ReachabilityStatus = "UNCHECKED"
	}
	return a, nil
}

const columns = `id,kind,address,resolved_ip,business_group,owner,created_at,
COALESCE((SELECT status FROM asset_reachability r WHERE r.asset_id=assets.id),'UNCHECKED'),
COALESCE((SELECT checked_at FROM asset_reachability r WHERE r.asset_id=assets.id),'')`

func (s *Store) List(ctx context.Context) ([]Asset, error) { return ListSnapshot(ctx, s.db) }

type SnapshotQuerier interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

// ListSnapshot reads the complete registry through the caller's transaction.
func ListSnapshot(ctx context.Context, q SnapshotQuerier) ([]Asset, error) {
	rows, err := q.QueryContext(ctx, "SELECT "+columns+" FROM assets ORDER BY created_at DESC,id")
	if err != nil {
		return nil, fmt.Errorf("query assets: %w", err)
	}
	defer rows.Close()
	result := []Asset{}
	for rows.Next() {
		a, err := decodeAsset(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, a)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range result {
		ports, err := q.QueryContext(ctx, "SELECT port FROM asset_port_requests WHERE asset_id=? ORDER BY port", result[i].ID)
		if err != nil {
			return nil, err
		}
		for ports.Next() {
			var port int
			if err := ports.Scan(&port); err != nil {
				ports.Close()
				return nil, err
			}
			result[i].RequestedPorts = append(result[i].RequestedPorts, port)
		}
		err = ports.Err()
		ports.Close()
		if err != nil {
			return nil, err
		}
	}

	for i := range result {
		approved, err := q.QueryContext(ctx, `SELECT p.port,p.kind,p.source FROM asset_ports p
        WHERE p.asset_id=? AND NOT EXISTS(
          SELECT 1 FROM port_quarantine q
           WHERE q.asset_id=p.asset_id AND q.port=p.port AND q.status='ACTIVE'
        ) ORDER BY p.port`, result[i].ID)
		if err != nil {
			return nil, err
		}
		for approved.Next() {
			var item Port
			if err := approved.Scan(&item.Port, &item.Kind, &item.Source); err != nil {
				approved.Close()
				return nil, err
			}
			result[i].Ports = append(result[i].Ports, item)
			if item.Kind == "EXCLUDED_PROXY" {
				result[i].SkippedPorts = append(result[i].SkippedPorts, item.Port)
			}
		}
		err = approved.Err()
		approved.Close()
		if err != nil {
			return nil, err
		}
		quarantine, err := q.QueryContext(ctx, "SELECT port FROM port_quarantine WHERE asset_id=? AND status='ACTIVE' ORDER BY port", result[i].ID)
		if err != nil {
			return nil, err
		}
		for quarantine.Next() {
			var port int
			if err := quarantine.Scan(&port); err != nil {
				quarantine.Close()
				return nil, err
			}
			result[i].QuarantinedPorts = append(result[i].QuarantinedPorts, port)
		}
		err = quarantine.Err()
		quarantine.Close()
		if err != nil {
			return nil, err
		}
	}
	if err := loadProfiles(ctx, q, result); err != nil {
		return nil, err
	}
	return result, nil
}
func (s *Store) Create(ctx context.Context, actor string, in Input) (Asset, error) {
	in, err := normalize(in)
	if err != nil {
		return Asset{}, err
	}
	id, err := newID()
	if err != nil {
		return Asset{}, err
	}
	createdAt := time.Now().UTC().Format(time.RFC3339Nano)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Asset{}, err
	}
	defer tx.Rollback()
	resolved := ""
	if in.Kind == "host" {
		resolved = in.Address
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO assets(id,kind,address,resolved_ip,business_group,owner,created_at)
 VALUES (?,?,?,?,?,?,?)`, id, in.Kind, in.Address, resolved, in.BusinessGroup, in.Owner, createdAt)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return Asset{}, ErrDuplicate
		}
		return Asset{}, fmt.Errorf("create asset: %w", err)
	}
	if err := ensureBusinessGroupTx(ctx, tx, actor, in.BusinessGroup, createdAt); err != nil {
		return Asset{}, fmt.Errorf("register business group: %w", err)
	}
	if err := storeRequests(ctx, tx, id, actor, in.RequestedPorts); err != nil {
		return Asset{}, err
	}
	if err := storeSkipped(ctx, tx, id, in.SkippedPorts); err != nil {
		return Asset{}, err
	}
	if err := saveProfile(ctx, tx, id, in); err != nil {
		return Asset{}, err
	}
	if err := auditTx(ctx, tx, actor, "create_asset", id); err != nil {
		return Asset{}, err
	}
	if err := tx.Commit(); err != nil {
		return Asset{}, err
	}
	result := Asset{ID: id, Kind: in.Kind, Address: in.Address, ResolvedIP: resolved,
		BusinessGroup: in.BusinessGroup, Owner: in.Owner, CreatedAt: createdAt,
		Ports: skippedPortRecords(in.SkippedPorts), RequestedPorts: in.RequestedPorts, QuarantinedPorts: []int{}, SkippedPorts: in.SkippedPorts, Services: []inventory.Service{}, LoginEntries: []inventory.LoginEntry{}}
	applyProfile(&result, in)
	return result, nil
}
func skippedPortRecords(ports []int) []Port {
	out := []Port{}
	for _, p := range ports {
		out = append(out, Port{Port: p, Kind: "EXCLUDED_PROXY", Source: "manual_skip"})
	}
	return out
}
func (s *Store) Update(ctx context.Context, actor, id string, edit Edit) (Asset, error) {
	if !validProfile(edit) {
		return Asset{}, ErrInvalid
	}
	if strings.TrimSpace(actor) == "" || strings.TrimSpace(id) == "" {
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
	a, err := decodeAsset(tx.QueryRowContext(ctx, "SELECT "+columns+" FROM assets WHERE id=?", id))
	if errors.Is(err, sql.ErrNoRows) {
		return Asset{}, ErrNotFound
	}
	if err != nil {
		return Asset{}, err
	}
	if edit.Address == "" {
		edit.Address = a.Address
	}
	normalized, err := normalize(Input{Kind: a.Kind, Address: edit.Address, BusinessGroup: edit.BusinessGroup, Owner: edit.Owner, RequestedPorts: ports, SkippedPorts: edit.SkippedPorts})
	if err != nil {
		return Asset{}, err
	}
	resolved := ""
	if normalized.Kind == "host" {
		resolved = normalized.Address
	}
	addressChanged := normalized.Address != a.Address
	if _, err := tx.ExecContext(ctx, "UPDATE assets SET address=?,resolved_ip=?,business_group=?,owner=? WHERE id=?", normalized.Address, resolved, edit.BusinessGroup, edit.Owner, id); err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return Asset{}, ErrDuplicate
		}
		return Asset{}, err
	}
	if err := ensureBusinessGroupTx(ctx, tx, actor, normalized.BusinessGroup, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		return Asset{}, fmt.Errorf("register business group: %w", err)
	}
	if addressChanged {
		for _, table := range []string{"asset_services", "asset_login_entries", "port_quarantine"} {
			if _, err := tx.ExecContext(ctx, "DELETE FROM "+table+" WHERE asset_id=?", id); err != nil {
				return Asset{}, err
			}
		}
		var hasScopeTable int
		if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='authorized_scopes'").Scan(&hasScopeTable); err != nil {
			return Asset{}, err
		}
		if hasScopeTable > 0 {
			if _, err := tx.ExecContext(ctx, "UPDATE authorized_scopes SET status='REVOKED' WHERE asset_id=? AND status IN ('PENDING','APPROVED')", id); err != nil {
				return Asset{}, err
			}
		}
		if _, err := tx.ExecContext(ctx, "DELETE FROM asset_reachability WHERE asset_id=?", id); err != nil {
			return Asset{}, err
		}
	}
	// Any metadata or request edit invalidates all earlier port decisions.
	// Never retain stale approvals when an asset is resubmitted.
	for _, query := range []string{
		"DELETE FROM asset_ports WHERE asset_id=?",
		"DELETE FROM asset_port_reviews WHERE asset_id=?",
		"DELETE FROM asset_port_request_authors WHERE asset_id=?",
		"DELETE FROM asset_port_requests WHERE asset_id=?",
	} {
		if _, err := tx.ExecContext(ctx, query, id); err != nil {
			return Asset{}, err
		}
	}
	if err := storeRequests(ctx, tx, id, actor, ports); err != nil {
		return Asset{}, err
	}
	if err := storeSkipped(ctx, tx, id, normalized.SkippedPorts); err != nil {
		return Asset{}, err
	}
	if err := saveProfile(ctx, tx, id, edit); err != nil {
		return Asset{}, err
	}
	if err := auditTx(ctx, tx, actor, "update_asset", id); err != nil {
		return Asset{}, err
	}
	if err := tx.Commit(); err != nil {
		return Asset{}, err
	}
	applyProfile(&a, edit)
	a.BusinessGroup = edit.BusinessGroup
	a.Owner = edit.Owner
	a.Address = normalized.Address
	a.ResolvedIP = resolved
	if addressChanged {
		a.ReachabilityStatus = "UNCHECKED"
		a.ReachabilityCheckedAt = ""
	}
	a.RequestedPorts = ports
	a.Ports = skippedPortRecords(normalized.SkippedPorts)
	a.SkippedPorts = normalized.SkippedPorts
	return a, nil
}

// RequestPort appends one explicit port request without resetting decisions on
// other ports for the asset. It refuses ports already marked as proxy or
// quarantined.
func (s *Store) RequestPort(ctx context.Context, actor, id string, port int) error {
	if strings.TrimSpace(actor) == "" || id == "" || port < 1 || port > 65535 {
		return ErrInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var kind string
	if err := tx.QueryRowContext(ctx, "SELECT kind FROM assets WHERE id=?", id).Scan(&kind); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}
	if kind != "host" {
		return ErrInvalid
	}
	var exists int
	if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM asset_port_requests WHERE asset_id=? AND port=?", id, port).Scan(&exists); err != nil {
		return err
	}
	if exists > 0 {
		return ErrPortRequested
	}
	if err := tx.QueryRowContext(ctx, `SELECT
 (SELECT count(*) FROM asset_ports WHERE asset_id=? AND port=? AND kind='EXCLUDED_PROXY')+
 (SELECT count(*) FROM port_quarantine WHERE asset_id=? AND port=? AND status='ACTIVE')`, id, port, id, port).Scan(&exists); err != nil {
		return err
	}
	if exists > 0 {
		return ErrPortExcluded
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO asset_port_requests(asset_id,port) VALUES (?,?)", id, port); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO asset_port_request_authors(asset_id,port,requested_by) VALUES (?,?,?)", id, port, actor); err != nil {
		return err
	}
	if err := auditTx(ctx, tx, actor, "request_asset_port", id); err != nil {
		return err
	}
	return tx.Commit()
}

// RequestPorts creates a set of individual approval requests atomically. It
// does not approve any port or grant scan access.
func (s *Store) RequestPorts(ctx context.Context, actor, id string, ports []int) error {
	if strings.TrimSpace(actor) == "" || id == "" || len(ports) == 0 || len(ports) > MaxPortRequestBatch {
		return ErrInvalid
	}
	seen := make(map[int]struct{}, len(ports))
	for _, port := range ports {
		if port < 1 || port > 65535 {
			return ErrInvalid
		}
		if _, exists := seen[port]; exists {
			return ErrInvalid
		}
		seen[port] = struct{}{}
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var kind string
	if err := tx.QueryRowContext(ctx, "SELECT kind FROM assets WHERE id=?", id).Scan(&kind); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}
	if kind != "host" {
		return ErrInvalid
	}
	requested, err := tx.PrepareContext(ctx, "SELECT count(*) FROM asset_port_requests WHERE asset_id=? AND port=?")
	if err != nil {
		return err
	}
	defer requested.Close()
	excluded, err := tx.PrepareContext(ctx, `SELECT
 (SELECT count(*) FROM asset_ports WHERE asset_id=? AND port=? AND kind='EXCLUDED_PROXY')+
 (SELECT count(*) FROM port_quarantine WHERE asset_id=? AND port=? AND status='ACTIVE')`)
	if err != nil {
		return err
	}
	defer excluded.Close()
	for _, port := range ports {
		var exists int
		if err := requested.QueryRowContext(ctx, id, port).Scan(&exists); err != nil {
			return err
		}
		if exists > 0 {
			return ErrPortRequested
		}
		if err := excluded.QueryRowContext(ctx, id, port, id, port).Scan(&exists); err != nil {
			return err
		}
		if exists > 0 {
			return ErrPortExcluded
		}
	}
	if err := storeRequests(ctx, tx, id, actor, ports); err != nil {
		return err
	}
	if err := auditTx(ctx, tx, actor, "request_asset_ports", id); err != nil {
		return err
	}
	return tx.Commit()
}

// Delete removes an asset only after its authorization records are removed or
// revoked and deleted, so an active authorization cannot silently outlive it.
func (s *Store) Delete(ctx context.Context, actor, id string) error {
	if strings.TrimSpace(actor) == "" || strings.TrimSpace(id) == "" {
		return ErrInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var exists int
	if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM assets WHERE id=?", id).Scan(&exists); err != nil {
		return err
	}
	if exists == 0 {
		return ErrNotFound
	}
	var hasScopeTable int
	if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='authorized_scopes'").Scan(&hasScopeTable); err != nil {
		return err
	}
	if hasScopeTable > 0 {
		if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM authorized_scopes WHERE asset_id=?", id).Scan(&exists); err != nil {
			return err
		}
		if exists > 0 {
			return ErrInUse
		}
	}
	if err := auditTx(ctx, tx, actor, "delete_asset", id); err != nil {
		return err
	}
	for _, table := range []string{"asset_profiles", "asset_services", "asset_login_entries", "asset_reachability", "port_quarantine", "asset_ports", "asset_port_reviews", "asset_port_request_authors", "asset_port_requests"} {
		if _, err := tx.ExecContext(ctx, "DELETE FROM "+table+" WHERE asset_id=?", id); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM assets WHERE id=?", id); err != nil {
		return err
	}
	return tx.Commit()
}

// CheckReachability sends exactly one bounded ICMP echo to the registered host.
// NO_RESPONSE is informational; ICMP may be blocked while TCP services remain reachable.
func (s *Store) CheckReachability(ctx context.Context, actor, id string) (Reachability, error) {
	if strings.TrimSpace(actor) == "" || strings.TrimSpace(id) == "" {
		return Reachability{}, ErrInvalid
	}
	var address, kind string
	if err := s.db.QueryRowContext(ctx, "SELECT address,kind FROM assets WHERE id=?", id).Scan(&address, &kind); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Reachability{}, ErrNotFound
		}
		return Reachability{}, err
	}
	if kind != "host" {
		return Reachability{}, ErrInvalid
	}
	result, err := s.probeReachability(ctx, address)
	if err != nil {
		return Reachability{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Reachability{}, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `INSERT INTO asset_reachability(asset_id,status,checked_at) VALUES(?,?,?)
	 ON CONFLICT(asset_id) DO UPDATE SET status=excluded.status,checked_at=excluded.checked_at`, id, result.Status, result.CheckedAt); err != nil {
		return Reachability{}, err
	}
	if err := auditTx(ctx, tx, actor, "check_asset_reachability", id); err != nil {
		return Reachability{}, err
	}
	if err := tx.Commit(); err != nil {
		return Reachability{}, err
	}
	return result, nil
}

// TestReachability checks the exact numeric IP currently entered in an asset form.
// It does not require the asset to be saved and does not persist the result.
func (s *Store) TestReachability(ctx context.Context, address string) (Reachability, error) {
	address = strings.TrimSpace(address)
	ip := net.ParseIP(address)
	if ip == nil || ip.IsUnspecified() || ip.IsMulticast() || ip.Equal(net.IPv4bcast) {
		return Reachability{}, ErrInvalid
	}
	return s.probeReachability(ctx, ip.String())
}

// RefreshReachability checks only numeric host addresses already registered in the asset inventory.
// Each target receives one bounded ICMP echo per pass; no response is not an offline determination.
func (s *Store) RefreshReachability(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx, `SELECT id,address FROM assets WHERE kind='host' ORDER BY id`)
	if err != nil {
		return err
	}
	type target struct {
		id      string
		address string
	}
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
		result, err := s.probeReachability(ctx, item.address)
		if err != nil {
			return err
		}
		_, err = s.db.ExecContext(ctx, `INSERT INTO asset_reachability(asset_id,status,checked_at)
			SELECT id,?,? FROM assets WHERE id=? AND kind='host' AND address=?
			ON CONFLICT(asset_id) DO UPDATE SET status=excluded.status,checked_at=excluded.checked_at`,
			result.Status, result.CheckedAt, item.id, item.address)
		if err != nil {
			return fmt.Errorf("store reachability for registered host: %w", err)
		}
	}
	return nil
}

func (s *Store) probeReachability(ctx context.Context, address string) (Reachability, error) {
	checkCtx, cancel := context.WithTimeout(ctx, 2500*time.Millisecond)
	defer cancel()
	reachable, pingErr := s.pinger(checkCtx, address)
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
