package assets

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"regexp"
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
)

type Asset struct {
	ID               string `json:"id"`
	Kind             string `json:"kind"`
	Address          string `json:"address"`
	ResolvedIP       string `json:"resolvedIp,omitempty"`
	BusinessGroup    string `json:"businessGroup"`
	Owner            string `json:"owner"`
	CreatedAt        string `json:"createdAt"`
	Ports            []Port `json:"ports"`
	RequestedPorts   []int  `json:"requestedPorts"`
	QuarantinedPorts []int  `json:"quarantinedPorts"`
	SkippedPorts     []int  `json:"skippedPorts"`
}
type Port struct {
	Port   int    `json:"port"`
	Kind   string `json:"kind"`
	Source string `json:"source"`
}
type Input struct {
	Kind           string `json:"kind"`
	Address        string `json:"address"`
	BusinessGroup  string `json:"businessGroup"`
	Owner          string `json:"owner"`
	RequestedPorts []int  `json:"requestedPorts"`
	SkippedPorts   []int  `json:"skippedPorts"`
}
type Edit struct {
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
}
type Store struct{ db *sql.DB }

const maxPorts = 50

var imageRepoPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._:/-]{0,254}$`)

func New(db *sql.DB) (*Store, error) {
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
	} {
		if _, err := db.Exec(stmt); err != nil {
			return nil, fmt.Errorf("initialize asset schema: %w", err)
		}
	}
	return &Store{db: db}, nil
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
	for _, port := range in.SkippedPorts {
		found := false
		for _, requested := range ports {
			found = found || port == requested
		}
		if !found || in.Kind != "host" {
			return Input{}, ErrInvalid
		}
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
	var resolved sql.NullString
	err := row.Scan(&a.ID, &a.Kind, &a.Address, &resolved, &a.BusinessGroup, &a.Owner, &a.CreatedAt)
	if err != nil {
		return a, err
	}
	if resolved.Valid {
		a.ResolvedIP = resolved.String
	}
	a.Ports = []Port{}
	a.RequestedPorts = []int{}
	a.QuarantinedPorts = []int{}
	a.SkippedPorts = []int{}
	return a, nil
}

const columns = "id,kind,address,resolved_ip,business_group,owner,created_at"

func (s *Store) List(ctx context.Context) ([]Asset, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT "+columns+" FROM assets ORDER BY created_at DESC,id")
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
		ports, err := s.db.QueryContext(ctx, "SELECT port FROM asset_port_requests WHERE asset_id=? ORDER BY port", result[i].ID)
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
		approved, err := s.db.QueryContext(ctx, `SELECT p.port,p.kind,p.source FROM asset_ports p
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
		quarantine, err := s.db.QueryContext(ctx, "SELECT port FROM port_quarantine WHERE asset_id=? AND status='ACTIVE' ORDER BY port", result[i].ID)
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
	if err := storeRequests(ctx, tx, id, actor, in.RequestedPorts); err != nil {
		return Asset{}, err
	}
	if err := storeSkipped(ctx, tx, id, in.SkippedPorts); err != nil {
		return Asset{}, err
	}
	if err := auditTx(ctx, tx, actor, "create_asset", id); err != nil {
		return Asset{}, err
	}
	if err := tx.Commit(); err != nil {
		return Asset{}, err
	}
	return Asset{ID: id, Kind: in.Kind, Address: in.Address, ResolvedIP: resolved,
		BusinessGroup: in.BusinessGroup, Owner: in.Owner, CreatedAt: createdAt,
		Ports: skippedPortRecords(in.SkippedPorts), RequestedPorts: in.RequestedPorts, QuarantinedPorts: []int{}, SkippedPorts: in.SkippedPorts}, nil
}
func skippedPortRecords(ports []int) []Port {
	out := []Port{}
	for _, p := range ports {
		out = append(out, Port{Port: p, Kind: "EXCLUDED_PROXY", Source: "manual_skip"})
	}
	return out
}
func (s *Store) Update(ctx context.Context, actor, id string, edit Edit) (Asset, error) {
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
	normalized, err := normalize(Input{Kind: a.Kind, Address: a.Address, BusinessGroup: edit.BusinessGroup, Owner: edit.Owner, RequestedPorts: ports, SkippedPorts: edit.SkippedPorts})
	if err != nil {
		return Asset{}, err
	}
	if _, err := tx.ExecContext(ctx, "UPDATE assets SET business_group=?,owner=? WHERE id=?", edit.BusinessGroup, edit.Owner, id); err != nil {
		return Asset{}, err
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
	if err := auditTx(ctx, tx, actor, "update_asset", id); err != nil {
		return Asset{}, err
	}
	if err := tx.Commit(); err != nil {
		return Asset{}, err
	}
	a.BusinessGroup = edit.BusinessGroup
	a.Owner = edit.Owner
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
