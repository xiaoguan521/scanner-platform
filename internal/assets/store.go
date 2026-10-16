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
	ErrInvalid   = errors.New("invalid asset")
	ErrDuplicate = errors.New("asset already exists")
	ErrNotFound  = errors.New("asset not found")
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
}
type Edit struct {
	BusinessGroup  string `json:"businessGroup"`
	Owner          string `json:"owner"`
	RequestedPorts []int  `json:"requestedPorts"`
}
type Repository interface {
	List(context.Context) ([]Asset, error)
	Create(context.Context, string, Input) (Asset, error)
	Update(context.Context, string, string, Edit) (Asset, error)
}
type Store struct{ db *sql.DB }

const maxPorts = 50

var imageRepoPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._:/-]{0,254}$`)

func New(db *sql.DB) (*Store, error) {
	if db == nil {
		return nil, fmt.Errorf("%w: missing database", ErrInvalid)
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
		if ip == nil {
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
	return in, nil
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
func storeRequests(ctx context.Context, tx *sql.Tx, id string, ports []int) error {
	for _, port := range ports {
		if _, err := tx.ExecContext(ctx, "INSERT INTO asset_port_requests(asset_id,port) VALUES (?,?)", id, port); err != nil {
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
	if err := storeRequests(ctx, tx, id, in.RequestedPorts); err != nil {
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
		Ports: []Port{}, RequestedPorts: in.RequestedPorts, QuarantinedPorts: []int{}}, nil
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
	if _, err := tx.ExecContext(ctx, "UPDATE assets SET business_group=?,owner=? WHERE id=?", edit.BusinessGroup, edit.Owner, id); err != nil {
		return Asset{}, err
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM asset_port_requests WHERE asset_id=?", id); err != nil {
		return Asset{}, err
	}
	if err := storeRequests(ctx, tx, id, ports); err != nil {
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
	return a, nil
}
