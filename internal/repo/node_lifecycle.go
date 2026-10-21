package repo

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

var (
	ErrInvalidNodeLifecycle  = errors.New("invalid node lifecycle input")
	ErrNodeLifecycleExists   = errors.New("node already registered")
	ErrNodeLifecycleNotFound = errors.New("node is not registered")
	ErrNodeRevoked           = errors.New("node is revoked")
	nodeLifecycleID          = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$`)
)

const nodeOfflineAfter = 10 * time.Second

type NodeLifecycle struct {
	ID                string  `json:"id"`
	Kind              string  `json:"kind"`
	HostID            string  `json:"hostId"`
	Status            string  `json:"status"`
	RegisteredAt      string  `json:"registeredAt"`
	LastHeartbeat     *string `json:"lastHeartbeat,omitempty"`
	RevokedAt         *string `json:"revokedAt,omitempty"`
	OfflineGeneration int     `json:"offlineGeneration"`
}

type NodeLifecycleEvent struct {
	ID         string `json:"id"`
	NodeID     string `json:"nodeId"`
	Kind       string `json:"kind"`
	Generation int    `json:"generation"`
	CreatedAt  string `json:"createdAt"`
}

func nodeTime(now time.Time) string { return now.UTC().Format("2006-01-02T15:04:05.000000000Z") }

func nodeSQL(postgres bool, query string) string {
	if !postgres {
		return query
	}
	for n := 1; strings.Contains(query, "?"); n++ {
		query = strings.Replace(query, "?", fmt.Sprintf("$%d", n), 1)
	}
	return query
}

func registerNodeLifecycle(ctx context.Context, db *sql.DB, postgres bool, in NodeLifecycle, actor string) (NodeLifecycle, error) {
	if !nodeLifecycleID.MatchString(in.ID) || !nodeLifecycleID.MatchString(in.HostID) || (in.Kind != "worker" && in.Kind != "updater") || actor == "" {
		return NodeLifecycle{}, ErrInvalidNodeLifecycle
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return NodeLifecycle{}, fmt.Errorf("begin node registration: %w", err)
	}
	defer tx.Rollback()
	in.Status, in.RegisteredAt = "REGISTERED", nodeTime(time.Now())
	result, err := tx.ExecContext(ctx, nodeSQL(postgres, `INSERT INTO node_lifecycle(id,kind,host_id,status,registered_at) VALUES(?,?,?,?,?) ON CONFLICT(id) DO NOTHING`), in.ID, in.Kind, in.HostID, in.Status, in.RegisteredAt)
	if err != nil {
		return NodeLifecycle{}, fmt.Errorf("register node: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return NodeLifecycle{}, fmt.Errorf("check node registration result: %w", err)
	}
	if affected == 0 {
		return NodeLifecycle{}, ErrNodeLifecycleExists
	}
	if err = nodeEventTx(ctx, tx, postgres, in.ID, "REGISTERED", 0, in.RegisteredAt); err != nil {
		return NodeLifecycle{}, err
	}
	if err = nodeAuditTx(ctx, tx, postgres, actor, "register_node", in.ID, in.RegisteredAt); err != nil {
		return NodeLifecycle{}, err
	}
	if err = tx.Commit(); err != nil {
		return NodeLifecycle{}, fmt.Errorf("commit node registration: %w", err)
	}
	return in, nil
}

func revokeNodeLifecycle(ctx context.Context, db *sql.DB, postgres bool, id, actor string) error {
	if !nodeLifecycleID.MatchString(id) || actor == "" {
		return ErrInvalidNodeLifecycle
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin node revocation: %w", err)
	}
	defer tx.Rollback()
	var generation int
	err = tx.QueryRowContext(ctx, nodeSQL(postgres, `SELECT offline_generation FROM node_lifecycle WHERE id=?`), id).Scan(&generation)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNodeLifecycleNotFound
	}
	if err != nil {
		return fmt.Errorf("read node revocation state: %w", err)
	}
	now := nodeTime(time.Now())
	result, err := tx.ExecContext(ctx, nodeSQL(postgres, `UPDATE node_lifecycle SET status='REVOKED',revoked_at=? WHERE id=? AND status<>'REVOKED'`), now, id)
	if err != nil {
		return fmt.Errorf("revoke node: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("check node revocation result: %w", err)
	}
	if affected == 0 {
		return tx.Commit()
	}
	if err = nodeEventTx(ctx, tx, postgres, id, "REVOKED", generation, now); err != nil {
		return err
	}
	if err = nodeAuditTx(ctx, tx, postgres, actor, "revoke_node", id, now); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("commit node revocation: %w", err)
	}
	return nil
}

func nodeEventTx(ctx context.Context, tx *sql.Tx, postgres bool, id, kind string, generation int, at string) error {
	_, err := tx.ExecContext(ctx, nodeSQL(postgres, `INSERT INTO node_lifecycle_events(id,node_id,kind,generation,created_at) VALUES(?,?,?,?,?) ON CONFLICT(node_id,kind,generation) DO NOTHING`), "node-event-"+randomLocalID(), id, kind, generation, at)
	if err != nil {
		return fmt.Errorf("record node lifecycle event: %w", err)
	}
	return nil
}

func nodeAuditTx(ctx context.Context, tx *sql.Tx, postgres bool, actor, action, id, at string) error {
	_, err := tx.ExecContext(ctx, nodeSQL(postgres, `INSERT INTO audit_logs(id,actor,action,object_type,object_id,detail,created_at) VALUES(?,?,?,?,?,?,?)`), "audit-"+randomLocalID(), actor, action, "node", id, "", at)
	if err != nil {
		return fmt.Errorf("audit node lifecycle: %w", err)
	}
	return nil
}

func getNodeLifecycle(ctx context.Context, db *sql.DB, postgres bool, id string) (NodeLifecycle, bool, error) {
	var item NodeLifecycle
	var heartbeat, revoked sql.NullString
	err := db.QueryRowContext(ctx, nodeSQL(postgres, `SELECT id,kind,host_id,status,registered_at,last_heartbeat,revoked_at,offline_generation FROM node_lifecycle WHERE id=?`), id).Scan(&item.ID, &item.Kind, &item.HostID, &item.Status, &item.RegisteredAt, &heartbeat, &revoked, &item.OfflineGeneration)
	if errors.Is(err, sql.ErrNoRows) {
		return NodeLifecycle{}, false, nil
	}
	if err != nil {
		return NodeLifecycle{}, false, fmt.Errorf("read node lifecycle: %w", err)
	}
	if heartbeat.Valid {
		item.LastHeartbeat = &heartbeat.String
	}
	if revoked.Valid {
		item.RevokedAt = &revoked.String
	}
	return item, true, nil
}

func touchNodeLifecycle(ctx context.Context, db *sql.DB, postgres bool, id, kind string) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin node heartbeat: %w", err)
	}
	defer tx.Rollback()
	var status, expectedKind string
	var generation int
	err = tx.QueryRowContext(ctx, nodeSQL(postgres, `SELECT kind,status,offline_generation FROM node_lifecycle WHERE id=?`), id).Scan(&expectedKind, &status, &generation)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read node heartbeat state: %w", err)
	}
	if status == "REVOKED" {
		return ErrNodeRevoked
	}
	if expectedKind != kind {
		return ErrInvalidNodeLifecycle
	}
	now := nodeTime(time.Now())
	_, err = tx.ExecContext(ctx, nodeSQL(postgres, `UPDATE node_lifecycle SET status='ONLINE',last_heartbeat=? WHERE id=? AND revoked_at IS NULL`), now, id)
	if err != nil {
		return fmt.Errorf("record node heartbeat: %w", err)
	}
	if status == "OFFLINE" {
		if err = nodeEventTx(ctx, tx, postgres, id, "RECOVERED", generation, now); err != nil {
			return err
		}
	}
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("commit node heartbeat: %w", err)
	}
	return nil
}

func refreshNodeLifecycle(ctx context.Context, db *sql.DB, postgres bool, now time.Time) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin node offline refresh: %w", err)
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, nodeSQL(postgres, `SELECT id,offline_generation FROM node_lifecycle WHERE status='ONLINE' AND last_heartbeat<? ORDER BY id LIMIT 1000`), nodeTime(now.Add(-nodeOfflineAfter)))
	if err != nil {
		return fmt.Errorf("list overdue nodes: %w", err)
	}
	type overdue struct {
		id         string
		generation int
	}
	items := []overdue{}
	for rows.Next() {
		var item overdue
		if err = rows.Scan(&item.id, &item.generation); err != nil {
			rows.Close()
			return fmt.Errorf("scan overdue node: %w", err)
		}
		items = append(items, item)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("iterate overdue nodes: %w", err)
	}
	rows.Close()
	for _, item := range items {
		generation := item.generation + 1
		result, e := tx.ExecContext(ctx, nodeSQL(postgres, `UPDATE node_lifecycle SET status='OFFLINE',offline_generation=? WHERE id=? AND status='ONLINE'`), generation, item.id)
		if e != nil {
			return fmt.Errorf("mark node offline: %w", e)
		}
		affected, e := result.RowsAffected()
		if e != nil {
			return e
		}
		if affected == 0 {
			continue
		}
		if e = nodeEventTx(ctx, tx, postgres, item.id, "OFFLINE", generation, nodeTime(now)); e != nil {
			return e
		}
	}
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("commit node offline refresh: %w", err)
	}
	return nil
}

func listNodeLifecycleEvents(ctx context.Context, db *sql.DB, postgres bool, id string) ([]NodeLifecycleEvent, error) {
	if !nodeLifecycleID.MatchString(id) {
		return nil, ErrInvalidNodeLifecycle
	}
	rows, err := db.QueryContext(ctx, nodeSQL(postgres, `SELECT id,node_id,kind,generation,created_at FROM node_lifecycle_events WHERE node_id=? ORDER BY created_at,id LIMIT 200`), id)
	if err != nil {
		return nil, fmt.Errorf("list node lifecycle events: %w", err)
	}
	defer rows.Close()
	items := []NodeLifecycleEvent{}
	for rows.Next() {
		var item NodeLifecycleEvent
		if err = rows.Scan(&item.ID, &item.NodeID, &item.Kind, &item.Generation, &item.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan node lifecycle event: %w", err)
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *RuntimeStore) RegisterNodeLifecycle(ctx context.Context, in NodeLifecycle, actor string) (NodeLifecycle, error) {
	return registerNodeLifecycle(ctx, s.db, false, in, actor)
}
func (s *PostgresRuntimeStore) RegisterNodeLifecycle(ctx context.Context, in NodeLifecycle, actor string) (NodeLifecycle, error) {
	return registerNodeLifecycle(ctx, s.db, true, in, actor)
}
func (s *RuntimeStore) RevokeNodeLifecycle(ctx context.Context, id, actor string) error {
	return revokeNodeLifecycle(ctx, s.db, false, id, actor)
}
func (s *PostgresRuntimeStore) RevokeNodeLifecycle(ctx context.Context, id, actor string) error {
	return revokeNodeLifecycle(ctx, s.db, true, id, actor)
}
func (s *RuntimeStore) GetNodeLifecycle(ctx context.Context, id string) (NodeLifecycle, bool, error) {
	return getNodeLifecycle(ctx, s.db, false, id)
}
func (s *PostgresRuntimeStore) GetNodeLifecycle(ctx context.Context, id string) (NodeLifecycle, bool, error) {
	return getNodeLifecycle(ctx, s.db, true, id)
}
func (s *RuntimeStore) TouchNodeLifecycle(ctx context.Context, id, kind string) error {
	return touchNodeLifecycle(ctx, s.db, false, id, kind)
}
func (s *PostgresRuntimeStore) TouchNodeLifecycle(ctx context.Context, id, kind string) error {
	return touchNodeLifecycle(ctx, s.db, true, id, kind)
}
func (s *RuntimeStore) RefreshNodeLifecycle(ctx context.Context, now time.Time) error {
	return refreshNodeLifecycle(ctx, s.db, false, now)
}
func (s *PostgresRuntimeStore) RefreshNodeLifecycle(ctx context.Context, now time.Time) error {
	return refreshNodeLifecycle(ctx, s.db, true, now)
}
func (s *RuntimeStore) ListNodeLifecycleEvents(ctx context.Context, id string) ([]NodeLifecycleEvent, error) {
	return listNodeLifecycleEvents(ctx, s.db, false, id)
}
func (s *PostgresRuntimeStore) ListNodeLifecycleEvents(ctx context.Context, id string) ([]NodeLifecycleEvent, error) {
	return listNodeLifecycleEvents(ctx, s.db, true, id)
}
