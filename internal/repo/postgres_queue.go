package repo

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

var (
	// ErrPostgresTaskUnavailable means that no queued chunk can be claimed, or
	// that a lease/complete operation no longer owns the requested chunk.
	ErrPostgresTaskUnavailable = errors.New("postgres task chunk unavailable")
	ErrPostgresTaskInvalid     = errors.New("invalid postgres task")
)

const defaultPostgresLeaseDuration = 2 * time.Minute

// PostgresTaskStore is the first production-oriented queue adapter. It keeps
// claiming, lease renewal and completion inside Server-owned PostgreSQL
// transactions; Worker and Updater never receive this database handle.
type PostgresTaskStore struct {
	db            *sql.DB
	leaseDuration time.Duration
	now           func() time.Time
}

var _ TaskStore = (*PostgresTaskStore)(nil)
var _ LeaseRegistry = (*PostgresTaskStore)(nil)

func NewPostgresTaskStore(db *sql.DB) (*PostgresTaskStore, error) {
	if db == nil {
		return nil, ErrPostgresDSNRequired
	}
	return &PostgresTaskStore{db: db, leaseDuration: defaultPostgresLeaseDuration, now: time.Now}, nil
}

func (s *PostgresTaskStore) CreateTask(ctx context.Context, task ScanTask) error {
	if s == nil || s.db == nil || !validPostgresTask(task) {
		return ErrPostgresTaskInvalid
	}
	engines, err := json.Marshal(task.Engines)
	if err != nil {
		return fmt.Errorf("encode postgres task engines: %w", err)
	}
	targets, err := json.Marshal(task.Targets)
	if err != nil {
		return fmt.Errorf("encode postgres task targets: %w", err)
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin postgres task: %w", err)
	}
	defer tx.Rollback()
	var deadline any
	if !task.HardDeadline.IsZero() {
		deadline = task.HardDeadline.UTC()
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO scan_tasks
		(id,scope_id,engines,status,hard_deadline,created_by)
		VALUES ($1,$2,$3,$4,$5,$6)`, task.ID, task.ScopeID, string(engines), task.Status, deadline, task.CreatedBy); err != nil {
		return fmt.Errorf("insert postgres task: %w", err)
	}
	chunkID := task.ID + "-chunk"
	if _, err := tx.ExecContext(ctx, `INSERT INTO scan_task_chunks
		(id,task_id,targets,status,pinned_rule_version)
		VALUES ($1,$2,$3,'PENDING',$4)`, chunkID, task.ID, string(targets), task.PinnedRuleVersion); err != nil {
		return fmt.Errorf("insert postgres task chunk: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit postgres task: %w", err)
	}
	return nil
}

func validPostgresTask(task ScanTask) bool {
	if strings.TrimSpace(task.ID) == "" || len(task.ID) > 128 ||
		strings.TrimSpace(task.ScopeID) == "" || len(task.ScopeID) > 128 ||
		strings.TrimSpace(task.CreatedBy) == "" || len(task.CreatedBy) > 128 ||
		(task.Status != "PENDING" && task.Status != "WAITING_WINDOW") ||
		len(task.Engines) == 0 || len(task.Engines) > 16 || len(task.Targets) == 0 || len(task.Targets) > 65535 {
		return false
	}
	if !task.HardDeadline.IsZero() && !task.HardDeadline.After(time.Now().UTC()) {
		return false
	}
	for _, value := range task.Engines {
		if strings.TrimSpace(value) == "" || len(value) > 1024 || strings.ContainsAny(value, "\x00\r\n") {
			return false
		}
	}
	for _, target := range task.Targets {
		if !validPostgresTarget(target) {
			return false
		}
	}
	return true
}

func validPostgresTarget(raw string) bool {
	host, portText, err := net.SplitHostPort(strings.TrimSpace(raw))
	if err != nil || host == "" || portText == "" {
		return false
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || ip.IsUnspecified() || ip.IsMulticast() || ip.Zone() != "" {
		return false
	}
	port, err := strconv.Atoi(portText)
	return err == nil && port >= 1 && port <= 65535
}

func (s *PostgresTaskStore) ClaimChunk(ctx context.Context, worker string) (TaskChunk, error) {
	if s == nil || s.db == nil || strings.TrimSpace(worker) == "" || len(worker) > 128 {
		return TaskChunk{}, ErrPostgresTaskInvalid
	}
	leaseDuration := s.leaseDuration
	if leaseDuration <= 0 {
		leaseDuration = defaultPostgresLeaseDuration
	}
	now := time.Now
	if s.now != nil {
		now = s.now
	}
	leaseUntil := now().UTC().Add(leaseDuration)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return TaskChunk{}, fmt.Errorf("begin postgres claim: %w", err)
	}
	defer tx.Rollback()
	var chunk TaskChunk
	var targets string
	var lease sql.NullTime
	var hardDeadline sql.NullTime
	err = tx.QueryRowContext(ctx, `SELECT c.id,c.task_id,c.status,
		COALESCE(c.worker_node_id,''),COALESCE(c.pinned_rule_version,''),
		c.targets,c.lease_expires_at,c.completed_fully,t.hard_deadline
		FROM scan_task_chunks c
		JOIN scan_tasks t ON t.id=c.task_id
		WHERE c.status='PENDING'
		  AND (c.lease_expires_at IS NULL OR c.lease_expires_at <= CURRENT_TIMESTAMP)
		  AND (t.hard_deadline IS NULL OR t.hard_deadline > CURRENT_TIMESTAMP)
		ORDER BY t.created_at,c.id
		LIMIT 1 FOR UPDATE OF c,t SKIP LOCKED`).Scan(
		&chunk.ID, &chunk.TaskID, &chunk.Status, &chunk.WorkerNodeID,
		&chunk.PinnedRuleVersion, &targets, &lease, &chunk.CompletedFully, &hardDeadline)
	if errors.Is(err, sql.ErrNoRows) {
		return TaskChunk{}, ErrPostgresTaskUnavailable
	}
	if err != nil {
		return TaskChunk{}, fmt.Errorf("select postgres task chunk: %w", err)
	}
	if err := json.Unmarshal([]byte(targets), &chunk.Targets); err != nil {
		return TaskChunk{}, fmt.Errorf("decode postgres task targets: %w", err)
	}
	if hardDeadline.Valid && hardDeadline.Time.Before(leaseUntil) {
		leaseUntil = hardDeadline.Time.UTC()
	}
	if !leaseUntil.After(now().UTC()) {
		return TaskChunk{}, ErrPostgresTaskUnavailable
	}
	if _, err := tx.ExecContext(ctx, `UPDATE scan_task_chunks
		SET status='RUNNING',worker_node_id=$1,lease_expires_at=$2,
			started_at=COALESCE(started_at,CURRENT_TIMESTAMP)
		WHERE id=$3`, worker, leaseUntil, chunk.ID); err != nil {
		return TaskChunk{}, fmt.Errorf("claim postgres task chunk: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE scan_tasks SET status='RUNNING'
		WHERE id=$1 AND status IN ('PENDING','WAITING_WINDOW')`, chunk.TaskID); err != nil {
		return TaskChunk{}, fmt.Errorf("mark postgres task running: %w", err)
	}
	chunk.Status = "RUNNING"
	chunk.WorkerNodeID = worker
	chunk.LeaseExpiresAt = leaseUntil
	if err := tx.Commit(); err != nil {
		return TaskChunk{}, fmt.Errorf("commit postgres claim: %w", err)
	}
	return chunk, nil
}

func (s *PostgresTaskStore) CompleteChunk(ctx context.Context, chunkID string, completedFully bool) error {
	if s == nil || s.db == nil || strings.TrimSpace(chunkID) == "" || len(chunkID) > 160 {
		return ErrPostgresTaskInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin postgres completion: %w", err)
	}
	defer tx.Rollback()
	var taskID string
	if err := tx.QueryRowContext(ctx, `UPDATE scan_task_chunks
		SET status=$1,completed_fully=$2,lease_expires_at=NULL,finished_at=CURRENT_TIMESTAMP
		WHERE id=$3 AND status='RUNNING'
		RETURNING task_id`, map[bool]string{true: "COMPLETED", false: "FAILED"}[completedFully], completedFully, chunkID).Scan(&taskID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrPostgresTaskUnavailable
		}
		return fmt.Errorf("complete postgres task chunk: %w", err)
	}
	if completedFully {
		if _, err := tx.ExecContext(ctx, `UPDATE scan_tasks t SET status='COMPLETED'
			WHERE t.id=$1 AND NOT EXISTS (
				SELECT 1 FROM scan_task_chunks c
				WHERE c.task_id=t.id AND c.status<>'COMPLETED'
			)`, taskID); err != nil {
			return fmt.Errorf("complete postgres task: %w", err)
		}
	} else if _, err := tx.ExecContext(ctx, `UPDATE scan_tasks SET status='FAILED' WHERE id=$1`, taskID); err != nil {
		return fmt.Errorf("fail postgres task: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit postgres completion: %w", err)
	}
	return nil
}

func (s *PostgresTaskStore) RenewChunkLease(ctx context.Context, chunkID, worker, ruleVersion string) (time.Time, error) {
	if s == nil || s.db == nil || strings.TrimSpace(chunkID) == "" || strings.TrimSpace(worker) == "" || len(chunkID) > 160 || len(worker) > 128 || len(ruleVersion) > 256 {
		return time.Time{}, ErrPostgresTaskInvalid
	}
	leaseDuration := s.leaseDuration
	if leaseDuration <= 0 {
		leaseDuration = defaultPostgresLeaseDuration
	}
	now := time.Now
	if s.now != nil {
		now = s.now
	}
	candidate := now().UTC().Add(leaseDuration)
	var expires time.Time
	err := s.db.QueryRowContext(ctx, `UPDATE scan_task_chunks c
		SET lease_expires_at=CASE WHEN t.hard_deadline IS NULL THEN $1
			ELSE LEAST($1,t.hard_deadline) END
		FROM scan_tasks t
		WHERE c.id=$2 AND c.task_id=t.id AND c.status='RUNNING'
		  AND c.worker_node_id=$3 AND c.pinned_rule_version=$4
		  AND c.lease_expires_at>CURRENT_TIMESTAMP
		  AND (t.hard_deadline IS NULL OR t.hard_deadline>CURRENT_TIMESTAMP)
		RETURNING c.lease_expires_at`, candidate, chunkID, worker, ruleVersion).Scan(&expires)
	if errors.Is(err, sql.ErrNoRows) {
		return time.Time{}, ErrPostgresTaskUnavailable
	}
	if err != nil {
		return time.Time{}, fmt.Errorf("renew postgres task lease: %w", err)
	}
	return expires.UTC(), nil
}

func (s *PostgresTaskStore) CountRunningByVersion(ctx context.Context, ruleVersion, worker string) (int, error) {
	if s == nil || s.db == nil || strings.TrimSpace(ruleVersion) == "" || strings.TrimSpace(worker) == "" {
		return 0, ErrPostgresTaskInvalid
	}
	var count int
	if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM scan_task_chunks
		WHERE status='RUNNING' AND pinned_rule_version=$1 AND worker_node_id=$2`, ruleVersion, worker).Scan(&count); err != nil {
		return 0, fmt.Errorf("count postgres running chunks: %w", err)
	}
	return count, nil
}
