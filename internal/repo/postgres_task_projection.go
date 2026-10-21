package repo

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"scanner-platform/internal/taskflow"
)

var (
	ErrPostgresProjectionInvalid = errors.New("invalid postgres task projection")
	ErrPostgresProjectionMissing = errors.New("postgres task projection is missing")
)

// PostgresTaskProjection persists the Server-owned fields that are needed to
// render a task and its advisory progress. Queue status, leases and targets
// are deliberately read from scan_tasks/scan_task_chunks instead of trusting
// the JSON projection.
type PostgresTaskProjection struct {
	db  *sql.DB
	now func() time.Time
}

func NewPostgresTaskProjection(db *sql.DB) (*PostgresTaskProjection, error) {
	if db == nil {
		return nil, ErrPostgresDSNRequired
	}
	return &PostgresTaskProjection{db: db, now: time.Now}, nil
}

// Save stores a bounded JSON projection. It is intentionally separate from
// the queue mutation so callers can include it in their own transaction when
// creating or completing a task.
func (s *PostgresTaskProjection) Save(ctx context.Context, task taskflow.Task) error {
	if s == nil || s.db == nil || !validPostgresProjectionTask(task) {
		return ErrPostgresProjectionInvalid
	}
	data, err := json.Marshal(task)
	if err != nil {
		return fmt.Errorf("encode postgres task projection: %w", err)
	}
	if len(data) > taskflow.MaxReportBytes {
		return ErrPostgresProjectionInvalid
	}
	now := s.currentTime()
	if _, err := s.db.ExecContext(ctx, `INSERT INTO scan_task_projections
		(task_id,data,fixed_threshold,fixed_threshold_frozen,updated_at) VALUES ($1,$2,$3,TRUE,$4)
		ON CONFLICT(task_id) DO UPDATE SET data=EXCLUDED.data,
		fixed_threshold=CASE WHEN scan_task_projections.fixed_threshold_frozen
			THEN scan_task_projections.fixed_threshold ELSE EXCLUDED.fixed_threshold END,
		updated_at=EXCLUDED.updated_at`,
		task.ID, string(data), projectionFixedThreshold(task), now); err != nil {
		return fmt.Errorf("save postgres task projection: %w", err)
	}
	return nil
}

// SaveTx is the transaction form used by Server-side queue adapters.
func (s *PostgresTaskProjection) SaveTx(ctx context.Context, tx *sql.Tx, task taskflow.Task) error {
	if s == nil || tx == nil || !validPostgresProjectionTask(task) {
		return ErrPostgresProjectionInvalid
	}
	data, err := json.Marshal(task)
	if err != nil {
		return fmt.Errorf("encode postgres task projection: %w", err)
	}
	if len(data) > taskflow.MaxReportBytes {
		return ErrPostgresProjectionInvalid
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO scan_task_projections
		(task_id,data,fixed_threshold,fixed_threshold_frozen,updated_at) VALUES ($1,$2,$3,TRUE,$4)
		ON CONFLICT(task_id) DO UPDATE SET data=EXCLUDED.data,
		fixed_threshold=CASE WHEN scan_task_projections.fixed_threshold_frozen
			THEN scan_task_projections.fixed_threshold ELSE EXCLUDED.fixed_threshold END,
		updated_at=EXCLUDED.updated_at`,
		task.ID, string(data), projectionFixedThreshold(task), s.currentTime()); err != nil {
		return fmt.Errorf("save postgres task projection: %w", err)
	}
	return nil
}

func projectionFixedThreshold(task taskflow.Task) int {
	if task.FixedThreshold < 1 {
		return 1
	}
	if task.FixedThreshold > 3 {
		return 3
	}
	return task.FixedThreshold
}

func validPostgresProjectionTask(task taskflow.Task) bool {
	if strings.TrimSpace(task.ID) == "" || len(task.ID) > 128 ||
		strings.ContainsAny(task.ID, "\x00\r\n") || task.TargetCount < 0 ||
		task.TotalChunks < 0 || task.CompletedChunks < 0 || task.CompletedChunks > task.TotalChunks {
		return false
	}
	return task.Status == "" || validPostgresProjectionStatus(task.Status)
}

func validPostgresProjectionStatus(status string) bool {
	switch status {
	case "PENDING", "WAITING_WINDOW", "RUNNING", "PAUSED_WINDOW", "PAUSED", "COMPLETED", "FAILED", "CANCELED":
		return true
	default:
		return false
	}
}

func (s *PostgresTaskProjection) currentTime() time.Time {
	if s.now != nil {
		return s.now().UTC()
	}
	return time.Now().UTC()
}

// Get reconstructs a task using normalized queue state for status, chunks and
// deadlines, and the projection for the remaining Server-owned fields.
func (s *PostgresTaskProjection) Get(ctx context.Context, id string) (taskflow.Task, error) {
	if s == nil || s.db == nil || strings.TrimSpace(id) == "" || len(id) > 128 {
		return taskflow.Task{}, ErrPostgresProjectionInvalid
	}
	var raw, scopeID, status, enginesRaw string
	var fixedThreshold int
	var fixedThresholdFrozen bool
	var createdAt time.Time
	var deadline, archivedAt sql.NullTime
	err := s.db.QueryRowContext(ctx, `SELECT p.data,p.fixed_threshold,p.fixed_threshold_frozen,t.scope_id,t.status,t.engines,
		t.created_at,t.hard_deadline,t.archived_at
		FROM scan_task_projections p JOIN scan_tasks t ON t.id=p.task_id
		WHERE p.task_id=$1`, id).Scan(&raw, &fixedThreshold, &fixedThresholdFrozen, &scopeID, &status, &enginesRaw,
		&createdAt, &deadline, &archivedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return taskflow.Task{}, ErrPostgresProjectionMissing
	}
	if err != nil {
		return taskflow.Task{}, fmt.Errorf("read postgres task projection: %w", err)
	}
	var task taskflow.Task
	if err := json.Unmarshal([]byte(raw), &task); err != nil {
		return taskflow.Task{}, fmt.Errorf("decode postgres task projection: %w", err)
	}
	var engines []string
	if err := json.Unmarshal([]byte(enginesRaw), &engines); err != nil {
		return taskflow.Task{}, fmt.Errorf("decode postgres task engines: %w", err)
	}
	task.ID, task.ScopeID, task.Status, task.Engines = id, scopeID, status, engines
	if fixedThresholdFrozen {
		task.FixedThreshold = fixedThreshold
		if task.FixedThreshold < 1 {
			task.FixedThreshold = 1
		}
	} else {
		task.FixedThreshold = 0
	}
	task.CreatedAt = createdAt.UTC()
	task.Archived = archivedAt.Valid
	task.HardDeadline = ""
	if deadline.Valid {
		task.HardDeadline = deadline.Time.UTC().Format(time.RFC3339Nano)
	}
	chunks, err := s.readChunks(ctx, id)
	if err != nil {
		return taskflow.Task{}, err
	}
	task.Chunks = chunks
	task.TotalChunks = len(chunks)
	task.CompletedChunks = 0
	task.TargetCount = 0
	for _, chunk := range chunks {
		task.TargetCount += len(chunk.Targets)
		if chunk.Status == "COMPLETED" {
			task.CompletedChunks++
		}
	}
	progress, err := s.readProgress(ctx, id)
	if err != nil {
		return taskflow.Task{}, err
	}
	task.Progress = progress
	return task, nil
}

func (s *PostgresTaskProjection) readChunks(ctx context.Context, taskID string) ([]taskflow.Chunk, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,task_id,status,
		COALESCE(worker_node_id,''),COALESCE(pinned_rule_version,''),targets,
		lease_expires_at,completed_fully,started_at,finished_at
		FROM scan_task_chunks WHERE task_id=$1 ORDER BY id`, taskID)
	if err != nil {
		return nil, fmt.Errorf("list postgres task chunks: %w", err)
	}
	defer rows.Close()
	chunks := make([]taskflow.Chunk, 0)
	for rows.Next() {
		var chunk taskflow.Chunk
		var targets string
		var lease, started, finished sql.NullTime
		if err := rows.Scan(&chunk.ID, &chunk.TaskID, &chunk.Status,
			&chunk.WorkerNodeID, &chunk.PinnedRuleVersion, &targets, &lease,
			&chunk.CompletedFully, &started, &finished); err != nil {
			return nil, fmt.Errorf("scan postgres task chunk: %w", err)
		}
		if err := json.Unmarshal([]byte(targets), &chunk.Targets); err != nil {
			return nil, fmt.Errorf("decode postgres task chunk: %w", err)
		}
		if lease.Valid {
			value := lease.Time.UTC()
			chunk.LeaseExpiresAt = &value
		}
		if started.Valid {
			value := started.Time.UTC()
			chunk.StartedAt = &value
		}
		if finished.Valid {
			value := finished.Time.UTC()
			chunk.FinishedAt = &value
		}
		chunks = append(chunks, chunk)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate postgres task chunks: %w", err)
	}
	return chunks, nil
}

func (s *PostgresTaskProjection) readProgress(ctx context.Context, taskID string) (*taskflow.TaskProgress, error) {
	var phase, worker string
	var completed, total int
	var updatedAt time.Time
	err := s.db.QueryRowContext(ctx, `SELECT phase,worker_id,completed,total,updated_at
		FROM scan_task_progress WHERE task_id=$1`, taskID).Scan(&phase, &worker,
		&completed, &total, &updatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read postgres task progress: %w", err)
	}
	_ = worker // ownership is checked when progress is written, not exposed.
	return &taskflow.TaskProgress{Phase: phase, Completed: completed, Total: total, UpdatedAt: updatedAt.UTC()}, nil
}

// SaveProgress accepts only progress for the Worker currently holding the
// normalized running chunk. It never changes queue status or authorization.
func (s *PostgresTaskProjection) SaveProgress(ctx context.Context, worker string, update taskflow.ProgressUpdate) error {
	if s == nil || s.db == nil || !validPostgresProgressIdentity(worker, update) {
		return ErrPostgresProjectionInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin postgres task progress: %w", err)
	}
	defer tx.Rollback()
	var raw string
	var status string
	var owner string
	err = tx.QueryRowContext(ctx, `SELECT t.status,c.worker_node_id,p.data
		FROM scan_tasks t
		JOIN scan_task_chunks c ON c.task_id=t.id AND c.status='RUNNING'
		JOIN scan_task_projections p ON p.task_id=t.id
		WHERE t.id=$1 AND c.worker_node_id=$2
		FOR UPDATE OF c,p`, update.TaskID, worker).Scan(&status, &owner, &raw)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrTaskConflict
	}
	if err != nil {
		return fmt.Errorf("read postgres task progress owner: %w", err)
	}
	if status != "RUNNING" || owner != worker {
		return ErrTaskConflict
	}
	var task taskflow.Task
	if err := json.Unmarshal([]byte(raw), &task); err != nil {
		return fmt.Errorf("decode postgres task progress metadata: %w", err)
	}
	engine := ""
	if len(task.Engines) == 1 {
		engine = task.Engines[0]
	}
	if !validRuntimeTaskProgress(engine, len(task.PortProbePorts), update) {
		return ErrPostgresProjectionInvalid
	}
	var oldWorker, oldPhase string
	var oldCompleted, oldTotal int
	readErr := tx.QueryRowContext(ctx, `SELECT worker_id,phase,completed,total
		FROM scan_task_progress WHERE task_id=$1 FOR UPDATE`, update.TaskID).Scan(
		&oldWorker, &oldPhase, &oldCompleted, &oldTotal)
	if readErr != nil && !errors.Is(readErr, sql.ErrNoRows) {
		return fmt.Errorf("read previous postgres task progress: %w", readErr)
	}
	if readErr == nil && oldWorker == worker {
		oldRank := runtimeProgressRank(engine, oldPhase)
		newRank := runtimeProgressRank(engine, update.Phase)
		if newRank < oldRank || update.Phase == oldPhase &&
			(update.Completed < oldCompleted || update.Total != oldTotal) {
			return ErrPostgresProjectionInvalid
		}
	}
	now := s.currentTime()
	if _, err := tx.ExecContext(ctx, `INSERT INTO scan_task_progress
		(task_id,worker_id,phase,completed,total,updated_at)
		VALUES ($1,$2,$3,$4,$5,$6)
		ON CONFLICT(task_id) DO UPDATE SET worker_id=EXCLUDED.worker_id,
		phase=EXCLUDED.phase,completed=EXCLUDED.completed,total=EXCLUDED.total,
		updated_at=EXCLUDED.updated_at`, update.TaskID, worker, update.Phase,
		update.Completed, update.Total, now); err != nil {
		return fmt.Errorf("save postgres task progress: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit postgres task progress: %w", err)
	}
	return nil
}

func validPostgresProgressIdentity(worker string, update taskflow.ProgressUpdate) bool {
	return strings.TrimSpace(worker) != "" && len(worker) <= 128 &&
		strings.TrimSpace(update.TaskID) != "" && len(update.TaskID) <= 128 &&
		update.Completed >= 0 && update.Total >= update.Completed && update.Total <= 65535 &&
		len(update.Phase) > 0 && len(update.Phase) <= 64 &&
		!strings.ContainsAny(worker+update.TaskID+update.Phase, "\x00\r\n")
}
