package repo

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"scanner-platform/internal/assets"
	"scanner-platform/internal/scheduler"
	"scanner-platform/internal/taskflow"

	_ "modernc.org/sqlite"
)

var ErrTaskConflict = errors.New("task is not running for this worker")

// RuntimeRepository is owned exclusively by Server. Workers use the HTTP API.
type RuntimeRepository interface {
	CreateSyntheticTask(context.Context) (taskflow.Task, error)
	ListRuntimeTasks(context.Context) ([]taskflow.Task, error)
	ClaimRuntimeTask(context.Context, string) (*taskflow.Task, error)
	CompleteRuntimeTask(context.Context, taskflow.Report) error
	ListRuntimeFindings(context.Context) ([]taskflow.Finding, error)
}

type RuntimeStore struct {
	db     *sql.DB
	ownsDB bool
}

func OpenRuntime(path string) (*RuntimeStore, error) {
	if path == "" {
		return nil, fmt.Errorf("database path is required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, fmt.Errorf("create database directory: %w", err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open task database: %w", err)
	}
	db.SetMaxOpenConns(1)
	store, err := NewRuntime(db)
	if err != nil {
		db.Close()
		return nil, err
	}
	store.ownsDB = true
	return store, nil
}

func NewRuntime(db *sql.DB) (*RuntimeStore, error) {
	if _, err := assets.New(db); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, statement := range []string{
		`PRAGMA busy_timeout=5000`,
		`PRAGMA foreign_keys=ON`,
		`PRAGMA journal_mode=WAL`,
		`CREATE TABLE IF NOT EXISTS scan_tasks (
			id TEXT PRIMARY KEY, status TEXT NOT NULL,
			worker_id TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL,
			started_at TEXT, finished_at TEXT, targets TEXT NOT NULL)`,
		`CREATE INDEX IF NOT EXISTS runtime_task_queue ON scan_tasks(status,created_at,id)`,
		`CREATE TABLE IF NOT EXISTS security_findings (
			id TEXT PRIMARY KEY, task_id TEXT NOT NULL UNIQUE REFERENCES scan_tasks(id),
			data TEXT NOT NULL)`,
	} {
		if _, err := db.ExecContext(ctx, statement); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("initialize task database: %w", err)
		}
	}
	store := &RuntimeStore{db: db}
	if err := store.migrateFindings(ctx); err != nil {
		return nil, err
	}
	if err := store.initLocal(ctx); err != nil {
		return nil, fmt.Errorf("initialize local task features: %w", err)
	}
	return store, nil
}

func (s *RuntimeStore) Close() error {
	if s.ownsDB {
		return s.db.Close()
	}
	return nil
}

func (s *RuntimeStore) CreateSyntheticTask(ctx context.Context) (taskflow.Task, error) {
	return s.createRuntimeTask(ctx, "task-"+rand.Text(), []string{"192.0.2.10:8080"})
}

// SeedSyntheticTask creates at most one startup task per database.
func (s *RuntimeStore) SeedSyntheticTask(ctx context.Context) error {
	_, err := s.createRuntimeTask(ctx, "framework-demo", []string{"192.0.2.10:8080"})
	return err
}

func (s *RuntimeStore) createRuntimeTask(ctx context.Context, id string, targets []string) (taskflow.Task, error) {
	encoded, err := json.Marshal(targets)
	if err != nil {
		return taskflow.Task{}, fmt.Errorf("encode targets: %w", err)
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO scan_tasks(id,status,created_at,targets)
		VALUES (?,'PENDING',?,?) ON CONFLICT(id) DO NOTHING`, id, time.Now().UTC().Format(time.RFC3339Nano), string(encoded))
	if err != nil {
		return taskflow.Task{}, fmt.Errorf("create task: %w", err)
	}
	return readRuntimeTask(s.db.QueryRowContext(ctx, `SELECT `+taskColumns+` FROM scan_tasks WHERE id=?`, id))
}

const taskColumns = `id,status,worker_id,created_at,started_at,finished_at,targets,details`

type rowScanner interface{ Scan(...any) error }

func readRuntimeTask(row rowScanner) (taskflow.Task, error) {
	var task taskflow.Task
	var worker, created, targets, details string
	var started, finished sql.NullString
	if err := row.Scan(&task.ID, &task.Status, &worker, &created, &started, &finished, &targets, &details); err != nil {
		return taskflow.Task{}, fmt.Errorf("read task: %w", err)
	}
	var err error
	if task.CreatedAt, err = time.Parse(time.RFC3339Nano, created); err != nil {
		return taskflow.Task{}, fmt.Errorf("parse task creation time: %w", err)
	}
	chunk := taskflow.Chunk{ID: task.ID + "-chunk", TaskID: task.ID, WorkerNodeID: worker, Status: task.Status}
	if err := json.Unmarshal([]byte(targets), &chunk.Targets); err != nil {
		return taskflow.Task{}, fmt.Errorf("decode task targets: %w", err)
	}
	for _, item := range []struct {
		value sql.NullString
		field **time.Time
	}{{started, &chunk.StartedAt}, {finished, &chunk.FinishedAt}} {
		if item.value.Valid {
			parsed, err := time.Parse(time.RFC3339Nano, item.value.String)
			if err != nil {
				return taskflow.Task{}, fmt.Errorf("parse task execution time: %w", err)
			}
			*item.field = &parsed
		}
	}
	task.Synthetic, task.ScopeName, task.Engines = true, "模拟任务（不连接目标）", []string{"synthetic"}
	task.TotalChunks, task.TargetCount = 1, len(chunk.Targets)
	if task.Status == "COMPLETED" {
		task.CompletedChunks, chunk.CompletedFully = 1, true
	}
	task.Chunks = []taskflow.Chunk{chunk}
	var detail taskDetails
	if err := json.Unmarshal([]byte(details), &detail); err != nil {
		return taskflow.Task{}, err
	}
	task.HardDeadline = detail.Deadline
	task.SkippedTargets = detail.Skipped
	task.TimeWindows = detail.Input.TimeWindows
	if task.TimeWindows == nil {
		task.TimeWindows = []scheduler.Window{}
	}
	task.RuleVersion = detail.RuleVersion
	task.Error = detail.Error
	task.InputPath, task.InputKind, task.Scheme = detail.Input.InputPath, detail.Input.InputKind, detail.Input.Scheme
	if detail.Input.Engine != "" && detail.Input.Engine != "synthetic" {
		task.Synthetic = false
		task.Engines = []string{detail.Input.Engine}
		task.ScopeName = "显式目标扫描"
	}
	if task.SkippedTargets == nil {
		task.SkippedTargets = []string{}
	}
	return task, nil
}

func (s *RuntimeStore) ListRuntimeTasks(ctx context.Context) ([]taskflow.Task, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+taskColumns+` FROM scan_tasks ORDER BY created_at DESC,id`)
	if err != nil {
		return nil, fmt.Errorf("list tasks: %w", err)
	}
	defer rows.Close()
	items := []taskflow.Task{}
	for rows.Next() {
		item, err := readRuntimeTask(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *RuntimeStore) ClaimRuntimeTask(ctx context.Context, worker string) (*taskflow.Task, error) {
	for attempt := 0; attempt < 10; attempt++ {
		task, err := s.claimRuntimeTask(ctx, worker)
		var sqliteErr interface{ Code() int }
		if err == nil || !errors.As(err, &sqliteErr) || sqliteErr.Code()&255 != 5 {
			return task, err
		}
		timer := time.NewTimer(time.Duration(attempt+1) * 10 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
	return nil, fmt.Errorf("claim queue remained busy")
}

func (s *RuntimeStore) claimRuntimeTask(ctx context.Context, worker string) (*taskflow.Task, error) {
	// Check each queued task against its persisted window immediately before dispatch.
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	for {
		var id, data string
		err = tx.QueryRowContext(ctx, `SELECT id,details FROM scan_tasks WHERE status='PENDING' ORDER BY created_at,id LIMIT 1`).Scan(&id, &data)
		if errors.Is(err, sql.ErrNoRows) {
			return nil, tx.Commit()
		}
		if err != nil {
			return nil, err
		}
		var detail taskDetails
		if err := json.Unmarshal([]byte(data), &detail); err != nil {
			return nil, err
		}
		if len(detail.Input.Targets) > 0 || detail.Input.Engine == "trivy" {
			targets, fresh, err := resolveTargets(ctx, tx, detail.Input)
			if errors.Is(err, ErrInvalidTask) {
				if _, err := tx.ExecContext(ctx, "UPDATE scan_tasks SET status='CANCELED' WHERE id=?", id); err != nil {
					return nil, err
				}
				if err := logLocal(ctx, tx, "local-server", "cancel_changed_targets", "task", id, "登记目标或跳过标记已变化，请重新创建任务"); err != nil {
					return nil, err
				}
				continue
			}
			if err != nil {
				return nil, err
			}
			fresh.RuleVersion = detail.RuleVersion
			detail = fresh
			encoded, _ := json.Marshal(targets)
			if _, err := tx.ExecContext(ctx, "UPDATE scan_tasks SET targets=? WHERE id=?", string(encoded), id); err != nil {
				return nil, err
			}
		}
		deadline, allowed, err := scheduler.AllowedUntil(detail.Input.TimeWindows, time.Now())
		if err != nil {
			return nil, err
		}
		if !allowed {
			if _, err := tx.ExecContext(ctx, "UPDATE scan_tasks SET status='WAITING_WINDOW' WHERE id=?", id); err != nil {
				return nil, err
			}
			continue
		}
		detail.Deadline = deadline.UTC().Format(time.RFC3339Nano)
		encoded, _ := json.Marshal(detail)
		if _, err := tx.ExecContext(ctx, "UPDATE scan_tasks SET details=? WHERE id=?", string(encoded), id); err != nil {
			return nil, err
		}
		break
	}
	task, err := readRuntimeTask(tx.QueryRowContext(ctx, `UPDATE scan_tasks SET status='RUNNING',worker_id=?,started_at=?
		WHERE id=(SELECT id FROM scan_tasks WHERE status='PENDING' ORDER BY created_at,id LIMIT 1)
		AND status='PENDING' RETURNING `+taskColumns, worker, time.Now().UTC().Format(time.RFC3339Nano)))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("claim task: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &task, nil
}

func (s *RuntimeStore) CompleteRuntimeTask(ctx context.Context, report taskflow.Report) error {
	if report.Status == "FAILED" || report.Status == "COMPLETED" {
		return s.completeEngineTask(ctx, report)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin task completion: %w", err)
	}
	defer tx.Rollback()
	task, err := readRuntimeTask(tx.QueryRowContext(ctx, `SELECT `+taskColumns+` FROM scan_tasks WHERE id=?`, report.TaskID))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrTaskConflict
		}
		return err
	}
	chunk := task.Chunks[0]
	if task.Status == "RUNNING" && chunk.WorkerNodeID == report.WorkerID && report.Status == "PAUSED_WINDOW" {
		if _, err := tx.ExecContext(ctx, "UPDATE scan_tasks SET status='PAUSED_WINDOW',worker_id='' WHERE id=?", task.ID); err != nil {
			return err
		}
		return tx.Commit()
	}
	if chunk.WorkerNodeID != report.WorkerID || len(chunk.Targets) == 0 || report.Target != chunk.Targets[0] || report.Title != taskflow.SyntheticTitle {
		return ErrTaskConflict
	}
	if task.Status == "COMPLETED" {
		return nil // Retried reports cannot create duplicate findings.
	}
	if task.Status != "RUNNING" {
		return ErrTaskConflict
	}
	if task.HardDeadline != "" {
		deadline, err := time.Parse(time.RFC3339Nano, task.HardDeadline)
		if err != nil {
			return err
		}
		if !time.Now().Before(deadline) {
			if _, err := tx.ExecContext(ctx, "UPDATE scan_tasks SET status='PAUSED_WINDOW',worker_id='' WHERE id=?", task.ID); err != nil {
				return err
			}
			if err := tx.Commit(); err != nil {
				return err
			}
			return ErrTaskConflict
		}
	}
	now := time.Now().UTC()
	finding := taskflow.Finding{
		ID: "finding-" + task.ID, TaskID: task.ID, Fingerprint: "synthetic-" + task.ID,
		Severity: "INFO", Title: taskflow.SyntheticTitle, Engine: "synthetic", TemplateOrCVE: "framework-check",
		Target: report.Target, Status: "OPEN", FirstSeen: now, LastSeen: now, Synthetic: true,
	}
	var rawDetails string
	if err := tx.QueryRowContext(ctx, "SELECT details FROM scan_tasks WHERE id=?", task.ID).Scan(&rawDetails); err != nil {
		return err
	}
	var detail taskDetails
	if err := json.Unmarshal([]byte(rawDetails), &detail); err != nil {
		return err
	}
	owner := detail.Owners[report.Target]
	finding.BusinessGroup = owner.Group
	finding.Owner = owner.Owner
	data, err := json.Marshal(finding)
	if err != nil {
		return fmt.Errorf("encode finding: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO security_findings(id,task_id,data) VALUES (?,?,?)`, finding.ID, task.ID, string(data)); err != nil {
		return fmt.Errorf("save finding: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE scan_tasks SET status='COMPLETED',finished_at=? WHERE id=?`, now.Format(time.RFC3339Nano), task.ID); err != nil {
		return fmt.Errorf("complete task: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit task result: %w", err)
	}
	return nil
}

func (s *RuntimeStore) ListRuntimeFindings(ctx context.Context) ([]taskflow.Finding, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT data FROM security_findings ORDER BY rowid DESC`)
	if err != nil {
		return nil, fmt.Errorf("list findings: %w", err)
	}
	defer rows.Close()
	items := []taskflow.Finding{}
	for rows.Next() {
		var data string
		var finding taskflow.Finding
		if err := rows.Scan(&data); err != nil {
			return nil, fmt.Errorf("read finding: %w", err)
		}
		if err := json.Unmarshal([]byte(data), &finding); err != nil {
			return nil, fmt.Errorf("decode finding: %w", err)
		}
		items = append(items, finding)
	}
	return items, rows.Err()
}
