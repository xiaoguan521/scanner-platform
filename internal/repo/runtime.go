package repo

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"scanner-platform/internal/assets"
	"scanner-platform/internal/findings"
	"scanner-platform/internal/scheduler"
	"scanner-platform/internal/taskflow"

	_ "modernc.org/sqlite"
)

var ErrTaskConflict = errors.New("task is not running for this worker")
var ErrTaskNotFound = errors.New("task not found")
var ErrTaskNotTerminal = errors.New("task is not terminal")
var ErrTaskHasFindings = errors.New("task has associated findings")
var ErrTaskLease = errors.New("task lease is invalid or expired")
var ErrTaskNotPausable = errors.New("task cannot be paused in its current state")
var ErrTaskNotResumable = errors.New("task is not manually paused")

// NoRuleLeaseVersion is used for real tasks that do not consume a rule
// directory (for example bounded TCP probing). They still receive a Server
// lease, but must never be mistaken for a GC-pinned rules version.
const NoRuleLeaseVersion = "__no_rules__"

// RuntimeRepository is owned exclusively by Server. Workers use the HTTP API.
type RuntimeRepository interface {
	CreateSyntheticTask(context.Context) (taskflow.Task, error)
	ListRuntimeTasks(context.Context) ([]taskflow.Task, error)
	GetRuntimeTask(context.Context, string) (taskflow.Task, error)
	ClaimRuntimeTask(context.Context, string) (*taskflow.Task, error)
	UpdateRuntimeTaskProgress(context.Context, string, taskflow.ProgressUpdate) error
	CompleteRuntimeTask(context.Context, taskflow.Report) error
	ListRuntimeFindings(context.Context) ([]taskflow.Finding, error)
}

type RuntimeStore struct {
	db                *sql.DB
	ownsDB            bool
	LeaseDuration     time.Duration
	findingExpiryMu   sync.Mutex
	nextFindingExpiry time.Time
}

// RuntimeMode lets diagnostics identify the portable SQLite backend explicitly.
func (s *RuntimeStore) RuntimeMode() string { return "sqlite" }

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
			started_at TEXT, finished_at TEXT, targets TEXT NOT NULL,
			pinned_rule_version TEXT NOT NULL DEFAULT '', lease_expires_at TEXT)`,
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
	if err := store.initFindingIndexes(ctx); err != nil {
		return nil, err
	}
	if err := store.initFindingWork(ctx); err != nil {
		return nil, err
	}
	if err := store.initFindingEvents(ctx); err != nil {
		return nil, err
	}
	if err := store.initFindingRetests(ctx); err != nil {
		return nil, err
	}
	if err := store.initLocal(ctx); err != nil {
		return nil, fmt.Errorf("initialize local task features: %w", err)
	}
	if err := store.initProduct(ctx); err != nil {
		return nil, err
	}
	if err := store.InitReports(ctx); err != nil {
		return nil, err
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

const taskColumns = `id,status,worker_id,created_at,started_at,finished_at,targets,details,pinned_rule_version,lease_expires_at`

type rowScanner interface{ Scan(...any) error }

func readRuntimeTask(row rowScanner) (taskflow.Task, error) {
	var task taskflow.Task
	var worker, created, targets, details, pinnedRuleVersion string
	var leaseExpiresAt sql.NullString
	var started, finished sql.NullString
	if err := row.Scan(&task.ID, &task.Status, &worker, &created, &started, &finished, &targets, &details, &pinnedRuleVersion, &leaseExpiresAt); err != nil {
		return taskflow.Task{}, fmt.Errorf("read task: %w", err)
	}
	var err error
	if task.CreatedAt, err = time.Parse(time.RFC3339Nano, created); err != nil {
		return taskflow.Task{}, fmt.Errorf("parse task creation time: %w", err)
	}
	chunk := taskflow.Chunk{ID: task.ID + "-chunk", TaskID: task.ID, WorkerNodeID: worker, Status: task.Status, PinnedRuleVersion: pinnedRuleVersion}
	if leaseExpiresAt.Valid && leaseExpiresAt.String != "" {
		parsed, err := time.Parse(time.RFC3339Nano, leaseExpiresAt.String)
		if err != nil {
			return taskflow.Task{}, fmt.Errorf("parse task lease expiration: %w", err)
		}
		chunk.LeaseExpiresAt = &parsed
	}
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
	task.Archived = detail.Archived
	task.SkippedTargets = detail.Skipped
	task.TimeWindows = detail.Input.TimeWindows
	if task.TimeWindows == nil {
		task.TimeWindows = []scheduler.Window{}
	}
	task.RuleVersion = detail.RuleVersion
	task.FixedThreshold = detail.FixedThreshold
	if task.FixedThreshold < 1 {
		task.FixedThreshold = defaultPolicy().FixedThreshold
	}
	task.Error = detail.Error
	task.InputPath, task.InputKind, task.Scheme = detail.Input.InputPath, detail.Input.InputKind, detail.Input.Scheme
	task.AssetID = detail.Input.AssetID
	task.PortProbeConfig = detail.Input.PortProbe
	task.PortProbePorts = detail.ProbePorts
	task.PortProbeResults = detail.ProbeResults
	task.VulnerabilityPorts = detail.VulnPorts
	task.ServiceResults = detail.Services
	task.SystemScanStatus = detail.SystemStatus
	task.ApplicationScanStatus = detail.ApplicationStatus
	task.ApplicationResults = detail.ApplicationResults
	task.FenceStatus = detail.FenceStatus
	task.DropCount = detail.DropCount
	task.RetestFindingID = detail.RetestFindingID
	task.AssetProfile = detail.AssetProfile
	task.EffectiveExclusions = detail.EffectiveExclusions
	for _, service := range detail.Services {
		if service.Quarantined {
			task.QuarantinedPorts = append(task.QuarantinedPorts, service.Port)
		}
	}
	task.CustomTemplates = make([]json.RawMessage, 0, len(detail.CustomRules))
	for _, template := range detail.CustomRules {
		task.CustomTemplates = append(task.CustomTemplates, json.RawMessage(template))
	}
	task.CustomRuleCount = len(detail.CustomRules)
	if detail.Input.Engine != "" && detail.Input.Engine != "synthetic" {
		task.Synthetic = false
		task.Engines = []string{detail.Input.Engine}
		task.ScopeName = "显式目标扫描"
		if detail.Input.Engine == "port-probe" {
			task.ScopeName = "单台资产 TCP 端口探测"
		} else if detail.Input.Engine == "auto" {
			task.ScopeName = "单台资产自动端口与 HTTP 漏洞检查"
		}
	}
	if task.SkippedTargets == nil {
		task.SkippedTargets = []string{}
	}
	return task, nil
}

func (s *RuntimeStore) ListRuntimeTasks(ctx context.Context) ([]taskflow.Task, error) {
	page, err := s.ListRuntimeTasksPage(ctx, TaskListQuery{Page: 1, Archived: "all"})
	if err != nil {
		return nil, err
	}
	return page.Items, nil
}

// GetRuntimeTask returns the same safe task projection as the task list, but
// for one task. It also attaches the current finding count and advisory
// Worker progress so a detail view never has to trust stale list data.
func (s *RuntimeStore) GetRuntimeTask(ctx context.Context, id string) (taskflow.Task, error) {
	if strings.TrimSpace(id) == "" || len(id) > 128 {
		return taskflow.Task{}, ErrTaskNotFound
	}
	task, err := readRuntimeTask(s.db.QueryRowContext(ctx, `SELECT `+taskColumns+` FROM scan_tasks WHERE id=?`, id))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return taskflow.Task{}, ErrTaskNotFound
		}
		return taskflow.Task{}, fmt.Errorf("read task detail: %w", err)
	}
	counts, err := s.runtimeTaskFindingCounts(ctx)
	if err != nil {
		return taskflow.Task{}, err
	}
	task.FindingCount = counts[id]
	progress, err := s.runtimeTaskProgress(ctx)
	if err != nil {
		return taskflow.Task{}, err
	}
	if current, ok := progress[id]; ok {
		task.Progress = &current
	}
	return task, nil
}

// ListRuntimeAssets exposes the server-owned asset projection to API
// aggregators without exposing the underlying database handle.
func (s *RuntimeStore) ListRuntimeAssets(ctx context.Context) ([]assets.Asset, error) {
	return assets.ListSnapshot(ctx, s.db)
}

func (s *RuntimeStore) runtimeTaskProgress(ctx context.Context) (map[string]taskflow.TaskProgress, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT task_id,phase,completed,total,updated_at,history FROM scan_task_progress`)
	if err != nil {
		return nil, fmt.Errorf("list task progress: %w", err)
	}
	defer rows.Close()
	progress := map[string]taskflow.TaskProgress{}
	for rows.Next() {
		var taskID, phase, updatedAt, history string
		var completed, total int
		if err := rows.Scan(&taskID, &phase, &completed, &total, &updatedAt, &history); err != nil {
			return nil, fmt.Errorf("read task progress: %w", err)
		}
		updated, err := time.Parse(time.RFC3339Nano, updatedAt)
		if err != nil {
			return nil, fmt.Errorf("parse task progress time: %w", err)
		}
		progress[taskID] = withLiveProgress(taskflow.TaskProgress{Phase: phase, Completed: completed, Total: total, UpdatedAt: updated}, history)
	}
	return progress, rows.Err()
}

// UpdateRuntimeTaskProgress persists advisory progress only for the Worker
// currently owning a running task. The progress never affects authorization.
func (s *RuntimeStore) UpdateRuntimeTaskProgress(ctx context.Context, worker string, update taskflow.ProgressUpdate) error {
	if update.TaskID == "" || len(update.TaskID) > 128 || worker == "" || len(worker) > 64 {
		return ErrInvalidTask
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin task progress update: %w", err)
	}
	defer tx.Rollback()
	var status, owner, rawDetails string
	err = tx.QueryRowContext(ctx, `SELECT status,worker_id,details FROM scan_tasks WHERE id=?`, update.TaskID).Scan(&status, &owner, &rawDetails)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrTaskConflict
		}
		return err
	}
	if status != "RUNNING" || owner != worker {
		return ErrTaskConflict
	}
	var detail struct {
		Input struct {
			Engine string `json:"engine"`
		} `json:"input"`
		ProbePorts json.RawMessage `json:"probePorts"`
	}
	if err := json.Unmarshal([]byte(rawDetails), &detail); err != nil {
		return fmt.Errorf("decode task progress metadata: %w", err)
	}
	portTotal := 0
	if detail.Input.Engine == "auto" || update.Phase == "tcp_probe" {
		portTotal, err = countJSONItems(detail.ProbePorts)
		if err != nil {
			return fmt.Errorf("count dispatched probe ports: %w", err)
		}
	}
	if !validRuntimeTaskProgress(detail.Input.Engine, portTotal, update) {
		return ErrInvalidTask
	}
	if len(update.OpenPorts) > 0 || len(update.HTTPPorts) > 0 {
		var dispatchedPorts []int
		if err := json.Unmarshal(detail.ProbePorts, &dispatchedPorts); err != nil {
			return ErrInvalidTask
		}
		dispatched := make(map[int]bool, len(dispatchedPorts))
		for _, port := range dispatchedPorts {
			dispatched[port] = true
		}
		if detail.Input.Engine != "auto" || !validLivePorts(update.OpenPorts, dispatched) || !validLivePorts(update.HTTPPorts, dispatched) {
			return ErrInvalidTask
		}
	}
	var oldWorker, oldPhase, oldHistory string
	var oldCompleted, oldTotal int
	readErr := tx.QueryRowContext(ctx, `SELECT worker_id,phase,completed,total,history FROM scan_task_progress WHERE task_id=?`, update.TaskID).Scan(&oldWorker, &oldPhase, &oldCompleted, &oldTotal, &oldHistory)
	if readErr != nil && !errors.Is(readErr, sql.ErrNoRows) {
		return fmt.Errorf("read previous task progress: %w", readErr)
	}
	if readErr == nil && oldWorker == worker {
		oldRank := runtimeProgressRank(detail.Input.Engine, oldPhase)
		newRank := runtimeProgressRank(detail.Input.Engine, update.Phase)
		if newRank < oldRank || update.Phase == oldPhase && (update.Completed < oldCompleted || update.Total != oldTotal) {
			return ErrInvalidTask
		}
	}
	baseHistory, basePhase := "", ""
	if readErr == nil && oldWorker == worker {
		baseHistory, basePhase = oldHistory, oldPhase
	}
	history := nextLiveProgress(baseHistory, basePhase, oldTotal, update)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := tx.ExecContext(ctx, `INSERT INTO scan_task_progress(task_id,worker_id,phase,completed,total,updated_at,history)
		VALUES (?,?,?,?,?,?,?) ON CONFLICT(task_id) DO UPDATE SET worker_id=excluded.worker_id,phase=excluded.phase,
		completed=excluded.completed,total=excluded.total,updated_at=excluded.updated_at,history=excluded.history`,
		update.TaskID, worker, update.Phase, update.Completed, update.Total, now, history); err != nil {
		return fmt.Errorf("save task progress: %w", err)
	}
	return tx.Commit()
}

func validRuntimeTaskProgress(engine string, portTotal int, update taskflow.ProgressUpdate) bool {
	if update.Completed < 0 || update.Total < 0 || update.Completed > update.Total {
		return false
	}
	switch update.Phase {
	case "tcp_probe":
		return (engine == "auto" || engine == "port-probe") && update.Total == portTotal && update.Total > 0
	case "service_identification", "http_scan", "ssh_collection", "trivy_scan":
		if engine != "auto" {
			return false
		}
		switch update.Phase {
		case "ssh_collection", "trivy_scan":
			return update.Total <= 1
		default:
			return update.Total <= portTotal
		}
	case "application_scan":
		return engine == "auto" && update.Total <= 256
	case "engine_scan":
		return (engine == "nuclei" || engine == "zap" || engine == "trivy") && update.Total <= 1
	default:
		return false
	}
}

func runtimeProgressRank(engine, phase string) int {
	switch engine {
	case "auto":
		return map[string]int{"tcp_probe": 1, "service_identification": 2, "http_scan": 3, "ssh_collection": 4, "trivy_scan": 5, "application_scan": 6}[phase]
	case "port-probe":
		if phase == "tcp_probe" {
			return 1
		}
	case "nuclei", "zap", "trivy":
		if phase == "engine_scan" {
			return 1
		}
	}
	return 0
}

func countJSONItems(raw json.RawMessage) (int, error) {
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return 0, nil
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('[') {
		return 0, fmt.Errorf("expected JSON array")
	}
	count := 0
	for decoder.More() {
		var value int
		if err := decoder.Decode(&value); err != nil {
			return 0, err
		}
		count++
	}
	if _, err := decoder.Token(); err != nil {
		return 0, err
	}
	return count, nil
}

func (s *RuntimeStore) runtimeTaskFindingCounts(ctx context.Context) (map[string]int, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT task_id,COUNT(*) FROM (
		SELECT task_id,finding_id FROM task_finding_observations
		UNION
		SELECT task_id,id FROM security_findings
	) GROUP BY task_id`)
	if err != nil {
		return nil, fmt.Errorf("count task findings: %w", err)
	}
	defer rows.Close()
	counts := map[string]int{}
	for rows.Next() {
		var taskID string
		var count int
		if err := rows.Scan(&taskID, &count); err != nil {
			return nil, err
		}
		counts[taskID] = count
	}
	return counts, rows.Err()
}

func (s *RuntimeStore) ClaimRuntimeTask(ctx context.Context, worker string) (*taskflow.Task, error) {
	return s.claimRuntimeTaskWithRules(ctx, worker, "", true, false)
}

// ClaimRuntimeTaskWithRules is used by a real Worker after it has read its
// local CURRENT pointer. Rule-backed tasks are left queued when the local
// version is missing or differs; no task is claimed and no fake scan failure
// is created. Port probes and passive ZAP tasks do not require a rule bundle.
func (s *RuntimeStore) ClaimRuntimeTaskWithRules(ctx context.Context, worker, localRuleVersion string, rulesReady bool) (*taskflow.Task, error) {
	return s.claimRuntimeTaskWithRules(ctx, worker, localRuleVersion, rulesReady, true)
}

func (s *RuntimeStore) claimRuntimeTaskWithRules(ctx context.Context, worker, localRuleVersion string, rulesReady, enforceRules bool) (*taskflow.Task, error) {
	for attempt := 0; attempt < 10; attempt++ {
		task, err := s.claimRuntimeTask(ctx, worker, localRuleVersion, rulesReady, enforceRules)
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

func (s *RuntimeStore) claimRuntimeTask(ctx context.Context, worker, localRuleVersion string, rulesReady, enforceRules bool) (*taskflow.Task, error) {
	// Check each queued task against its persisted window immediately before dispatch.
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	var claimedDetail taskDetails
	claimedID := ""
	skippedForRules := map[string]bool{}
	defer tx.Rollback()
	for {
		var id, data string
		query := `SELECT id,details FROM scan_tasks WHERE status='PENDING'`
		args := make([]any, 0, len(skippedForRules))
		if len(skippedForRules) > 0 {
			placeholders := make([]string, 0, len(skippedForRules))
			for id := range skippedForRules {
				placeholders = append(placeholders, "?")
				args = append(args, id)
			}
			query += " AND id NOT IN (" + strings.Join(placeholders, ",") + ")"
		}
		query += " ORDER BY created_at,id LIMIT 1"
		err = tx.QueryRowContext(ctx, query, args...).Scan(&id, &data)
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
		if enforceRules && requiresRuleBundle(detail.Input) &&
			(!rulesReady || localRuleVersion == "" || detail.RuleVersion == "" || detail.RuleVersion != localRuleVersion) {
			skippedForRules[id] = true
			continue
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
			if len(detail.ProbePorts) > 0 {
				old := map[int]bool{}
				for _, p := range detail.ProbePorts {
					old[p] = true
				}
				narrowed := []int{}
				for _, p := range fresh.ProbePorts {
					if old[p] {
						narrowed = append(narrowed, p)
					}
				}
				if len(narrowed) == 0 {
					if _, err := tx.ExecContext(ctx, "UPDATE scan_tasks SET status='CANCELED' WHERE id=?", id); err != nil {
						return nil, err
					}
					continue
				}
				fresh.ProbePorts = narrowed
				if detail.Input.Engine == "auto" {
					fresh.VulnPorts = append([]int{}, narrowed...)
				}
			}
			fresh.RuleVersion = detail.RuleVersion
			fresh.CustomRules = detail.CustomRules
			fresh.FixedThreshold = detail.FixedThreshold
			if fresh.FixedThreshold < 1 {
				fresh.FixedThreshold = defaultPolicy().FixedThreshold
			}
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
		claimedDetail = detail
		claimedID = id
		break
	}
	claimNow := time.Now().UTC()
	leaseVersion := ""
	var leaseExpiry any
	if !claimedDetail.Input.Synthetic {
		leaseVersion = claimedDetail.RuleVersion
		if leaseVersion == "" {
			leaseVersion = NoRuleLeaseVersion
		}
		deadline, err := taskDeadline(claimedDetail.Deadline)
		if err != nil {
			return nil, err
		}
		expires := claimNow.Add(s.leaseDuration())
		if !deadline.IsZero() && deadline.Before(expires) {
			expires = deadline
		}
		if !expires.After(claimNow) {
			return nil, ErrTaskLease
		}
		leaseExpiry = expires.Format(time.RFC3339Nano)
	}
	task, err := readRuntimeTask(tx.QueryRowContext(ctx, `UPDATE scan_tasks SET status='RUNNING',worker_id=?,started_at=?,pinned_rule_version=?,lease_expires_at=?
		WHERE id=? AND status='PENDING' RETURNING `+taskColumns, worker, claimNow.Format(time.RFC3339Nano), leaseVersion, leaseExpiry, claimedID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("claim task: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM scan_task_progress WHERE task_id=?`, task.ID); err != nil {
		return nil, fmt.Errorf("reset task progress: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &task, nil
}

func requiresRuleBundle(input taskflow.TaskInput) bool {
	return !input.Synthetic && input.Engine != "port-probe" && input.Engine != "zap"
}

func (s *RuntimeStore) CompleteRuntimeTask(ctx context.Context, report taskflow.Report) error {
	if err := validateFenceTelemetry(report); err != nil {
		return err
	}
	if err := s.ExpireAcceptedRisks(ctx, time.Now().UTC()); err != nil {
		return err
	}
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
		if err := validateTaskLease(task, report.WorkerID, time.Now().UTC()); err != nil {
			return err
		}
		if !validApplicationReport(report, len(task.Engines) == 1 && task.Engines[0] == "auto") {
			return ErrInvalidTask
		}
		if len(task.Engines) == 1 && task.Engines[0] == "auto" {
			if !validSystemScanStatus(report.SystemScanStatus) {
				return ErrInvalidTask
			}
			if err := persistAutoScanStatus(ctx, tx, task.ID, report); err != nil {
				return err
			}
		} else if report.SystemScanStatus != "" {
			return ErrInvalidTask
		}
		if err := persistFenceTelemetry(ctx, tx, task.ID, report); err != nil {
			return err
		}
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
	finding = findings.Upgrade(finding)
	assetID, _, ownerErr := resolveOwner(ctx, tx, finding.Target)
	if ownerErr != nil {
		return ownerErr
	}
	finding.AssetID = assetID
	data, err := json.Marshal(finding)
	if err != nil {
		return fmt.Errorf("encode finding: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO security_findings(id,task_id,data) VALUES (?,?,?)`, finding.ID, task.ID, string(data)); err != nil {
		return fmt.Errorf("save finding: %w", err)
	}
	if err := observation(ctx, tx, finding); err != nil {
		return err
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
	page, err := s.ListRuntimeFindingsPage(ctx, FindingListQuery{Page: 1})
	if err != nil {
		return nil, err
	}
	return page.Items, nil
}

// liveProgress is the server-side memory behind scan_task_progress.history: the
// final counts of finished phases and the ports found so far.
type liveProgress struct {
	Phases    map[string]taskflow.PhaseCount `json:"phases,omitempty"`
	OpenPorts []int                          `json:"openPorts,omitempty"`
	HTTPPorts []int                          `json:"httpPorts,omitempty"`
}

func decodeLiveProgress(raw string) liveProgress {
	var live liveProgress
	if raw == "" || json.Unmarshal([]byte(raw), &live) != nil {
		return liveProgress{}
	}
	return live
}

func withLiveProgress(progress taskflow.TaskProgress, raw string) taskflow.TaskProgress {
	live := decodeLiveProgress(raw)
	progress.Phases, progress.OpenPorts, progress.HTTPPorts = live.Phases, live.OpenPorts, live.HTTPPorts
	return progress
}

// nextLiveProgress records the phase a Worker just left as fully done (a phase
// only advances after it finished, and its total is the input size of the next
// one) and keeps the newest found-port lists.
func nextLiveProgress(raw, oldPhase string, oldTotal int, update taskflow.ProgressUpdate) string {
	live := decodeLiveProgress(raw)
	if oldPhase != "" && update.Phase != oldPhase {
		if live.Phases == nil {
			live.Phases = map[string]taskflow.PhaseCount{}
		}
		live.Phases[oldPhase] = taskflow.PhaseCount{Completed: oldTotal, Total: oldTotal}
	}
	if update.OpenPorts != nil {
		live.OpenPorts = update.OpenPorts
	}
	if update.HTTPPorts != nil {
		live.HTTPPorts = update.HTTPPorts
	}
	if len(live.Phases) == 0 && live.OpenPorts == nil && live.HTTPPorts == nil {
		return ""
	}
	encoded, err := json.Marshal(live)
	if err != nil {
		return ""
	}
	return string(encoded)
}

// validLivePorts accepts only ports this task was dispatched to probe.
func validLivePorts(ports []int, dispatched map[int]bool) bool {
	if len(ports) > taskflow.MaxLivePorts {
		return false
	}
	seen := make(map[int]bool, len(ports))
	for _, port := range ports {
		if !dispatched[port] || seen[port] {
			return false
		}
		seen[port] = true
	}
	return true
}
