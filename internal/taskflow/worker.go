package taskflow

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"scanner-platform/internal/scheduler"
	"scanner-platform/internal/versionmgr"
)

type Worker struct {
	ServerURL string
	ID        string
	// NodeToken is an optional bearer credential for the authenticated node
	// protocol. Local loopback development may leave it empty.
	NodeToken    string
	Client       *http.Client
	Delay        time.Duration
	Interval     time.Duration
	Execute      func(context.Context, Task) ([]Detection, error)
	ProbePorts   func(context.Context, Task) ([]PortProbeResult, error)
	AutoScan     func(context.Context, Task) (AutoResult, error)
	EngineStatus func() []EngineStatus
	// CurrentRuleVersion reads the local read-only CURRENT pointer. The real
	// bootstrap supplies it; old fake/synthetic tests may leave it nil.
	CurrentRuleVersion func(context.Context) (string, error)
	LeaseGuard         scheduler.LeaseGuard
	// RequireLeases is enabled by the real Worker bootstrap. Direct protocol
	// tests may leave it false to exercise legacy fake tasks that predate lease
	// fields; Server-issued real tasks always include the fields.
	RequireLeases bool
}

type workerProgress struct {
	mu    sync.RWMutex
	value TaskProgress
	set   bool
}

func (p *workerProgress) update(value TaskProgress) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.set && p.value.Phase == value.Phase && value.Completed < p.value.Completed {
		return
	}
	p.value, p.set = value, true
}

func (p *workerProgress) snapshot() (TaskProgress, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.value, p.set
}

type workerLeaseRenewer struct{ worker *Worker }

func (r workerLeaseRenewer) Renew(ctx context.Context, assignment scheduler.Assignment) (time.Time, error) {
	var response struct {
		LeaseExpiresAt time.Time `json:"leaseExpiresAt"`
	}
	code, err := r.worker.post(ctx, "/api/v1/worker/renew", map[string]string{
		"taskId":            assignment.TaskID,
		"workerId":          assignment.WorkerNodeID,
		"pinnedRuleVersion": assignment.PinnedRuleVersion,
	}, &response)
	if err != nil {
		return time.Time{}, err
	}
	if code != http.StatusOK || response.LeaseExpiresAt.IsZero() {
		return time.Time{}, fmt.Errorf("invalid lease renewal response")
	}
	return response.LeaseExpiresAt, nil
}

func (w *Worker) runWithLease(ctx context.Context, task Task, work func(context.Context) error) error {
	if task.Synthetic || len(task.Chunks) != 1 {
		return work(ctx)
	}
	chunk := task.Chunks[0]
	if chunk.LeaseExpiresAt == nil && chunk.PinnedRuleVersion == "" {
		if w.RequireLeases {
			return scheduler.ErrInvalidLease
		}
		// Compatibility for old fake/local protocol fixtures. Server-issued
		// real tasks always carry both fields and take the guarded path.
		return work(ctx)
	}
	if chunk.LeaseExpiresAt == nil || chunk.PinnedRuleVersion == "" || task.HardDeadline == "" {
		return scheduler.ErrInvalidLease
	}
	deadline, err := time.Parse(time.RFC3339Nano, task.HardDeadline)
	if err != nil {
		return scheduler.ErrInvalidLease
	}
	guard := w.LeaseGuard
	if guard == (scheduler.LeaseGuard{}) {
		guard = scheduler.DefaultLeaseGuard()
	}
	assignment := scheduler.Assignment{
		TaskID:            task.ID,
		WorkerNodeID:      w.ID,
		PinnedRuleVersion: chunk.PinnedRuleVersion,
		LeaseExpiresAt:    *chunk.LeaseExpiresAt,
		HardDeadline:      deadline,
	}
	return guard.Run(ctx, assignment, workerLeaseRenewer{worker: w}, work)
}

func (w *Worker) Run(ctx context.Context, once bool) error {
	interval := w.Interval
	if interval <= 0 {
		interval = time.Second
	}
	for {
		worked, err := w.ProcessOne(ctx)
		if err != nil {
			// An invalid CURRENT is a local integrity/configuration error. Keep
			// the worker stopped until the rules installation is repaired rather
			// than polling forever while reporting the same RULES_ERROR state.
			if once || ctx.Err() != nil || errors.Is(err, versionmgr.ErrInvalidCurrent) {
				return err
			}
			slog.Warn("worker request failed; retrying", "error", err)
		}
		if once {
			return nil
		}
		if worked {
			continue
		}
		if err := waitFor(ctx, interval); err != nil {
			return err
		}
	}
}

func (w *Worker) ProcessOne(ctx context.Context) (bool, error) {
	localRuleVersion := ""
	rulesReady := true
	nodeStatus := "ONLINE"
	readinessErr := error(nil)
	if w.CurrentRuleVersion != nil {
		version, err := w.CurrentRuleVersion(ctx)
		if err != nil {
			if errors.Is(err, versionmgr.ErrWaitingForRules) {
				rulesReady = false
				nodeStatus = NodeStatusWaitingForRules
			} else {
				nodeStatus = NodeStatusRulesError
				readinessErr = fmt.Errorf("local rule readiness check failed: %w", err)
			}
		} else if strings.TrimSpace(version) == "" {
			rulesReady = false
			nodeStatus = NodeStatusWaitingForRules
		} else {
			localRuleVersion = version
		}
	}
	if w.EngineStatus != nil || w.CurrentRuleVersion != nil {
		payload := map[string]any{"id": w.ID, "kind": "worker"}
		if w.EngineStatus != nil {
			payload["engines"] = w.EngineStatus()
		}
		if w.CurrentRuleVersion != nil {
			payload["localRuleVersion"] = localRuleVersion
			payload["status"] = nodeStatus
		}
		_, _ = w.post(ctx, "/api/v1/nodes/heartbeat", payload, nil)
	}
	if readinessErr != nil {
		return false, readinessErr
	}
	var task Task
	claimPayload := map[string]any{"workerId": w.ID}
	if w.CurrentRuleVersion != nil {
		claimPayload["localRuleVersion"] = localRuleVersion
		claimPayload["rulesReady"] = rulesReady
	}
	code, err := w.post(ctx, "/api/v1/worker/claim", claimPayload, &task)
	if err != nil {
		return false, err
	}
	if code == http.StatusNoContent {
		return false, nil
	}
	if len(task.Chunks) != 1 || len(task.Chunks[0].Targets) == 0 {
		return false, fmt.Errorf("worker requires one chunk with explicit targets")
	}
	slog.Info("task claimed", "task_id", task.ID, "worker_id", w.ID)

	workCtx := ctx
	cancel := func() {}
	if task.HardDeadline != "" {
		deadline, err := time.Parse(time.RFC3339Nano, task.HardDeadline)
		if err != nil {
			return false, fmt.Errorf("invalid task deadline: %w", err)
		}
		workCtx, cancel = context.WithDeadline(ctx, deadline)
	}
	workCtx, stopWork := context.WithCancel(workCtx)
	progress := &workerProgress{}
	workCtx = WithProgressReporter(workCtx, progress.update)
	heartbeatCtx, stopHeartbeat := context.WithCancel(ctx)
	defer stopHeartbeat()
	defer stopWork()
	defer cancel()
	var remoteStopped atomic.Bool
	go func() {
		ticker := time.NewTicker(3 * time.Second)
		defer ticker.Stop()
		failed := 0
		for {
			select {
			case <-heartbeatCtx.Done():
				return
			case <-ticker.C:
				var state struct {
					TaskStatus string `json:"taskStatus"`
				}
				payload := map[string]any{"id": w.ID, "kind": "worker", "currentTask": task.ID}
				if w.CurrentRuleVersion != nil {
					payload["localRuleVersion"] = localRuleVersion
				}
				if current, ok := progress.snapshot(); ok {
					payload["progress"] = ProgressUpdate{TaskID: task.ID, Phase: current.Phase, Completed: current.Completed, Total: current.Total}
				}
				_, e := w.post(heartbeatCtx, "/api/v1/nodes/heartbeat", payload, &state)
				if e != nil {
					failed++
				} else {
					failed = 0
				}
				if failed >= 3 || state.TaskStatus != "" && state.TaskStatus != "RUNNING" {
					if state.TaskStatus != "" && state.TaskStatus != "RUNNING" {
						remoteStopped.Store(true)
					}
					stopWork()
					return
				}
			}
		}
	}()
	var detections []Detection
	var portProbeResults []PortProbeResult
	var serviceResults []ServiceResult
	var systemScanStatus string
	var applicationScanStatus string
	var applicationResults []ApplicationResult
	var completedFully bool
	var rulesExecuted bool
	var executedEngines []string
	isAutoTask := len(task.Engines) == 1 && task.Engines[0] == "auto"
	if isAutoTask {
		systemScanStatus = SystemScanNotStarted
	}
	assetProfile := task.AssetProfile
	execute := func(execCtx context.Context) error {
		if task.Synthetic {
			return waitFor(execCtx, w.Delay)
		}
		if len(task.Engines) == 1 && task.Engines[0] == "port-probe" {
			ReportProgress(execCtx, "tcp_probe", 0, len(task.PortProbePorts))
			if w.ProbePorts == nil {
				return fmt.Errorf("TCP port probe is not configured")
			}
			var executeErr error
			portProbeResults, executeErr = w.ProbePorts(execCtx, task)
			return executeErr
		}
		if len(task.Engines) == 1 && task.Engines[0] == "auto" {
			ReportProgress(execCtx, "tcp_probe", 0, len(task.PortProbePorts))
			if w.AutoScan == nil {
				return fmt.Errorf("automatic scan is not configured")
			}
			var result AutoResult
			var executeErr error
			result, executeErr = w.AutoScan(execCtx, task)
			detections, portProbeResults, serviceResults = result.Findings, result.Ports, result.Services
			completedFully, rulesExecuted, executedEngines = result.CompletedFully, result.RulesExecuted, append([]string(nil), result.ExecutedEngines...)
			if result.SystemStatus != "" {
				systemScanStatus = result.SystemStatus
			}
			assetProfile = result.AssetProfile
			applicationScanStatus = result.ApplicationStatus
			applicationResults = result.ApplicationResults
			return executeErr
		}
		if w.Execute == nil {
			return fmt.Errorf("scanning engines are not configured")
		}
		ReportProgress(execCtx, "engine_scan", 0, 0)
		var executeErr error
		detections, executeErr = w.Execute(execCtx, task)
		if executeErr == nil {
			completedFully = true
			rulesExecuted = true
			executedEngines = []string{task.Engines[0]}
		}
		return executeErr
	}
	err = w.runWithLease(workCtx, task, execute)
	if remoteStopped.Load() {
		// The Server deliberately changed the task state (pause/cancel/reclaim).
		// Do not send a stale failure or success report after that decision.
		return false, nil
	}

	report := Report{TaskID: task.ID, WorkerID: w.ID, Target: task.Chunks[0].Targets[0], Title: SyntheticTitle}
	if !task.Synthetic {
		report = Report{TaskID: task.ID, WorkerID: w.ID, Target: task.Chunks[0].Targets[0], Status: "COMPLETED", Findings: detections, CompletedFully: completedFully, RulesExecuted: rulesExecuted, ExecutedEngines: executedEngines, RuleVersion: task.RuleVersion}
		if len(task.Engines) == 1 && task.Engines[0] == "port-probe" {
			report.Findings = nil
			report.PortProbeResults = portProbeResults
		} else if len(task.Engines) == 1 && task.Engines[0] == "auto" {
			report.PortProbeResults = portProbeResults
			report.ServiceResults = serviceResults
			report.SystemScanStatus = systemScanStatus
			report.AssetProfile = assetProfile
			report.CompletedFully = completedFully
			report.RulesExecuted = rulesExecuted
			report.ExecutedEngines = executedEngines
			report.RuleVersion = task.RuleVersion
		}
	}
	if err != nil {
		if ctx.Err() != nil {
			if !task.Synthetic {
				reportCtx, reportCancel := context.WithTimeout(context.Background(), 3*time.Second)
				_, _ = w.post(reportCtx, "/api/v1/worker/report", Report{TaskID: task.ID, WorkerID: w.ID, Target: task.Chunks[0].Targets[0], Status: "FAILED", Error: "Worker 已停止，扫描未完成", SystemScanStatus: systemScanStatus, ApplicationScanStatus: applicationScanStatus, ApplicationResults: applicationResults}, nil)
				reportCancel()
			}
			return false, ctx.Err()
		}
		if errors.Is(err, scheduler.ErrLeaseExpired) || errors.Is(err, scheduler.ErrWorkerStopTimeout) || errors.Is(err, scheduler.ErrInvalidLease) || errors.Is(err, scheduler.ErrInvalidRenewal) {
			// The Server may already have reclaimed and reassigned this task. Do
			// not send a stale FAILED/COMPLETED report; Tick will requeue it and
			// the process supervisor handles an uncooperative executor.
			return false, fmt.Errorf("worker lease ended: %w", err)
		}
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, scheduler.ErrHardDeadline) {
			report = Report{TaskID: task.ID, WorkerID: w.ID, Target: task.Chunks[0].Targets[0], Status: "PAUSED_WINDOW", SystemScanStatus: systemScanStatus}
		} else if task.Synthetic {
			return true, err
		} else {
			report = Report{TaskID: task.ID, WorkerID: w.ID, Target: task.Chunks[0].Targets[0], Status: "FAILED", Error: "引擎执行失败，请检查节点状态、规则库、输入和 Worker 日志", SystemScanStatus: systemScanStatus}
			var publicError *ExecutionError
			if errors.As(err, &publicError) && len(publicError.UserMessage) > 0 && len(publicError.UserMessage) <= 500 {
				report.Error = publicError.UserMessage
			}
			slog.Warn("engine execution failed", "task_id", task.ID, "error", err)
		}
	}
	report.ApplicationScanStatus = applicationScanStatus
	report.ApplicationResults = applicationResults

	encoded, err := json.Marshal(report)
	if err != nil {
		return false, fmt.Errorf("encode result report: %w", err)
	}
	if len(encoded) > MaxReportBytes {
		report = Report{TaskID: task.ID, WorkerID: w.ID, Status: "FAILED", Error: "结果超过单次回报大小限制，请拆分目标或输入后重试", SystemScanStatus: systemScanStatus, ApplicationScanStatus: applicationScanStatus, ApplicationResults: applicationResults}
	}
	for {
		if code, err := w.post(ctx, "/api/v1/worker/report", report, nil); err == nil {
			break
		} else if code >= 400 && code < 500 {
			return false, fmt.Errorf("report rejected: %w", err)
		} else if ctx.Err() != nil {
			return false, ctx.Err()
		} else {
			slog.Warn("result report failed; retrying same task", "task_id", task.ID, "error", err)
		}
		if err := waitFor(ctx, time.Second); err != nil {
			return false, err
		}
	}
	status := report.Status
	if status == "" {
		status = "COMPLETED"
	}
	slog.Info("task report accepted", "task_id", task.ID, "status", status)
	return true, nil
}

func (w *Worker) post(ctx context.Context, path string, payload, result any) (int, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return 0, fmt.Errorf("encode worker request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(w.ServerURL, "/")+path, bytes.NewReader(body))
	if err != nil {
		return 0, fmt.Errorf("create worker request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if w.NodeToken != "" {
		req.Header.Set("Authorization", "Bearer "+w.NodeToken)
		req.Header.Set("X-Node-ID", w.ID)
	}
	client := w.Client
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	response, err := client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("call task API: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return response.StatusCode, fmt.Errorf("task API returned HTTP %d", response.StatusCode)
	}
	if result != nil && response.StatusCode != http.StatusNoContent {
		if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(result); err != nil {
			return response.StatusCode, fmt.Errorf("decode task API: %w", err)
		}
	}
	return response.StatusCode, nil
}

func waitFor(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
