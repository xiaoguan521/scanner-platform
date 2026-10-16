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
	"time"
)

type Worker struct {
	ServerURL    string
	ID           string
	Client       *http.Client
	Delay        time.Duration
	Interval     time.Duration
	Execute      func(context.Context, Task) ([]Detection, error)
	EngineStatus func() []EngineStatus
}

func (w *Worker) Run(ctx context.Context, once bool) error {
	interval := w.Interval
	if interval <= 0 {
		interval = time.Second
	}
	for {
		worked, err := w.ProcessOne(ctx)
		if err != nil {
			if once || ctx.Err() != nil {
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
	if w.EngineStatus != nil {
		_, _ = w.post(ctx, "/api/v1/nodes/heartbeat", map[string]any{"id": w.ID, "kind": "worker", "engines": w.EngineStatus()}, nil)
	}
	var task Task
	code, err := w.post(ctx, "/api/v1/worker/claim", map[string]string{"workerId": w.ID}, &task)
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
	heartbeatCtx, stopHeartbeat := context.WithCancel(ctx)
	defer stopHeartbeat()
	defer stopWork()
	defer cancel()
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
				_, e := w.post(heartbeatCtx, "/api/v1/nodes/heartbeat", map[string]any{"id": w.ID, "kind": "worker", "currentTask": task.ID}, &state)
				if e != nil {
					failed++
				} else {
					failed = 0
				}
				if failed >= 3 || state.TaskStatus != "" && state.TaskStatus != "RUNNING" {
					stopWork()
					return
				}
			}
		}
	}()
	var detections []Detection
	if task.Synthetic {
		err = waitFor(workCtx, w.Delay)
	} else if w.Execute == nil {
		err = fmt.Errorf("scanning engines are not configured")
	} else {
		detections, err = w.Execute(workCtx, task)
	}

	report := Report{TaskID: task.ID, WorkerID: w.ID, Target: task.Chunks[0].Targets[0], Title: SyntheticTitle}
	if !task.Synthetic {
		report = Report{TaskID: task.ID, WorkerID: w.ID, Status: "COMPLETED", Findings: detections}
	}
	if err != nil {
		if ctx.Err() != nil {
			if !task.Synthetic {
				reportCtx, reportCancel := context.WithTimeout(context.Background(), 3*time.Second)
				_, _ = w.post(reportCtx, "/api/v1/worker/report", Report{TaskID: task.ID, WorkerID: w.ID, Status: "FAILED", Error: "Worker 已停止，扫描未完成"}, nil)
				reportCancel()
			}
			return false, ctx.Err()
		}
		if errors.Is(err, context.DeadlineExceeded) {
			report = Report{TaskID: task.ID, WorkerID: w.ID, Status: "PAUSED_WINDOW"}
		} else if task.Synthetic {
			return true, err
		} else {
			report = Report{TaskID: task.ID, WorkerID: w.ID, Status: "FAILED", Error: "引擎执行失败，请检查节点状态、规则库、输入和 Worker 日志"}
			slog.Warn("engine execution failed", "task_id", task.ID, "error", err)
		}
	}

	encoded, err := json.Marshal(report)
	if err != nil {
		return false, fmt.Errorf("encode result report: %w", err)
	}
	if len(encoded) > MaxReportBytes {
		report = Report{TaskID: task.ID, WorkerID: w.ID, Status: "FAILED", Error: "结果超过单次回报大小限制，请拆分目标或输入后重试"}
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
