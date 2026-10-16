package taskflow

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

type Worker struct {
	ServerURL string
	ID        string
	Client    *http.Client
	Delay     time.Duration
	Interval  time.Duration
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
	var task Task
	code, err := w.post(ctx, "/api/v1/worker/claim", map[string]string{"workerId": w.ID}, &task)
	if err != nil {
		return false, err
	}
	if code == http.StatusNoContent {
		return false, nil
	}
	if !task.Synthetic || len(task.Chunks) != 1 || len(task.Chunks[0].Targets) == 0 {
		return false, fmt.Errorf("worker only accepts synthetic tasks with explicit targets")
	}
	slog.Info("synthetic task claimed", "task_id", task.ID, "worker_id", w.ID)
	if err := waitFor(ctx, w.Delay); err != nil {
		return false, err
	}
	report := Report{TaskID: task.ID, WorkerID: w.ID, Target: task.Chunks[0].Targets[0], Title: SyntheticTitle}
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
	slog.Info("synthetic task completed", "task_id", task.ID)
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
