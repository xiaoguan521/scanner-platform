package rules

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

type Agent struct {
	ServerURL string
	ID        string
	Manager   *Manager
	Client    *http.Client
}

func (a *Agent) post(ctx context.Context, path string, body, result any) (int, error) {
	data, err := json.Marshal(body)
	if err != nil {
		return 0, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(a.ServerURL, "/")+path, bytes.NewReader(data))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	client := a.Client
	if client == nil {
		client = &http.Client{Timeout: 2 * time.Minute, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }, Transport: &http.Transport{Proxy: nil}}
	}
	response, err := client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("updater API unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return response.StatusCode, fmt.Errorf("updater API HTTP %d", response.StatusCode)
	}
	if result != nil && response.StatusCode != 204 {
		if err := json.NewDecoder(io.LimitReader(response.Body, 384<<20)).Decode(result); err != nil {
			return response.StatusCode, err
		}
	}
	return response.StatusCode, nil
}
func pause(ctx context.Context) error {
	timer := time.NewTimer(time.Second)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
func (a *Agent) Run(ctx context.Context, once bool) error {
	bundles, err := a.Manager.List(ctx)
	if err != nil {
		return err
	}
	for {
		if _, err = a.post(ctx, "/api/v1/updater/state", map[string]any{"nodeId": a.ID, "bundles": bundles}, nil); err == nil {
			break
		}
		if err := pause(ctx); err != nil {
			return err
		}
	}
	for {
		worked, err := a.ProcessOne(ctx)
		if err != nil {
			if once || ctx.Err() != nil {
				return err
			}
			slog.Warn("updater operation failed", "error", err)
		}
		if once {
			return err
		}
		if !worked {
			if err := pause(ctx); err != nil {
				return err
			}
		}
	}
}
func (a *Agent) ProcessOne(ctx context.Context) (bool, error) {
	var job Job
	code, err := a.post(ctx, "/api/v1/updater/claim", map[string]string{"nodeId": a.ID}, &job)
	if err != nil {
		return false, err
	}
	if code == 204 {
		return false, nil
	}
	heartbeatCtx, stopHeartbeat := context.WithCancel(ctx)
	defer stopHeartbeat()
	go func() {
		ticker := time.NewTicker(3 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-heartbeatCtx.Done():
				return
			case <-ticker.C:
				_, _ = a.post(heartbeatCtx, "/api/v1/nodes/heartbeat", map[string]string{"id": a.ID, "kind": "updater", "currentTask": job.ID}, nil)
			}
		}
	}()
	var bundle Bundle
	switch job.Kind {
	case "IMPORT":
		bundle, err = a.Manager.Import(ctx, job.Bundle)
	case "FETCH":
		bundle, err = a.Manager.Fetch(ctx, job.URL, job.ExpectedSHA256)
	case "ACTIVATE":
		err = a.Manager.Activate(ctx, job.Version, job.Rollback)
		bundle.Version = job.Version
	default:
		err = fmt.Errorf("unknown update operation")
	}
	report := Report{JobID: job.ID, NodeID: a.ID, Status: "COMPLETED", Version: bundle.Version, Message: "操作完成；已验证规则签名及文件完整性，未执行扫描引擎"}
	if err != nil {
		report.Status = "FAILED"
		report.Message = err.Error()
		if len(report.Message) > 500 {
			report.Message = "规则操作失败"
		}
	}
	catalog, listErr := a.Manager.List(ctx)
	if listErr == nil {
		report.Bundles = catalog
	} else if err == nil {
		report.Status = "FAILED"
		report.Message = "规则目录完整性检查失败"
	}
	for {
		code, sendErr := a.post(ctx, "/api/v1/updater/report", report, nil)
		if sendErr == nil {
			break
		}
		if code >= 400 && code < 500 {
			return true, sendErr
		}
		if err := pause(ctx); err != nil {
			return true, err
		}
	}
	slog.Info("rule operation finished", "job_id", job.ID, "status", report.Status)
	return true, nil
}
