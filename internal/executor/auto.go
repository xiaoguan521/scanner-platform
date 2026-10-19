package executor

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"scanner-platform/internal/taskflow"
)

const maxAutoHTTPPorts = 256
const autoProbeWorkers = 16

// AutoScan probes only the Server-resolved range for one registered asset,
// then runs the read-only HTTP baseline against open ports in that range.
func (r *Runner) AutoScan(ctx context.Context, task taskflow.Task) (taskflow.AutoResult, error) {
	if len(task.Engines) != 1 || task.Engines[0] != "auto" || task.AssetID == "" || len(task.Chunks) != 1 || len(task.Chunks[0].Targets) != 1 || !task.PortProbeConfig.OpsApproved || len(task.VulnerabilityPorts) == 0 {
		return taskflow.AutoResult{}, fmt.Errorf("invalid automatic scan task")
	}
	probeTask := task
	probeTask.Engines = []string{"port-probe"}
	open, err := r.ProbePorts(ctx, probeTask)
	if err != nil {
		return taskflow.AutoResult{}, err
	}
	allowed := make(map[int]bool, len(task.VulnerabilityPorts))
	for _, port := range task.VulnerabilityPorts {
		allowed[port] = true
	}
	openApproved := make([]int, 0, len(open))
	for _, result := range open {
		if allowed[result.Port] {
			openApproved = append(openApproved, result.Port)
		}
	}
	if len(openApproved) > maxAutoHTTPPorts {
		return taskflow.AutoResult{}, &taskflow.ExecutionError{UserMessage: "开放端口超过单任务自动漏洞检查上限 256 个，请缩小端口范围或分批执行"}
	}
	timeout := r.Timeout
	if timeout < 1 || timeout > 60 {
		timeout = 10
	}
	services := detectHTTPServices(ctx, task.Chunks[0].Targets[0], openApproved, timeout)
	if err := ctx.Err(); err != nil {
		return taskflow.AutoResult{}, err
	}
	byScheme := map[string][]string{"http": {}, "https": {}}
	for _, service := range services {
		if service.Scheme == "http" || service.Scheme == "https" {
			target := net.JoinHostPort(task.Chunks[0].Targets[0], strconv.Itoa(service.Port))
			byScheme[service.Scheme] = append(byScheme[service.Scheme], target)
		}
	}
	result := taskflow.AutoResult{Ports: open, Services: services, Findings: []taskflow.Detection{}, SystemStatus: taskflow.SystemScanNotConfigured}
	for _, scheme := range []string{"http", "https"} {
		targets := byScheme[scheme]
		if len(targets) == 0 {
			continue
		}
		subtask := task
		subtask.Engines = []string{"nuclei"}
		subtask.Scheme = scheme
		subtask.Chunks = append([]taskflow.Chunk(nil), task.Chunks...)
		subtask.Chunks[0].Targets = targets
		findings, err := r.Execute(ctx, subtask)
		if err != nil {
			return taskflow.AutoResult{}, err
		}
		result.Findings = append(result.Findings, findings...)
		if r.zapReady() {
			subtask.Engines = []string{"zap"}
			findings, err = r.Execute(ctx, subtask)
			if err != nil {
				return taskflow.AutoResult{}, err
			}
			result.Findings = append(result.Findings, findings...)
		}
	}
	sshPort, configured := r.SSHCollector.ProfilePort(task.Chunks[0].Targets[0])
	if configured {
		rootfsPath, cleanup, status, collectErr := r.SSHCollector.CollectRootfs(ctx, task.Chunks[0].Targets[0], task.VulnerabilityPorts, openPorts(open), r.RuntimeDir, r.InputsDir)
		result.SystemStatus = status
		if ctx.Err() != nil {
			return taskflow.AutoResult{}, ctx.Err()
		}
		if collectErr == nil && rootfsPath != "" {
			defer cleanup()
			trivyReady := false
			for _, engine := range r.Status() {
				if engine.Name == "trivy" && engine.Ready {
					trivyReady = true
				}
			}
			if !trivyReady {
				result.SystemStatus = taskflow.SystemScanTrivyUnavailable
			} else {
				subtask := task
				subtask.Engines = []string{"trivy"}
				subtask.InputKind = "rootfs"
				subtask.InputPath = rootfsPath
				findings, scanErr := r.Execute(ctx, subtask)
				if ctx.Err() != nil {
					return taskflow.AutoResult{}, ctx.Err()
				}
				if scanErr != nil {
					var publicError *taskflow.ExecutionError
					if errors.As(scanErr, &publicError) && strings.Contains(publicError.UserMessage, "发行版尚未适配漏洞源") {
						result.SystemStatus = taskflow.SystemScanUnsupportedOS
					} else {
						result.SystemStatus = taskflow.SystemScanTrivyFailed
					}
				} else {
					host := task.Chunks[0].Targets[0]
					for i := range findings {
						findings[i].Target = net.JoinHostPort(host, strconv.Itoa(sshPort))
					}
					result.Findings = append(result.Findings, findings...)
					result.SystemStatus = taskflow.SystemScanCompleted
				}
			}
		}
	}
	result.SystemStatus = boundedSystemStatus(result.SystemStatus)
	return result, nil
}

func openPorts(results []taskflow.PortProbeResult) []int {
	ports := make([]int, len(results))
	for i, result := range results {
		ports[i] = result.Port
	}
	return ports
}

func boundedSystemStatus(value string) string {
	if value == "" || len(value) > 200 {
		return taskflow.SystemScanCollectionFailed
	}
	return value
}

func (r *Runner) zapReady() bool {
	r.checkVersions()
	if r.versionErrors["zap"] != nil {
		return false
	}
	if _, err := exec.LookPath("java"); err != nil {
		return false
	}
	info, err := os.Stat(r.zapJAR())
	return err == nil && info.Mode().IsRegular()
}

func detectHTTPServices(ctx context.Context, host string, ports []int, timeout int) []taskflow.ServiceResult {
	if timeout < 1 || timeout > 60 {
		timeout = 10
	}
	type indexed struct {
		index int
		port  int
	}
	jobs := make(chan indexed)
	results := make([]taskflow.ServiceResult, len(ports))
	var workers sync.WaitGroup
	count := min(autoProbeWorkers, len(ports))
	for range count {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for item := range jobs {
				results[item.index] = identifyHTTP(ctx, host, item.port, timeout)
			}
		}()
	}
	for index, port := range ports {
		select {
		case <-ctx.Done():
			close(jobs)
			workers.Wait()
			return nil
		case jobs <- indexed{index: index, port: port}:
		}
	}
	close(jobs)
	workers.Wait()
	return results
}

func identifyHTTP(ctx context.Context, host string, port, timeout int) taskflow.ServiceResult {
	target := net.JoinHostPort(host, strconv.Itoa(port))
	for _, scheme := range []string{"https", "http"} {
		raw := (&url.URL{Scheme: scheme, Host: target, Path: "/"}).String()
		if _, err := fetchRootLimit(ctx, raw, min(timeout, 3), 64<<10); err == nil {
			return taskflow.ServiceResult{Port: port, Scheme: scheme, Kind: "HTTP"}
		}
		if ctx.Err() != nil {
			return taskflow.ServiceResult{Port: port, Kind: "OTHER"}
		}
		// Keep this service check bounded even when an endpoint stalls.
		if err := waitSmall(ctx, 25*time.Millisecond); err != nil {
			return taskflow.ServiceResult{Port: port, Kind: "OTHER"}
		}
	}
	return taskflow.ServiceResult{Port: port, Kind: "OTHER"}
}

func waitSmall(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
