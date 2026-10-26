package executor

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"scanner-platform/internal/portprobe"
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
	policy, err := portprobe.PolicyFor(task.PortProbeConfig)
	if err != nil {
		return taskflow.AutoResult{}, err
	}
	rate := policy.Rate
	if r.Rate > 0 && r.Rate < rate {
		rate = r.Rate
	}
	ctx = withHTTPBudget(ctx, rate, maxHTTPRequestsPerTarget)
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
	taskflow.ReportProgress(ctx, "service_identification", 0, len(openApproved))
	services := identifyServicesWithProgress(ctx, task.Chunks[0].Targets[0], openApproved, task.PortProbeConfig, func(completed, total int) {
		taskflow.ReportProgress(ctx, "service_identification", completed, total)
	})
	result := taskflow.AutoResult{Ports: open, Services: services, Findings: []taskflow.Detection{}, SystemStatus: taskflow.SystemScanNotStarted, ApplicationStatus: taskflow.ApplicationScanNotStarted, AssetProfile: inferProfile(services)}
	markEngine := func(engine string) {
		for _, existing := range result.ExecutedEngines {
			if existing == engine {
				return
			}
		}
		result.ExecutedEngines = append(result.ExecutedEngines, engine)
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	if len(open) == 0 {
		// Nothing answered on the authorized ports: there is no HTTP(S) service
		// to check and no open SSH port to collect from, so finish here instead
		// of starting later phases. Statuses match what those phases would
		// have recorded for a closed SSH port, so finding lifecycle is unchanged.
		if _, configured := r.SSHCollector.ProfilePort(task.Chunks[0].Targets[0]); configured {
			result.SystemStatus = taskflow.SystemScanPortClosed
		} else {
			result.SystemStatus = taskflow.SystemScanNotConfigured
		}
		if apps := r.SSHCollector.Applications(task.Chunks[0].Targets[0]); len(apps) == 0 {
			result.ApplicationStatus = taskflow.ApplicationScanNotConfigured
		} else {
			result.ApplicationStatus = taskflow.ApplicationScanPortOutOfScope
			for _, app := range apps {
				result.ApplicationResults = append(result.ApplicationResults, taskflow.ApplicationResult{Alias: app.Alias, Status: taskflow.ApplicationScanPortOutOfScope})
			}
		}
		result.CompletedFully = autoScanCompleted(result)
		return result, nil
	}
	byScheme := map[string][]string{"http": {}, "https": {}}
	for _, service := range services {
		if !service.Quarantined && (service.Scheme == "http" || service.Scheme == "https") {
			target := net.JoinHostPort(task.Chunks[0].Targets[0], strconv.Itoa(service.Port))
			byScheme[service.Scheme] = append(byScheme[service.Scheme], target)
		}
	}
	httpTotal := len(byScheme["http"]) + len(byScheme["https"])
	if httpTotal > 0 {
		taskflow.ReportProgress(ctx, "http_scan", 0, httpTotal)
	}
	httpCompleted := 0
	httpScanFailed := false
	for _, scheme := range []string{"http", "https"} {
		targets := byScheme[scheme]
		if len(targets) == 0 {
			continue
		}
		for start := 0; start < len(targets); start += maxAutoHTTPPorts {
			end := min(start+maxAutoHTTPPorts, len(targets))
			subtask := task
			subtask.Engines = []string{"nuclei"}
			subtask.Scheme = scheme
			subtask.Chunks = append([]taskflow.Chunk(nil), task.Chunks...)
			subtask.Chunks[0].Targets = targets[start:end]
			findings, err := r.Execute(ctx, subtask)
			if err != nil {
				if ctx.Err() != nil {
					return result, ctx.Err()
				}
				// A single HTTP candidate batch failed (for example a root
				// request error). Record it and keep going so the remaining
				// candidates and the SSH/Trivy phases still run; the partial
				// HTTP coverage is reflected by CompletedFully below.
				httpScanFailed = true
			} else {
				markEngine("nuclei")
				result.Findings = append(result.Findings, findings...)
				if r.zapReady() {
					subtask.Engines = []string{"zap"}
					zapFindings, zapErr := r.Execute(ctx, subtask)
					if zapErr != nil {
						if ctx.Err() != nil {
							return result, ctx.Err()
						}
						httpScanFailed = true
					} else {
						markEngine("zap")
						result.Findings = append(result.Findings, zapFindings...)
					}
				}
			}
			httpCompleted += end - start
			taskflow.ReportProgress(ctx, "http_scan", httpCompleted, httpTotal)
		}
	}
	sshPort, configured := r.SSHCollector.ProfilePort(task.Chunks[0].Targets[0])
	if configured {
		taskflow.ReportProgress(ctx, "ssh_collection", 0, 1)
		rootfsPath, runtimeServices, cleanup, status, collectErr := r.SSHCollector.CollectRootfs(ctx, task.Chunks[0].Targets[0], task.VulnerabilityPorts, openPorts(open), r.RuntimeDir, r.InputsDir)
		if ctx.Err() == nil && collectErr == nil {
			taskflow.ReportProgress(ctx, "ssh_collection", 1, 1)
		}
		result.SystemStatus = status
		result.AssetProfile.RuntimeServices = runtimeServices
		if ctx.Err() != nil {
			return result, ctx.Err()
		}
		if collectErr == nil && rootfsPath != "" {
			defer cleanup()
			if path, err := localInput(r.InputsDir, rootfsPath, "rootfs"); err == nil {
				result.AssetProfile = profileFromRootfs(path)
			}
			trivyReady := false
			for _, engine := range r.Status() {
				if engine.Name == "trivy" && engine.Ready {
					trivyReady = true
				}
			}
			if !trivyReady {
				result.SystemStatus = taskflow.SystemScanTrivyUnavailable
			} else {
				taskflow.ReportProgress(ctx, "trivy_scan", 0, 1)
				subtask := task
				subtask.Engines = []string{"trivy"}
				subtask.InputKind = "rootfs"
				subtask.InputPath = rootfsPath
				findings, scanErr := r.Execute(ctx, subtask)
				if ctx.Err() != nil {
					return result, ctx.Err()
				}
				if scanErr != nil {
					var publicError *taskflow.ExecutionError
					if errors.As(scanErr, &publicError) && strings.Contains(publicError.UserMessage, "发行版尚未适配漏洞源") {
						result.SystemStatus = taskflow.SystemScanUnsupportedOS
					} else {
						result.SystemStatus = taskflow.SystemScanTrivyFailed
					}
				} else {
					taskflow.ReportProgress(ctx, "trivy_scan", 1, 1)
					markEngine("trivy")
					host := task.Chunks[0].Targets[0]
					for i := range findings {
						findings[i].Target = net.JoinHostPort(host, strconv.Itoa(sshPort))
					}
					result.Findings = append(result.Findings, findings...)
					result.SystemStatus = taskflow.SystemScanCompleted
				}
			}
		}
	} else {
		result.SystemStatus = taskflow.SystemScanNotConfigured
	}
	result.SystemStatus = boundedSystemStatus(result.SystemStatus)
	if err := r.scanApplications(ctx, task, &result); err != nil {
		if ctx.Err() != nil {
			return result, ctx.Err()
		}
		// Application (Java/Go) collection or analysis failed. scanApplications
		// already recorded the failed ApplicationScanStatus on result, and
		// autoScanCompleted rejects that status, so keep the completed
		// port/HTTP/system results and finish the task with
		// CompletedFully=false instead of discarding them and marking the
		// whole task FAILED.
	}
	for _, app := range result.ApplicationResults {
		if app.AnalyzedCount > 0 {
			markEngine("trivy")
			break
		}
	}
	result.RulesExecuted = len(result.ExecutedEngines) > 0
	result.CompletedFully = autoScanCompleted(result) && !httpScanFailed
	return result, nil
}

// autoScanCompleted is deliberately conservative. A known inability to
// collect or analyze a configured SSH/application input means the authorized
// scope was not fully checked, so its absence cannot close old findings.
func autoScanCompleted(result taskflow.AutoResult) bool {
	switch result.SystemStatus {
	case taskflow.SystemScanNotStarted, taskflow.SystemScanPortOutOfScope,
		taskflow.SystemScanPortClosed, taskflow.SystemScanCollectionFailed,
		taskflow.SystemScanInvalidSnapshot, taskflow.SystemScanTrivyUnavailable,
		taskflow.SystemScanUnsupportedOS, taskflow.SystemScanTrivyFailed,
		taskflow.SystemScanAuthFailed, taskflow.SystemScanHostKeyMismatch,
		taskflow.SystemScanPythonMissing, taskflow.SystemScanClientMissing:
		return false
	}
	switch result.ApplicationStatus {
	case taskflow.ApplicationScanNotStarted, taskflow.ApplicationScanCollecting,
		taskflow.ApplicationScanPortOutOfScope, taskflow.ApplicationScanScanning, taskflow.ApplicationScanCollectionFailed,
		taskflow.ApplicationScanAnalysisFailed:
		return false
	}
	return true
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
	return identifyServices(ctx, host, ports, portprobe.Config{})
}
func identifyHTTP(ctx context.Context, host string, port, timeout int) taskflow.ServiceResult {
	return identifyService(ctx, host, port, time.Duration(min(max(timeout, 1), 60))*time.Second, 2, 2, &identificationBudget{remaining: 2})
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
