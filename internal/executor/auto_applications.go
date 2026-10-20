package executor

import (
	"context"
	"fmt"
	"net"
	"strconv"

	"scanner-platform/internal/sshcollect"
	"scanner-platform/internal/taskflow"
)

// scanApplications keeps independent per-file inputs: success for one artifact
// must never imply that another artifact was analyzed.
func (r *Runner) scanApplications(ctx context.Context, task taskflow.Task, result *taskflow.AutoResult) error {
	host := task.Chunks[0].Targets[0]
	apps := r.SSHCollector.Applications(host)
	result.ApplicationStatus = taskflow.ApplicationScanNotConfigured
	if len(apps) == 0 {
		return nil
	}
	result.ApplicationStatus = taskflow.ApplicationScanNotStarted
	for _, app := range apps {
		result.ApplicationResults = append(result.ApplicationResults, taskflow.ApplicationResult{Alias: app.Alias, Status: taskflow.ApplicationScanNotStarted})
	}
	taskflow.ReportProgress(ctx, "ssh_collection", 0, 0)
	inputs, cleanup, status, err := r.SSHCollector.CollectApplications(ctx, host, task.VulnerabilityPorts, openPorts(result.Ports), r.RuntimeDir, r.InputsDir)
	defer cleanup()
	if status == taskflow.ApplicationScanPortOutOfScope {
		result.ApplicationStatus = status
		for i := range result.ApplicationResults {
			result.ApplicationResults[i].Status = status
		}
		return nil
	}
	if err != nil {
		result.ApplicationStatus = taskflow.ApplicationScanCollectionFailed
		for i := range result.ApplicationResults {
			result.ApplicationResults[i].Status = result.ApplicationStatus
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return &taskflow.ExecutionError{UserMessage: "指定部署目录应用采集失败：仅支持 Java 归档和含 Go 构建信息的 ELF；请检查 Worker 本地 SSH 配置、Python 3.7+、权限和采集限制"}
	}
	return scanCollectedApplications(ctx, task, result, inputs, r.Execute, func() int { port, _ := r.SSHCollector.ProfilePort(host); return port }())
}

type executeApplication func(context.Context, taskflow.Task) ([]taskflow.Detection, error)

func scanCollectedApplications(ctx context.Context, task taskflow.Task, result *taskflow.AutoResult, inputs []sshcollect.AppInput, execute executeApplication, sshPort int) error {
	byAlias := map[string]int{}
	for i := range result.ApplicationResults {
		byAlias[result.ApplicationResults[i].Alias] = i
		result.ApplicationResults[i].Status = taskflow.ApplicationScanScanning
	}
	for _, input := range inputs {
		i, ok := byAlias[input.Alias]
		if !ok {
			return fmt.Errorf("application input alias is not configured")
		}
		result.ApplicationResults[i].SelectedCount++
	}
	result.ApplicationStatus = taskflow.ApplicationScanScanning
	fail := func(err error) error {
		result.ApplicationStatus = taskflow.ApplicationScanAnalysisFailed
		for i := range result.ApplicationResults {
			if result.ApplicationResults[i].Status != taskflow.ApplicationScanCompleted {
				result.ApplicationResults[i].Status = taskflow.ApplicationScanAnalysisFailed
			}
		}
		return err
	}
	for _, input := range inputs {
		if err := ctx.Err(); err != nil {
			return fail(err)
		}
		subtask := task
		subtask.Engines = []string{"trivy"}
		subtask.InputKind = "artifact"
		subtask.InputPath = input.InputPath
		subtask.RequireInputSnapshot = true
		subtask.ExpectedArtifactType = input.ArtifactType
		taskflow.ReportProgress(ctx, "trivy_scan", 0, 0)
		findings, err := execute(ctx, subtask)
		if err != nil {
			if ctx.Err() != nil {
				return fail(ctx.Err())
			}
			return fail(&taskflow.ExecutionError{UserMessage: "指定部署目录应用分析失败，部分文件未完成；请检查 Java 索引、Go 产物类型和 Worker 本地日志"})
		}
		if err := ctx.Err(); err != nil {
			return fail(err)
		}
		for i := range findings {
			findings[i].Target = net.JoinHostPort(task.Chunks[0].Targets[0], strconv.Itoa(sshPort))
		}
		result.Findings = append(result.Findings, findings...)
		i := byAlias[input.Alias]
		result.ApplicationResults[i].AnalyzedCount++
		if result.ApplicationResults[i].AnalyzedCount == result.ApplicationResults[i].SelectedCount {
			result.ApplicationResults[i].Status = taskflow.ApplicationScanCompleted
		}
	}
	for _, app := range result.ApplicationResults {
		if app.SelectedCount == 0 {
			return fail(fmt.Errorf("application has no selected artifacts"))
		}
	}
	result.ApplicationStatus = taskflow.ApplicationScanCompleted
	return nil
}
