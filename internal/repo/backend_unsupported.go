package repo

import (
	"context"
	"fmt"
	"os"
	"time"

	"scanner-platform/internal/assets"
	"scanner-platform/internal/findings"
	"scanner-platform/internal/reporting"
	"scanner-platform/internal/rules"
	"scanner-platform/internal/scanplans"
	"scanner-platform/internal/taskflow"
)

// unsupportedRuntimeBackend is deliberately explicit: PostgreSQL mode never
// falls back to SQLite for a route that has not been ported yet.
type unsupportedRuntimeBackend struct{}

func backendCapabilityError(operation string) error {
	return fmt.Errorf("%w: %s", ErrBackendCapability, operation)
}

func (unsupportedRuntimeBackend) AddFindingNote(ctx context.Context, id, body, actor string) (FindingNote, error) {
	return FindingNote{}, backendCapabilityError("AddFindingNote")
}

func (unsupportedRuntimeBackend) AssignFinding(ctx context.Context, id, assigneeID, actor string) (taskflow.Finding, error) {
	return taskflow.Finding{}, backendCapabilityError("AssignFinding")
}

func (unsupportedRuntimeBackend) BatchAssignFindings(ctx context.Context, in FindingBatchAssignment, actor string) ([]taskflow.Finding, error) {
	return nil, backendCapabilityError("BatchAssignFindings")
}

func (unsupportedRuntimeBackend) BatchFindingDisposition(ctx context.Context, in FindingBatchDisposition, actor string) ([]taskflow.Finding, error) {
	return nil, backendCapabilityError("BatchFindingDisposition")
}

func (unsupportedRuntimeBackend) CancelTask(ctx context.Context, id, actor string) error {
	return backendCapabilityError("CancelTask")
}

func (unsupportedRuntimeBackend) ClaimRuleJob(ctx context.Context, nodeID string) (*rules.Job, error) {
	return nil, backendCapabilityError("ClaimRuleJob")
}

func (unsupportedRuntimeBackend) ClaimRuntimeTask(ctx context.Context, worker string) (*taskflow.Task, error) {
	return nil, backendCapabilityError("ClaimRuntimeTask")
}

func (unsupportedRuntimeBackend) ClaimRuntimeTaskWithRules(ctx context.Context, worker, localRuleVersion string, rulesReady bool) (*taskflow.Task, error) {
	return nil, backendCapabilityError("ClaimRuntimeTaskWithRules")
}

func (unsupportedRuntimeBackend) Close() error {
	return backendCapabilityError("Close")
}

func (unsupportedRuntimeBackend) CompleteRuntimeTask(ctx context.Context, report taskflow.Report) error {
	return backendCapabilityError("CompleteRuntimeTask")
}

func (unsupportedRuntimeBackend) CountRunningByVersion(ctx context.Context, nodeID, version string) (int, error) {
	return 0, backendCapabilityError("CountRunningByVersion")
}

func (unsupportedRuntimeBackend) CreateFindingRetest(ctx context.Context, findingID, actor string) (taskflow.Task, FindingRetest, error) {
	return taskflow.Task{}, FindingRetest{}, backendCapabilityError("CreateFindingRetest")
}

func (unsupportedRuntimeBackend) CreateLocalTask(ctx context.Context, in taskflow.TaskInput, actor string) (taskflow.Task, error) {
	return taskflow.Task{}, backendCapabilityError("CreateLocalTask")
}

func (unsupportedRuntimeBackend) CreateReport(ctx context.Context, input reporting.Request, actor string) (reporting.Job, error) {
	return reporting.Job{}, backendCapabilityError("CreateReport")
}

func (unsupportedRuntimeBackend) CreateReportFormat(ctx context.Context, id, format, actor string) (reporting.Job, error) {
	return reporting.Job{}, backendCapabilityError("CreateReportFormat")
}

func (unsupportedRuntimeBackend) CreateSyntheticTask(ctx context.Context) (taskflow.Task, error) {
	return taskflow.Task{}, backendCapabilityError("CreateSyntheticTask")
}

func (unsupportedRuntimeBackend) DeleteCustomRule(ctx context.Context, id, actor string) error {
	return backendCapabilityError("DeleteCustomRule")
}

func (unsupportedRuntimeBackend) DeleteKnowledge(ctx context.Context, id, actor string) error {
	return backendCapabilityError("DeleteKnowledge")
}

func (unsupportedRuntimeBackend) DeleteRuntimeTask(ctx context.Context, id, actor string) error {
	return backendCapabilityError("DeleteRuntimeTask")
}

func (unsupportedRuntimeBackend) DeleteScanPlan(ctx context.Context, id, actor string) error {
	return backendCapabilityError("DeleteScanPlan")
}

func (unsupportedRuntimeBackend) DeleteSchedule(ctx context.Context, id, actor string) error {
	return backendCapabilityError("DeleteSchedule")
}

func (unsupportedRuntimeBackend) DispatchNotificationOutbox(ctx context.Context) (int, error) {
	return 0, backendCapabilityError("DispatchNotificationOutbox")
}

func (unsupportedRuntimeBackend) ExpireAcceptedRisks(ctx context.Context, now time.Time) error {
	return backendCapabilityError("ExpireAcceptedRisks")
}

func (unsupportedRuntimeBackend) GetNotificationSettings(ctx context.Context) (NotificationSettings, error) {
	return NotificationSettings{}, backendCapabilityError("GetNotificationSettings")
}

func (unsupportedRuntimeBackend) GetReport(ctx context.Context, id string) (reporting.Job, error) {
	return reporting.Job{}, backendCapabilityError("GetReport")
}

func (unsupportedRuntimeBackend) GetReportTemplate(ctx context.Context, id string) (reporting.Template, error) {
	return reporting.Template{}, backendCapabilityError("GetReportTemplate")
}

func (unsupportedRuntimeBackend) GetRuntimeTask(ctx context.Context, id string) (taskflow.Task, error) {
	return taskflow.Task{}, backendCapabilityError("GetRuntimeTask")
}

func (unsupportedRuntimeBackend) GetScanPolicy(ctx context.Context) (ScanPolicy, error) {
	return ScanPolicy{}, backendCapabilityError("GetScanPolicy")
}

func (unsupportedRuntimeBackend) GetSystemSettings(ctx context.Context) (SystemSettings, error) {
	return SystemSettings{}, backendCapabilityError("GetSystemSettings")
}

func (unsupportedRuntimeBackend) ImportKnowledge(ctx context.Context, items []findings.KnowledgeEntry, actor string) error {
	return backendCapabilityError("ImportKnowledge")
}

func (unsupportedRuntimeBackend) InitReports(ctx context.Context) error {
	return backendCapabilityError("InitReports")
}

func (unsupportedRuntimeBackend) ListAuditLogs(ctx context.Context, query AuditLogQuery) ([]AuditLog, int, error) {
	return nil, 0, backendCapabilityError("ListAuditLogs")
}

func (unsupportedRuntimeBackend) ListCustomRules(ctx context.Context) ([]rules.CustomRule, error) {
	return nil, backendCapabilityError("ListCustomRules")
}

func (unsupportedRuntimeBackend) ListCustomRulesPage(ctx context.Context, in CustomRuleListQuery) (CustomRuleListPage, error) {
	return CustomRuleListPage{}, backendCapabilityError("ListCustomRulesPage")
}

func (unsupportedRuntimeBackend) ListFindingAssignees(ctx context.Context) ([]FindingAssignee, error) {
	return nil, backendCapabilityError("ListFindingAssignees")
}

func (unsupportedRuntimeBackend) ListFindingAssignmentEvents(ctx context.Context, id string) ([]FindingAssignmentEvent, error) {
	return nil, backendCapabilityError("ListFindingAssignmentEvents")
}

func (unsupportedRuntimeBackend) ListFindingEvents(ctx context.Context, id string) ([]FindingEvent, error) {
	return nil, backendCapabilityError("ListFindingEvents")
}

func (unsupportedRuntimeBackend) ListFindingNotes(ctx context.Context, id string) ([]FindingNote, error) {
	return nil, backendCapabilityError("ListFindingNotes")
}

func (unsupportedRuntimeBackend) ListFindingRetests(ctx context.Context, findingID string) ([]FindingRetest, error) {
	return nil, backendCapabilityError("ListFindingRetests")
}

func (unsupportedRuntimeBackend) ListKnowledge(ctx context.Context) ([]findings.KnowledgeEntry, error) {
	return nil, backendCapabilityError("ListKnowledge")
}

func (unsupportedRuntimeBackend) ListKnowledgePage(ctx context.Context, query KnowledgeListQuery) (KnowledgeListPage, error) {
	return KnowledgeListPage{}, backendCapabilityError("ListKnowledgePage")
}

func (unsupportedRuntimeBackend) ListNodes(ctx context.Context) ([]LocalNode, error) {
	return nil, backendCapabilityError("ListNodes")
}

func (unsupportedRuntimeBackend) ListNodesPage(ctx context.Context, in NodeListQuery) (NodeListPage, error) {
	return NodeListPage{}, backendCapabilityError("ListNodesPage")
}

func (unsupportedRuntimeBackend) ListNotificationDeliveries(ctx context.Context, limit, offset int) (NotificationDeliveryList, error) {
	return NotificationDeliveryList{}, backendCapabilityError("ListNotificationDeliveries")
}

func (unsupportedRuntimeBackend) ListNotifications(ctx context.Context, unreadOnly bool) (NotificationList, error) {
	return NotificationList{}, backendCapabilityError("ListNotifications")
}

func (unsupportedRuntimeBackend) ListNotificationsPage(ctx context.Context, query NotificationListQuery) (NotificationListPage, error) {
	return NotificationListPage{}, backendCapabilityError("ListNotificationsPage")
}

func (unsupportedRuntimeBackend) ListQuarantines(ctx context.Context) ([]map[string]any, error) {
	return nil, backendCapabilityError("ListQuarantines")
}

func (unsupportedRuntimeBackend) ListReportTemplates(ctx context.Context) ([]reporting.Template, error) {
	return nil, backendCapabilityError("ListReportTemplates")
}

func (unsupportedRuntimeBackend) ListReports(ctx context.Context) ([]reporting.Job, error) {
	return nil, backendCapabilityError("ListReports")
}

func (unsupportedRuntimeBackend) ListReportsPage(ctx context.Context, in ReportListQuery) (ReportListPage, error) {
	return ReportListPage{}, backendCapabilityError("ListReportsPage")
}

func (unsupportedRuntimeBackend) ListRuleJobs(ctx context.Context) ([]rules.Job, error) {
	return nil, backendCapabilityError("ListRuleJobs")
}

func (unsupportedRuntimeBackend) ListRuleJobsPage(ctx context.Context, in RuleJobListQuery) (RuleJobListPage, error) {
	return RuleJobListPage{}, backendCapabilityError("ListRuleJobsPage")
}

func (unsupportedRuntimeBackend) ListRules(ctx context.Context) ([]rules.Bundle, error) {
	return nil, backendCapabilityError("ListRules")
}

func (unsupportedRuntimeBackend) ListRulesPage(ctx context.Context, in RuleListQuery) (RuleListPage, error) {
	return RuleListPage{}, backendCapabilityError("ListRulesPage")
}

func (unsupportedRuntimeBackend) ListRuntimeAssets(ctx context.Context) ([]assets.Asset, error) {
	return nil, backendCapabilityError("ListRuntimeAssets")
}

func (unsupportedRuntimeBackend) ListRuntimeFindings(ctx context.Context) ([]taskflow.Finding, error) {
	return nil, backendCapabilityError("ListRuntimeFindings")
}

func (unsupportedRuntimeBackend) ListRuntimeFindingsPage(ctx context.Context, in FindingListQuery) (FindingListPage, error) {
	return FindingListPage{}, backendCapabilityError("ListRuntimeFindingsPage")
}

func (unsupportedRuntimeBackend) ListRuntimeTasks(ctx context.Context) ([]taskflow.Task, error) {
	return nil, backendCapabilityError("ListRuntimeTasks")
}

func (unsupportedRuntimeBackend) ListRuntimeTasksPage(ctx context.Context, in TaskListQuery) (TaskListPage, error) {
	return TaskListPage{}, backendCapabilityError("ListRuntimeTasksPage")
}

func (unsupportedRuntimeBackend) ListScanPlans(ctx context.Context) ([]scanplans.Plan, error) {
	return nil, backendCapabilityError("ListScanPlans")
}

func (unsupportedRuntimeBackend) ListScheduleRuns(ctx context.Context, scheduleID string, limit, offset int) ([]taskflow.ScheduleRun, int, error) {
	return nil, 0, backendCapabilityError("ListScheduleRuns")
}

func (unsupportedRuntimeBackend) ListSchedules(ctx context.Context) ([]taskflow.Schedule, error) {
	return nil, backendCapabilityError("ListSchedules")
}

func (unsupportedRuntimeBackend) ListTaskFindings(ctx context.Context, id string) ([]taskflow.Finding, error) {
	return nil, backendCapabilityError("ListTaskFindings")
}

func (unsupportedRuntimeBackend) ListTaskLogs(ctx context.Context, taskID string) ([]TaskLog, error) {
	return nil, backendCapabilityError("ListTaskLogs")
}

func (unsupportedRuntimeBackend) MarkAllNotificationsRead(ctx context.Context) error {
	return backendCapabilityError("MarkAllNotificationsRead")
}

func (unsupportedRuntimeBackend) MarkNotificationRead(ctx context.Context, id string) error {
	return backendCapabilityError("MarkNotificationRead")
}

func (unsupportedRuntimeBackend) OpenReport(ctx context.Context, id string) (reporting.Job, *os.File, error) {
	return reporting.Job{}, nil, backendCapabilityError("OpenReport")
}

func (unsupportedRuntimeBackend) PauseTask(ctx context.Context, id, actor string) error {
	return backendCapabilityError("PauseTask")
}

func (unsupportedRuntimeBackend) ProcessNextReport(ctx context.Context, directory string) (bool, error) {
	return false, backendCapabilityError("ProcessNextReport")
}

func (unsupportedRuntimeBackend) QueueRuleJob(ctx context.Context, job rules.Job, actor string) (rules.Job, error) {
	return rules.Job{}, backendCapabilityError("QueueRuleJob")
}

func (unsupportedRuntimeBackend) RecoverReports(ctx context.Context) error {
	return backendCapabilityError("RecoverReports")
}

func (unsupportedRuntimeBackend) RefreshNotifications(ctx context.Context) error {
	return backendCapabilityError("RefreshNotifications")
}

func (unsupportedRuntimeBackend) ReleaseQuarantine(ctx context.Context, assetID string, port int, reason, actor string) error {
	return backendCapabilityError("ReleaseQuarantine")
}

func (unsupportedRuntimeBackend) RenewChunkLease(ctx context.Context, taskID, workerID, pinnedRuleVersion string) (time.Time, error) {
	return time.Time{}, backendCapabilityError("RenewChunkLease")
}

func (unsupportedRuntimeBackend) ReportRuleJob(ctx context.Context, report rules.Report) error {
	return backendCapabilityError("ReportRuleJob")
}

func (unsupportedRuntimeBackend) ReportSnapshot(ctx context.Context, id string) (reporting.Snapshot, error) {
	return reporting.Snapshot{}, backendCapabilityError("ReportSnapshot")
}

func (unsupportedRuntimeBackend) ResumeTask(ctx context.Context, id, actor string) error {
	return backendCapabilityError("ResumeTask")
}

func (unsupportedRuntimeBackend) RetryReport(ctx context.Context, id, actor string) (reporting.Job, error) {
	return reporting.Job{}, backendCapabilityError("RetryReport")
}

func (unsupportedRuntimeBackend) RunReports(ctx context.Context, directory string) error {
	return backendCapabilityError("RunReports")
}

func (unsupportedRuntimeBackend) SaveCustomRule(ctx context.Context, actor string, input rules.CustomRule, create bool) (rules.CustomRule, error) {
	return rules.CustomRule{}, backendCapabilityError("SaveCustomRule")
}

func (unsupportedRuntimeBackend) SaveKnowledge(ctx context.Context, k findings.KnowledgeEntry, actor string) (findings.KnowledgeEntry, error) {
	return findings.KnowledgeEntry{}, backendCapabilityError("SaveKnowledge")
}

func (unsupportedRuntimeBackend) SaveNotificationSettings(ctx context.Context, settings NotificationSettings, actor string) (NotificationSettings, error) {
	return NotificationSettings{}, backendCapabilityError("SaveNotificationSettings")
}

func (unsupportedRuntimeBackend) SaveReportTemplate(ctx context.Context, t reporting.Template, actor string) (reporting.Template, error) {
	return reporting.Template{}, backendCapabilityError("SaveReportTemplate")
}

func (unsupportedRuntimeBackend) SaveScanPlan(ctx context.Context, actor string, input scanplans.Input, id string, update bool) (scanplans.Plan, error) {
	return scanplans.Plan{}, backendCapabilityError("SaveScanPlan")
}

func (unsupportedRuntimeBackend) SaveScanPolicy(ctx context.Context, p ScanPolicy, actor string) (ScanPolicy, error) {
	return ScanPolicy{}, backendCapabilityError("SaveScanPolicy")
}

func (unsupportedRuntimeBackend) SaveSchedule(ctx context.Context, in taskflow.Schedule, actor string) (taskflow.Schedule, error) {
	return taskflow.Schedule{}, backendCapabilityError("SaveSchedule")
}

func (unsupportedRuntimeBackend) SaveSystemSettings(ctx context.Context, settings SystemSettings, actor string) (SystemSettings, error) {
	return SystemSettings{}, backendCapabilityError("SaveSystemSettings")
}

func (unsupportedRuntimeBackend) SetTaskArchived(ctx context.Context, id, actor string, archived bool) error {
	return backendCapabilityError("SetTaskArchived")
}

func (unsupportedRuntimeBackend) SyncRules(ctx context.Context, bundles []rules.Bundle) error {
	return backendCapabilityError("SyncRules")
}

func (unsupportedRuntimeBackend) TaskStateForWorker(ctx context.Context, id, worker string) string {
	return ""
}

func (unsupportedRuntimeBackend) Tick(ctx context.Context, now time.Time) error {
	return backendCapabilityError("Tick")
}

func (unsupportedRuntimeBackend) ToggleSchedule(ctx context.Context, id, actor string, enabled bool) error {
	return backendCapabilityError("ToggleSchedule")
}

func (unsupportedRuntimeBackend) TouchNode(ctx context.Context, id, kind, task string, engineStatus ...[]taskflow.EngineStatus) error {
	return backendCapabilityError("TouchNode")
}

func (unsupportedRuntimeBackend) TouchNodeState(ctx context.Context, id, kind, task, localRuleVersion, nodeStatus string, engineStatus ...[]taskflow.EngineStatus) error {
	return backendCapabilityError("TouchNodeState")
}

func (unsupportedRuntimeBackend) UpdateFinding(ctx context.Context, id, status, actor string) (taskflow.Finding, error) {
	return taskflow.Finding{}, backendCapabilityError("UpdateFinding")
}

func (unsupportedRuntimeBackend) UpdateFindingDisposition(ctx context.Context, id string, in FindingDisposition, actor string) (taskflow.Finding, error) {
	return taskflow.Finding{}, backendCapabilityError("UpdateFindingDisposition")
}

func (unsupportedRuntimeBackend) UpdateRuntimeTaskProgress(ctx context.Context, worker string, update taskflow.ProgressUpdate) error {
	return backendCapabilityError("UpdateRuntimeTaskProgress")
}

func (unsupportedRuntimeBackend) UpdateSchedule(ctx context.Context, id string, in taskflow.Schedule, actor string) (taskflow.Schedule, error) {
	return taskflow.Schedule{}, backendCapabilityError("UpdateSchedule")
}

var _ RuntimeBackend = unsupportedRuntimeBackend{}
