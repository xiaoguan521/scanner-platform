package repo

import (
	"context"
	"errors"
	"os"
	"time"

	"scanner-platform/internal/assets"
	"scanner-platform/internal/findings"
	"scanner-platform/internal/reporting"
	"scanner-platform/internal/rules"
	"scanner-platform/internal/scanplans"
	"scanner-platform/internal/taskflow"
)

// ErrBackendCapability is returned when a selected backend does not yet
// implement an optional administrative surface. The Server must surface this
// as an unavailable capability instead of silently reading a second store.
var ErrBackendCapability = errors.New("selected storage backend capability is unavailable")

// RuntimeBackend is the Server-owned persistence surface used by the HTTP
// runtime. Keeping the API on a storage contract lets the Server select the
// SQLite portable backend or the PostgreSQL control-plane backend without
// silently mixing task, finding and report data between databases.
//
// Implementations must preserve the same authorization, lease and lifecycle
// invariants. A backend may return ErrBackendCapability for an endpoint that
// is not implemented yet; it must never fall back to a second database.
type RuntimeBackend interface {
	AddFindingNote(ctx context.Context, id, body, actor string) (FindingNote, error)
	AssignFinding(ctx context.Context, id, assigneeID, actor string) (taskflow.Finding, error)
	BatchAssignFindings(ctx context.Context, in FindingBatchAssignment, actor string) ([]taskflow.Finding, error)
	BatchFindingDisposition(ctx context.Context, in FindingBatchDisposition, actor string) ([]taskflow.Finding, error)
	CancelTask(ctx context.Context, id, actor string) error
	ClaimRuleJob(ctx context.Context, nodeID string) (*rules.Job, error)
	ClaimRuntimeTask(ctx context.Context, worker string) (*taskflow.Task, error)
	ClaimRuntimeTaskWithRules(ctx context.Context, worker, localRuleVersion string, rulesReady bool) (*taskflow.Task, error)
	Close() error
	CompleteRuntimeTask(ctx context.Context, report taskflow.Report) error
	CountRunningByVersion(ctx context.Context, nodeID, version string) (int, error)
	CreateFindingRetest(ctx context.Context, findingID, actor string) (taskflow.Task, FindingRetest, error)
	CreateLocalTask(ctx context.Context, in taskflow.TaskInput, actor string) (taskflow.Task, error)
	CreateReport(ctx context.Context, input reporting.Request, actor string) (reporting.Job, error)
	CreateReportFormat(ctx context.Context, id, format, actor string) (reporting.Job, error)
	CreateSyntheticTask(ctx context.Context) (taskflow.Task, error)
	DeleteCustomRule(ctx context.Context, id, actor string) error
	DeleteKnowledge(ctx context.Context, id, actor string) error
	DeleteRuntimeTask(ctx context.Context, id, actor string) error
	DeleteScanPlan(ctx context.Context, id, actor string) error
	DeleteSchedule(ctx context.Context, id, actor string) error
	DispatchNotificationOutbox(ctx context.Context) (int, error)
	ExpireAcceptedRisks(ctx context.Context, now time.Time) error
	GetNotificationSettings(ctx context.Context) (NotificationSettings, error)
	GetReport(ctx context.Context, id string) (reporting.Job, error)
	GetReportTemplate(ctx context.Context, id string) (reporting.Template, error)
	GetRuntimeTask(ctx context.Context, id string) (taskflow.Task, error)
	GetScanPolicy(ctx context.Context) (ScanPolicy, error)
	GetSystemSettings(ctx context.Context) (SystemSettings, error)
	ImportKnowledge(ctx context.Context, items []findings.KnowledgeEntry, actor string) error
	InitReports(ctx context.Context) error
	ListAuditLogs(ctx context.Context, query AuditLogQuery) ([]AuditLog, int, error)
	ListCustomRules(ctx context.Context) ([]rules.CustomRule, error)
	ListCustomRulesPage(ctx context.Context, in CustomRuleListQuery) (CustomRuleListPage, error)
	ListFindingAssignees(ctx context.Context) ([]FindingAssignee, error)
	ListFindingAssignmentEvents(ctx context.Context, id string) ([]FindingAssignmentEvent, error)
	ListFindingEvents(ctx context.Context, id string) ([]FindingEvent, error)
	ListFindingNotes(ctx context.Context, id string) ([]FindingNote, error)
	ListFindingRetests(ctx context.Context, findingID string) ([]FindingRetest, error)
	ListKnowledge(ctx context.Context) ([]findings.KnowledgeEntry, error)
	ListKnowledgePage(ctx context.Context, query KnowledgeListQuery) (KnowledgeListPage, error)
	ListNodes(ctx context.Context) ([]LocalNode, error)
	ListNodesPage(ctx context.Context, in NodeListQuery) (NodeListPage, error)
	ListNotificationDeliveries(ctx context.Context, limit, offset int) (NotificationDeliveryList, error)
	ListNotifications(ctx context.Context, unreadOnly bool) (NotificationList, error)
	ListNotificationsPage(ctx context.Context, query NotificationListQuery) (NotificationListPage, error)
	ListQuarantines(ctx context.Context) ([]map[string]any, error)
	ListReportTemplates(ctx context.Context) ([]reporting.Template, error)
	ListReports(ctx context.Context) ([]reporting.Job, error)
	ListReportsPage(ctx context.Context, in ReportListQuery) (ReportListPage, error)
	ListRuleJobs(ctx context.Context) ([]rules.Job, error)
	ListRuleJobsPage(ctx context.Context, in RuleJobListQuery) (RuleJobListPage, error)
	ListRules(ctx context.Context) ([]rules.Bundle, error)
	ListRulesPage(ctx context.Context, in RuleListQuery) (RuleListPage, error)
	ListRuntimeAssets(ctx context.Context) ([]assets.Asset, error)
	ListRuntimeFindings(ctx context.Context) ([]taskflow.Finding, error)
	ListRuntimeFindingsPage(ctx context.Context, in FindingListQuery) (FindingListPage, error)
	ListRuntimeTasks(ctx context.Context) ([]taskflow.Task, error)
	ListRuntimeTasksPage(ctx context.Context, in TaskListQuery) (TaskListPage, error)
	ListScanPlans(ctx context.Context) ([]scanplans.Plan, error)
	ListScheduleRuns(ctx context.Context, scheduleID string, limit, offset int) ([]taskflow.ScheduleRun, int, error)
	ListSchedules(ctx context.Context) ([]taskflow.Schedule, error)
	ListTaskFindings(ctx context.Context, id string) ([]taskflow.Finding, error)
	ListTaskLogs(ctx context.Context, taskID string) ([]TaskLog, error)
	MarkAllNotificationsRead(ctx context.Context) error
	MarkNotificationRead(ctx context.Context, id string) error
	OpenReport(ctx context.Context, id string) (reporting.Job, *os.File, error)
	PauseTask(ctx context.Context, id, actor string) error
	ProcessNextReport(ctx context.Context, directory string) (bool, error)
	QueueRuleJob(ctx context.Context, job rules.Job, actor string) (rules.Job, error)
	RecoverReports(ctx context.Context) error
	RefreshNotifications(ctx context.Context) error
	ReleaseQuarantine(ctx context.Context, assetID string, port int, reason, actor string) error
	RenewChunkLease(ctx context.Context, taskID, workerID, pinnedRuleVersion string) (time.Time, error)
	ReportRuleJob(ctx context.Context, report rules.Report) error
	ReportSnapshot(ctx context.Context, id string) (reporting.Snapshot, error)
	ResumeTask(ctx context.Context, id, actor string) error
	RetryReport(ctx context.Context, id, actor string) (reporting.Job, error)
	RunReports(ctx context.Context, directory string) error
	SaveCustomRule(ctx context.Context, actor string, input rules.CustomRule, create bool) (rules.CustomRule, error)
	SaveKnowledge(ctx context.Context, k findings.KnowledgeEntry, actor string) (findings.KnowledgeEntry, error)
	SaveNotificationSettings(ctx context.Context, settings NotificationSettings, actor string) (NotificationSettings, error)
	SaveReportTemplate(ctx context.Context, t reporting.Template, actor string) (reporting.Template, error)
	SaveScanPlan(ctx context.Context, actor string, input scanplans.Input, id string, update bool) (scanplans.Plan, error)
	SaveScanPolicy(ctx context.Context, p ScanPolicy, actor string) (ScanPolicy, error)
	SaveSchedule(ctx context.Context, in taskflow.Schedule, actor string) (taskflow.Schedule, error)
	SaveSystemSettings(ctx context.Context, settings SystemSettings, actor string) (SystemSettings, error)
	SetTaskArchived(ctx context.Context, id, actor string, archived bool) error
	SyncRules(ctx context.Context, bundles []rules.Bundle) error
	TaskStateForWorker(ctx context.Context, id, worker string) string
	Tick(ctx context.Context, now time.Time) error
	ToggleSchedule(ctx context.Context, id, actor string, enabled bool) error
	TouchNode(ctx context.Context, id, kind, task string, engineStatus ...[]taskflow.EngineStatus) error
	TouchNodeState(ctx context.Context, id, kind, task, localRuleVersion, nodeStatus string, engineStatus ...[]taskflow.EngineStatus) error
	UpdateFinding(ctx context.Context, id, status, actor string) (taskflow.Finding, error)
	UpdateFindingDisposition(ctx context.Context, id string, in FindingDisposition, actor string) (taskflow.Finding, error)
	UpdateRuntimeTaskProgress(ctx context.Context, worker string, update taskflow.ProgressUpdate) error
	UpdateSchedule(ctx context.Context, id string, in taskflow.Schedule, actor string) (taskflow.Schedule, error)
}

var _ RuntimeBackend = (*RuntimeStore)(nil)
