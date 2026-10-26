// Package taskflow contains the task protocol shared by Server and Worker.
package taskflow

import (
	"context"
	"encoding/json"
	"scanner-platform/internal/inventory"
	"scanner-platform/internal/portprobe"
	"scanner-platform/internal/scheduler"
	"strings"
	"time"
)

type TaskInput struct {
	Synthetic     bool               `json:"synthetic"`
	Engine        string             `json:"engine,omitempty"`
	Scheme        string             `json:"scheme,omitempty"`
	InputPath     string             `json:"inputPath,omitempty"`
	InputKind     string             `json:"inputKind,omitempty"`
	AssetID       string             `json:"assetId,omitempty"`
	PortProbe     portprobe.Config   `json:"portProbe,omitempty"`
	CustomRuleIDs []string           `json:"customRuleIds,omitempty"`
	Targets       []string           `json:"targets"`
	TimeWindows   []scheduler.Window `json:"timeWindows"`
}

type Schedule struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	TaskInput
	NextRun         string `json:"nextRun"`
	IntervalMinutes int    `json:"intervalMinutes"`
	Enabled         bool   `json:"enabled"`
	LastTaskID      string `json:"lastTaskId"`
	LastError       string `json:"lastError"`
	CreatedBy       string `json:"createdBy"`
}

// ScheduleRun is the safe execution history projection for a persisted
// schedule. It contains no task input, target or engine output.
type ScheduleRun struct {
	ID          string `json:"id"`
	ScheduleID  string `json:"scheduleId"`
	TaskID      string `json:"taskId"`
	TriggeredAt string `json:"triggeredAt"`
	Status      string `json:"status"`
	Error       string `json:"error,omitempty"`
}

const SyntheticTitle = "模拟发现项：任务链路已完成（未执行真实扫描）"

const (
	NodeStatusWaitingForRules  = "WAITING_FOR_RULES"
	NodeStatusRulesError       = "RULES_ERROR"
	SystemScanNotStarted       = "未采集：自动综合扫描在系统包检查前失败或中止"
	SystemScanNotConfigured    = "未配置 Worker 本地 SSH 采集"
	SystemScanPortOutOfScope   = "未采集：配置的 SSH 端口不在本次明确范围内"
	SystemScanPortClosed       = "未采集：SSH 端口未探测为开放"
	SystemScanClientMissing    = "未采集：Worker 未安装 OpenSSH 客户端"
	SystemScanHostKeyMismatch  = "未采集：SSH 主机指纹未匹配 Worker 本地 known_hosts"
	SystemScanAuthFailed       = "未采集：SSH 公钥认证失败，请检查密钥或 SSH Agent"
	SystemScanPythonMissing    = "未采集：目标服务器没有可用的 Python 3"
	SystemScanCollectionFailed = "未采集：SSH 连接或临时采集失败，请检查网络与目标系统"
	SystemScanInvalidSnapshot  = "未采集：SSH 返回的离线快照校验失败"
	SystemScanTrivyUnavailable = "未完成：Worker Trivy 引擎或本地漏洞库不可用"
	SystemScanUnsupportedOS    = "未完成：目标 Linux 发行版尚未适配漏洞源"
	SystemScanTrivyFailed      = "未完成：Trivy 系统包分析失败，请检查 Worker 本地日志"
	SystemScanCompleted        = "已通过 SSH 临时采集并完成本地系统包检查"
)

const MaxReportBytes = 32 << 20

// MaxUnconfirmedPorts bounds the list of ports whose state could not be decided.
const MaxUnconfirmedPorts = 1000

// Application scan reports contain configured aliases and bounded counters,
// never remote deployment paths, file names, credentials or engine output.
const (
	ApplicationScanNotConfigured    = "not_configured"
	ApplicationScanNotStarted       = "not_started"
	ApplicationScanPortOutOfScope   = "port_out_of_scope"
	ApplicationScanCollecting       = "collecting"
	ApplicationScanCollectionFailed = "collection_failed"
	ApplicationScanScanning         = "scanning"
	ApplicationScanAnalysisFailed   = "analysis_failed"
	ApplicationScanCompleted        = "completed"
)

type ApplicationResult struct {
	Alias         string `json:"alias"`
	Status        string `json:"status"`
	SelectedCount int    `json:"selectedCount"`
	AnalyzedCount int    `json:"analyzedCount"`
}

// ExecutionError exposes a deliberate, static user-facing explanation. Do not
// construct UserMessage from engine output, paths, credentials or raw requests.
type ExecutionError struct {
	UserMessage string
}

func (e *ExecutionError) Error() string { return e.UserMessage }

type Chunk struct {
	ID                string     `json:"id"`
	TaskID            string     `json:"taskId"`
	WorkerNodeID      string     `json:"workerNodeId,omitempty"`
	PinnedRuleVersion string     `json:"pinnedRuleVersion,omitempty"`
	LeaseExpiresAt    *time.Time `json:"leaseExpiresAt,omitempty"`
	Targets           []string   `json:"targets"`
	Status            string     `json:"status"`
	CompletedFully    bool       `json:"completedFully"`
	StartedAt         *time.Time `json:"startedAt,omitempty"`
	FinishedAt        *time.Time `json:"finishedAt,omitempty"`
}

type Task struct {
	EffectiveExclusions []portprobe.Range  `json:"effectiveExclusions,omitempty"`
	QuarantinedPorts    []int              `json:"quarantinedPorts,omitempty"`
	ID                  string             `json:"id"`
	ScopeID             string             `json:"scopeId"`
	ScopeName           string             `json:"scopeName"`
	Engines             []string           `json:"engines"`
	Status              string             `json:"status"`
	Archived            bool               `json:"archived,omitempty"`
	FindingCount        int                `json:"findingCount"`
	HardDeadline        string             `json:"hardDeadline"`
	TotalChunks         int                `json:"totalChunks"`
	CompletedChunks     int                `json:"completedChunks"`
	TargetCount         int                `json:"targetCount"`
	CreatedAt           time.Time          `json:"createdAt"`
	Chunks              []Chunk            `json:"chunks"`
	Synthetic           bool               `json:"synthetic"`
	SkippedTargets      []string           `json:"skippedTargets"`
	TimeWindows         []scheduler.Window `json:"timeWindows"`
	RuleVersion         string             `json:"ruleVersion"`
	// FixedThreshold is frozen with the task and used only by the Server when
	// evaluating the finding lifecycle. It is deliberately not sent to Worker.
	FixedThreshold        int                 `json:"-"`
	InputPath             string              `json:"inputPath,omitempty"`
	InputKind             string              `json:"inputKind,omitempty"`
	Scheme                string              `json:"scheme,omitempty"`
	AssetID               string              `json:"assetId,omitempty"`
	PortProbeConfig       portprobe.Config    `json:"portProbeConfig,omitempty"`
	PortProbePorts        []int               `json:"portProbePorts,omitempty"`
	PortProbeResults      []PortProbeResult   `json:"portProbeResults,omitempty"`
	TCPWrapped            int                 `json:"tcpWrapped,omitempty"`
	UnconfirmedPorts      []int               `json:"unconfirmedPorts,omitempty"`
	VulnerabilityPorts    []int               `json:"vulnerabilityPorts,omitempty"`
	CustomTemplates       []json.RawMessage   `json:"customTemplates,omitempty"`
	CustomRuleCount       int                 `json:"customRuleCount,omitempty"`
	ServiceResults        []ServiceResult     `json:"serviceResults,omitempty"`
	SystemScanStatus      string              `json:"systemScanStatus,omitempty"`
	ApplicationScanStatus string              `json:"applicationScanStatus,omitempty"`
	ApplicationResults    []ApplicationResult `json:"applicationResults,omitempty"`
	RetestFindingID       string              `json:"retestFindingId,omitempty"`
	RequireInputSnapshot  bool                `json:"-"`
	ExpectedArtifactType  string              `json:"-"`
	Progress              *TaskProgress       `json:"progress,omitempty"`
	AssetProfile          inventory.Profile   `json:"assetProfile,omitempty"`
	Error                 string              `json:"error,omitempty"`
	// FenceStatus and DropCount are optional execution telemetry reported by a
	// kernel-enforced Worker fence. They never broaden the authorized scope.
	FenceStatus string `json:"fenceStatus,omitempty"`
	DropCount   uint64 `json:"dropCount,omitempty"`
}

// TaskProgress is advisory execution telemetry. It never changes scan scope,
// authorization, findings, or task completion state.
// PhaseCount is the final n/m of a phase the task has already moved past.
type PhaseCount struct {
	Completed int `json:"completed"`
	Total     int `json:"total"`
}

type TaskProgress struct {
	Phase     string    `json:"phase"`
	Completed int       `json:"completed"`
	Total     int       `json:"total"`
	UpdatedAt time.Time `json:"updatedAt"`
	// Phases holds the final counts of earlier phases, so the UI can show that
	// each phase worked on the result of the previous one (open ports, HTTP
	// services) while a later phase is still running.
	Phases map[string]PhaseCount `json:"phases,omitempty"`
	// OpenPorts and HTTPPorts are the ports found so far, reported while the
	// scan is still running. They are omitted when longer than MaxLivePorts.
	OpenPorts []int `json:"openPorts,omitempty"`
	HTTPPorts []int `json:"httpPorts,omitempty"`
	// Services is a compact view of the identified services (no login entries,
	// URLs or evidence); the complete inventory arrives with the final report.
	Services []LiveService `json:"services,omitempty"`
}

// LiveService is the small projection of a service shown while a task runs.
type LiveService struct {
	Port     int    `json:"port"`
	Kind     string `json:"kind"`
	Scheme   string `json:"scheme,omitempty"`
	Software string `json:"software,omitempty"`
	Version  string `json:"version,omitempty"`
	Title    string `json:"title,omitempty"`
	TLS      bool   `json:"tls,omitempty"`
}

// MaxLiveServices and MaxLiveText bound the live service list; a longer list
// is omitted and the UI waits for the final report.
const (
	MaxLiveServices = 128
	MaxLiveText     = 120
)

// MaxLivePorts bounds the live port lists carried by progress telemetry. A host
// with more open ports is unusual; the UI then falls back to counts and the
// complete list arrives with the final report.
const MaxLivePorts = 512

// FenceTelemetry is the small trusted projection returned by a fenced Worker.
// Raw firewall rules, addresses and packet contents never cross this boundary.
type FenceTelemetry struct {
	Status    string
	DropCount uint64
}

// ProgressUpdate is sent by a Worker in its existing heartbeat.
type ProgressUpdate struct {
	TaskID    string        `json:"taskId"`
	Phase     string        `json:"phase"`
	Completed int           `json:"completed"`
	Total     int           `json:"total"`
	OpenPorts []int         `json:"openPorts,omitempty"`
	HTTPPorts []int         `json:"httpPorts,omitempty"`
	Services  []LiveService `json:"services,omitempty"`
}

type ProgressReporter func(TaskProgress)

type progressReporterKey struct{}

// WithProgressReporter adds an in-memory progress callback to a task context.
func WithProgressReporter(ctx context.Context, reporter ProgressReporter) context.Context {
	return context.WithValue(ctx, progressReporterKey{}, reporter)
}

// ReportProgress publishes bounded phase telemetry when a Worker installed a
// reporter. It intentionally does not retain any scan output or target data.
func ReportProgress(ctx context.Context, phase string, completed, total int) {
	reporter, ok := ctx.Value(progressReporterKey{}).(ProgressReporter)
	if !ok || reporter == nil {
		return
	}
	reporter(TaskProgress{Phase: phase, Completed: completed, Total: total, UpdatedAt: time.Now().UTC()})
}

// Found is what a phase has discovered so far.
type Found struct {
	Open, HTTP []int
	Services   []ServiceResult
}

// LiveServices projects identified services to their compact live form, or nil
// when there are too many to carry in progress telemetry.
func LiveServices(services []ServiceResult) []LiveService {
	if len(services) > MaxLiveServices {
		return nil
	}
	clip := func(value string) string {
		if len(value) <= MaxLiveText {
			return value
		}
		return strings.ToValidUTF8(value[:MaxLiveText], "")
	}
	out := make([]LiveService, 0, len(services))
	for _, service := range services {
		out = append(out, LiveService{Port: service.Port, Kind: service.Kind, Scheme: service.Scheme, Software: clip(service.Software), Version: clip(service.Version), Title: clip(service.Title), TLS: service.TLS})
	}
	return out
}

// ReportFound publishes what was discovered so far together with the phase
// counter. Port lists over MaxLivePorts are dropped, not truncated.
func ReportFound(ctx context.Context, phase string, completed, total int, found Found) {
	open, http := found.Open, found.HTTP
	reporter, ok := ctx.Value(progressReporterKey{}).(ProgressReporter)
	if !ok || reporter == nil {
		return
	}
	progress := TaskProgress{Phase: phase, Completed: completed, Total: total, UpdatedAt: time.Now().UTC()}
	if len(open) <= MaxLivePorts {
		progress.OpenPorts = append([]int(nil), open...)
	}
	if len(http) <= MaxLivePorts {
		progress.HTTPPorts = append([]int(nil), http...)
	}
	progress.Services = LiveServices(found.Services)
	reporter(progress)
}

// ReportProgressValue forwards a progress value received from the fenced child.
func ReportProgressValue(ctx context.Context, progress TaskProgress) {
	if reporter, ok := ctx.Value(progressReporterKey{}).(ProgressReporter); ok && reporter != nil {
		progress.UpdatedAt = time.Now().UTC()
		reporter(progress)
	}
}

// PortProbeResult records only a successful TCP connection. It contains no
// banner, protocol data, or service fingerprint.
type PortProbeResult struct {
	Port int `json:"port"`
}

// ServiceResult is limited to a bounded HTTP response check on an explicitly
// approved open port; it does not retain response content or arbitrary banners.
type ServiceResult = inventory.Service

type Finding struct {
	AssigneeID        string              `json:"assigneeId,omitempty"`
	AssigneeName      string              `json:"assigneeName,omitempty"`
	AcceptedReason    string              `json:"acceptedReason,omitempty"`
	AcceptedUntil     *time.Time          `json:"acceptedUntil,omitempty"`
	AssetID           string              `json:"assetId,omitempty"`
	ID                string              `json:"id"`
	TaskID            string              `json:"taskId"`
	Fingerprint       string              `json:"fingerprint"`
	Severity          string              `json:"severity"`
	Title             string              `json:"title"`
	Engine            string              `json:"engine"`
	TemplateOrCVE     string              `json:"templateOrCve"`
	Target            string              `json:"target"`
	Status            string              `json:"status"`
	FirstSeen         time.Time           `json:"firstSeen"`
	LastSeen          time.Time           `json:"lastSeen"`
	ConsecutiveMisses int                 `json:"consecutiveMisses"`
	BusinessGroup     string              `json:"businessGroup"`
	Owner             string              `json:"owner"`
	VerifiedInRun     bool                `json:"verifiedInRun"`
	ResolvedAt        *time.Time          `json:"resolvedAt,omitempty"`
	Synthetic         bool                `json:"synthetic"`
	MatchedPath       string              `json:"matchedPath,omitempty"`
	Package           string              `json:"package,omitempty"`
	InstalledVersion  string              `json:"installedVersion,omitempty"`
	FixedVersion      string              `json:"fixedVersion,omitempty"`
	ArtifactID        string              `json:"artifactId,omitempty"`
	Description       string              `json:"description,omitempty"`
	RiskType          string              `json:"riskType,omitempty"`
	DetectMethod      string              `json:"detectMethod,omitempty"`
	Confidence        string              `json:"confidence,omitempty"`
	CVSSScore         *float64            `json:"cvssScore,omitempty"`
	VulnCategory      string              `json:"vulnCategory,omitempty"`
	Identifiers       map[string][]string `json:"identifiers,omitempty"`
	Impact            string              `json:"impact,omitempty"`
	Solution          string              `json:"solution,omitempty"`
	References        []string            `json:"references,omitempty"`
	Evidence          string              `json:"evidence,omitempty"`
	Port              int                 `json:"port,omitempty"`
	Component         string              `json:"component,omitempty"`
	ContentLanguage   string              `json:"contentLanguage,omitempty"`
}

// Detection is normalized engine output. Raw requests, responses and credentials
// are intentionally absent from the persisted result protocol.
type Detection struct {
	AssetID          string              `json:"assetId,omitempty"`
	Engine           string              `json:"engine"`
	TemplateID       string              `json:"templateId"`
	Target           string              `json:"target"`
	Title            string              `json:"title"`
	Severity         string              `json:"severity"`
	MatchedPath      string              `json:"matchedPath,omitempty"`
	Package          string              `json:"package,omitempty"`
	InstalledVersion string              `json:"installedVersion,omitempty"`
	FixedVersion     string              `json:"fixedVersion,omitempty"`
	ArtifactID       string              `json:"artifactId,omitempty"`
	Description      string              `json:"description,omitempty"`
	RiskType         string              `json:"riskType,omitempty"`
	DetectMethod     string              `json:"detectMethod,omitempty"`
	Confidence       string              `json:"confidence,omitempty"`
	CVSSScore        *float64            `json:"cvssScore,omitempty"`
	VulnCategory     string              `json:"vulnCategory,omitempty"`
	Identifiers      map[string][]string `json:"identifiers,omitempty"`
	Impact           string              `json:"impact,omitempty"`
	Solution         string              `json:"solution,omitempty"`
	References       []string            `json:"references,omitempty"`
	Evidence         string              `json:"evidence,omitempty"`
	Port             int                 `json:"port,omitempty"`
	Component        string              `json:"component,omitempty"`
	ContentLanguage  string              `json:"contentLanguage,omitempty"`
}

type Report struct {
	TaskID                string              `json:"taskId"`
	WorkerID              string              `json:"workerId"`
	Target                string              `json:"target"`
	Title                 string              `json:"title"`
	Status                string              `json:"status,omitempty"`
	Error                 string              `json:"error,omitempty"`
	Findings              []Detection         `json:"findings,omitempty"`
	PortProbeResults      []PortProbeResult   `json:"portProbeResults,omitempty"`
	TCPWrapped            int                 `json:"tcpWrapped,omitempty"`
	UnconfirmedPorts      []int               `json:"unconfirmedPorts,omitempty"`
	ServiceResults        []ServiceResult     `json:"serviceResults,omitempty"`
	SystemScanStatus      string              `json:"systemScanStatus,omitempty"`
	ApplicationScanStatus string              `json:"applicationScanStatus,omitempty"`
	ApplicationResults    []ApplicationResult `json:"applicationResults,omitempty"`
	AssetProfile          inventory.Profile   `json:"assetProfile,omitempty"`
	FenceStatus           string              `json:"fenceStatus,omitempty"`
	DropCount             uint64              `json:"dropCount,omitempty"`
	// Completion metadata is a fail-closed gate for automatic FIXED updates.
	// Older Workers may omit it; such reports still ingest findings but cannot
	// mark missing findings as fixed.
	CompletedFully  bool     `json:"completedFully,omitempty"`
	RulesExecuted   bool     `json:"rulesExecuted,omitempty"`
	ExecutedEngines []string `json:"executedEngines,omitempty"`
	RuleVersion     string   `json:"ruleVersion,omitempty"`
}

type AutoResult struct {
	// TCPWrapped counts ports that completed the handshake but ran no service.
	TCPWrapped         int
	UnconfirmedPorts   []int
	Findings           []Detection
	Ports              []PortProbeResult
	Services           []ServiceResult
	SystemStatus       string
	ApplicationStatus  string
	ApplicationResults []ApplicationResult
	AssetProfile       inventory.Profile
	CompletedFully     bool
	RulesExecuted      bool
	ExecutedEngines    []string
}

// EngineStatus is based on local binary and data checks, not a successful scan.
type EngineStatus struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Installed bool   `json:"installed"`
	Ready     bool   `json:"ready"`
	Message   string `json:"message"`
}
