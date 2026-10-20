// Package taskflow contains the task protocol shared by Server and Worker.
package taskflow

import (
	"encoding/json"
	"scanner-platform/internal/inventory"
	"scanner-platform/internal/portprobe"
	"scanner-platform/internal/scheduler"
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

const SyntheticTitle = "模拟发现项：任务链路已完成（未执行真实扫描）"

const (
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

// ExecutionError exposes a deliberate, static user-facing explanation. Do not
// construct UserMessage from engine output, paths, credentials or raw requests.
type ExecutionError struct {
	UserMessage string
}

func (e *ExecutionError) Error() string { return e.UserMessage }

type Chunk struct {
	ID             string     `json:"id"`
	TaskID         string     `json:"taskId"`
	WorkerNodeID   string     `json:"workerNodeId,omitempty"`
	Targets        []string   `json:"targets"`
	Status         string     `json:"status"`
	CompletedFully bool       `json:"completedFully"`
	StartedAt      *time.Time `json:"startedAt,omitempty"`
	FinishedAt     *time.Time `json:"finishedAt,omitempty"`
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
	InputPath           string             `json:"inputPath,omitempty"`
	InputKind           string             `json:"inputKind,omitempty"`
	Scheme              string             `json:"scheme,omitempty"`
	AssetID             string             `json:"assetId,omitempty"`
	PortProbeConfig     portprobe.Config   `json:"portProbeConfig,omitempty"`
	PortProbePorts      []int              `json:"portProbePorts,omitempty"`
	PortProbeResults    []PortProbeResult  `json:"portProbeResults,omitempty"`
	VulnerabilityPorts  []int              `json:"vulnerabilityPorts,omitempty"`
	CustomTemplates     []json.RawMessage  `json:"customTemplates,omitempty"`
	CustomRuleCount     int                `json:"customRuleCount,omitempty"`
	ServiceResults      []ServiceResult    `json:"serviceResults,omitempty"`
	SystemScanStatus    string             `json:"systemScanStatus,omitempty"`
	AssetProfile        inventory.Profile  `json:"assetProfile,omitempty"`
	Error               string             `json:"error,omitempty"`
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
	TaskID           string            `json:"taskId"`
	WorkerID         string            `json:"workerId"`
	Target           string            `json:"target"`
	Title            string            `json:"title"`
	Status           string            `json:"status,omitempty"`
	Error            string            `json:"error,omitempty"`
	Findings         []Detection       `json:"findings,omitempty"`
	PortProbeResults []PortProbeResult `json:"portProbeResults,omitempty"`
	ServiceResults   []ServiceResult   `json:"serviceResults,omitempty"`
	SystemScanStatus string            `json:"systemScanStatus,omitempty"`
	AssetProfile     inventory.Profile `json:"assetProfile,omitempty"`
}

type AutoResult struct {
	Findings     []Detection
	Ports        []PortProbeResult
	Services     []ServiceResult
	SystemStatus string
	AssetProfile inventory.Profile
}

// EngineStatus is based on local binary and data checks, not a successful scan.
type EngineStatus struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Installed bool   `json:"installed"`
	Ready     bool   `json:"ready"`
	Message   string `json:"message"`
}
