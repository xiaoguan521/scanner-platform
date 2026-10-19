// Package taskflow contains the task protocol shared by Server and Worker.
package taskflow

import (
	"scanner-platform/internal/scheduler"
	"time"
)

type TaskInput struct {
	Synthetic   bool               `json:"synthetic"`
	Engine      string             `json:"engine,omitempty"`
	Scheme      string             `json:"scheme,omitempty"`
	InputPath   string             `json:"inputPath,omitempty"`
	InputKind   string             `json:"inputKind,omitempty"`
	Targets     []string           `json:"targets"`
	TimeWindows []scheduler.Window `json:"timeWindows"`
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

const MaxReportBytes = 4 << 20

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
	ID              string             `json:"id"`
	ScopeID         string             `json:"scopeId"`
	ScopeName       string             `json:"scopeName"`
	Engines         []string           `json:"engines"`
	Status          string             `json:"status"`
	HardDeadline    string             `json:"hardDeadline"`
	TotalChunks     int                `json:"totalChunks"`
	CompletedChunks int                `json:"completedChunks"`
	TargetCount     int                `json:"targetCount"`
	CreatedAt       time.Time          `json:"createdAt"`
	Chunks          []Chunk            `json:"chunks"`
	Synthetic       bool               `json:"synthetic"`
	SkippedTargets  []string           `json:"skippedTargets"`
	TimeWindows     []scheduler.Window `json:"timeWindows"`
	RuleVersion     string             `json:"ruleVersion"`
	InputPath       string             `json:"inputPath,omitempty"`
	InputKind       string             `json:"inputKind,omitempty"`
	Scheme          string             `json:"scheme,omitempty"`
	Error           string             `json:"error,omitempty"`
}

type Finding struct {
	ID                string    `json:"id"`
	TaskID            string    `json:"taskId"`
	Fingerprint       string    `json:"fingerprint"`
	Severity          string    `json:"severity"`
	Title             string    `json:"title"`
	Engine            string    `json:"engine"`
	TemplateOrCVE     string    `json:"templateOrCve"`
	Target            string    `json:"target"`
	Status            string    `json:"status"`
	FirstSeen         time.Time `json:"firstSeen"`
	LastSeen          time.Time `json:"lastSeen"`
	ConsecutiveMisses int       `json:"consecutiveMisses"`
	BusinessGroup     string    `json:"businessGroup"`
	Owner             string    `json:"owner"`
	VerifiedInRun     bool      `json:"verifiedInRun"`
	Synthetic         bool      `json:"synthetic"`
	MatchedPath       string    `json:"matchedPath,omitempty"`
	Package           string    `json:"package,omitempty"`
	InstalledVersion  string    `json:"installedVersion,omitempty"`
	FixedVersion      string    `json:"fixedVersion,omitempty"`
	ArtifactID        string    `json:"artifactId,omitempty"`
	Description       string    `json:"description,omitempty"`
}

// Detection is normalized engine output. Raw requests, responses and credentials
// are intentionally absent from the persisted result protocol.
type Detection struct {
	Engine           string `json:"engine"`
	TemplateID       string `json:"templateId"`
	Target           string `json:"target"`
	Title            string `json:"title"`
	Severity         string `json:"severity"`
	MatchedPath      string `json:"matchedPath,omitempty"`
	Package          string `json:"package,omitempty"`
	InstalledVersion string `json:"installedVersion,omitempty"`
	FixedVersion     string `json:"fixedVersion,omitempty"`
	ArtifactID       string `json:"artifactId,omitempty"`
	Description      string `json:"description,omitempty"`
}

type Report struct {
	TaskID   string      `json:"taskId"`
	WorkerID string      `json:"workerId"`
	Target   string      `json:"target"`
	Title    string      `json:"title"`
	Status   string      `json:"status,omitempty"`
	Error    string      `json:"error,omitempty"`
	Findings []Detection `json:"findings,omitempty"`
}

// EngineStatus is based on local binary and data checks, not a successful scan.
type EngineStatus struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Installed bool   `json:"installed"`
	Ready     bool   `json:"ready"`
	Message   string `json:"message"`
}
