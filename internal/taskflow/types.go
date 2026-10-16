// Package taskflow contains the task protocol shared by Server and Worker.
package taskflow

import "time"

const SyntheticTitle = "模拟发现项：任务链路已完成（未执行真实扫描）"

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
	ID              string    `json:"id"`
	ScopeID         string    `json:"scopeId"`
	ScopeName       string    `json:"scopeName"`
	Engines         []string  `json:"engines"`
	Status          string    `json:"status"`
	HardDeadline    string    `json:"hardDeadline"`
	TotalChunks     int       `json:"totalChunks"`
	CompletedChunks int       `json:"completedChunks"`
	TargetCount     int       `json:"targetCount"`
	CreatedAt       time.Time `json:"createdAt"`
	Chunks          []Chunk   `json:"chunks"`
	Synthetic       bool      `json:"synthetic"`
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
}

type Report struct {
	TaskID   string `json:"taskId"`
	WorkerID string `json:"workerId"`
	Target   string `json:"target"`
	Title    string `json:"title"`
}
