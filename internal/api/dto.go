package api

import (
	"scanner-platform/internal/account"
	"scanner-platform/internal/approvals"
	"scanner-platform/internal/assets"
	"scanner-platform/internal/repo"
	"scanner-platform/internal/rules"
	"scanner-platform/internal/scheduler"
	"scanner-platform/internal/taskflow"
	"time"
)

// These aliases keep the HTTP contract identical to the served JSON models.
// They never expose database credentials, password hashes or session tokens.
type ListResponse[T any] struct {
	Items []T `json:"items"`
	Total int `json:"total"`
}
type APIError struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}
type UserDTO = account.User
type AssetDTO = assets.Asset
type AssetPortDTO = assets.Port
type NewAssetRequestDTO = assets.Input
type EditAssetRequestDTO = assets.Edit
type TimeWindowDTO = scheduler.Window
type AuthorizedScopeDTO = approvals.Scope
type TaskChunkDTO = taskflow.Chunk
type ScanTaskDTO = taskflow.Task
type NewTaskRequestDTO = taskflow.TaskInput
type ScheduleDTO = taskflow.Schedule
type FindingDTO = taskflow.Finding
type DetectionDTO = taskflow.Detection
type WorkerReportDTO = taskflow.Report
type EngineStatusDTO = taskflow.EngineStatus
type NodeInfoDTO = repo.LocalNode
type RuleBundleDTO = rules.Bundle
type RuleJobDTO = rules.Job
type PortQuarantineDTO struct {
	AssetID    string     `json:"assetId"`
	Address    string     `json:"address"`
	Port       int        `json:"port"`
	Reason     string     `json:"reason"`
	DetectedAt time.Time  `json:"detectedAt"`
	Status     string     `json:"status"`
	ReviewedBy string     `json:"reviewedBy,omitempty"`
	ReviewedAt *time.Time `json:"reviewedAt,omitempty"`
}
