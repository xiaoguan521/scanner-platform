package api

import (
	"scanner-platform/internal/account"
	"scanner-platform/internal/approvals"
	"scanner-platform/internal/assets"
	"scanner-platform/internal/repo"
	"scanner-platform/internal/reporting"
	"scanner-platform/internal/rules"
	"scanner-platform/internal/scanplans"
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
type PageListResponse[T any] struct {
	Items    []T `json:"items"`
	Total    int `json:"total"`
	Page     int `json:"page"`
	PageSize int `json:"pageSize"`
}
type ScopePageResponse struct {
	Items         []approvals.Scope `json:"items"`
	Total         int               `json:"total"`
	Page          int               `json:"page"`
	PageSize      int               `json:"pageSize"`
	ExpiringCount int               `json:"expiringCount"`
	ExpiredCount  int               `json:"expiredCount"`
}
type TaskPageResponse struct {
	Items        []taskflow.Task `json:"items"`
	Total        int             `json:"total"`
	Page         int             `json:"page"`
	PageSize     int             `json:"pageSize"`
	StatusCounts map[string]int  `json:"statusCounts"`
}
type FindingPageResponse struct {
	Items    []taskflow.Finding     `json:"items"`
	Total    int                    `json:"total"`
	Page     int                    `json:"page"`
	PageSize int                    `json:"pageSize"`
	Counts   repo.FindingListCounts `json:"counts"`
}
type ReportPageResponse struct {
	Items    []reporting.Job `json:"items"`
	Total    int             `json:"total"`
	Page     int             `json:"page"`
	PageSize int             `json:"pageSize"`
}
type APIError struct {
	Code string `json:"code"`
	// Error is a deprecated compatibility alias. New clients should use Code.
	Error     string `json:"error"`
	Message   string `json:"message"`
	Hint      string `json:"hint"`
	RequestID string `json:"request_id"`
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
type ScanPlanDTO = scanplans.Plan
type SystemSettingsDTO = repo.SystemSettings
type NotificationSettingsDTO = repo.NotificationSettings
type NotificationDeliveryDTO = repo.NotificationDelivery
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
