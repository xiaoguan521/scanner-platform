package api

import "time"

// DTOs model the future UI JSON responses. Repository persistence models are
// deliberately separate. At Phase 0 these are schemas, not enabled handlers.
// Datetimes use RFC 3339 via time.Time JSON encoding.

type ListResponse[T any] struct {
	Items []T `json:"items"`
	Total int `json:"total"`
}

type APIError struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

type UserDTO struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Role     string `json:"role"`
	IsActive bool   `json:"isActive"`
}

type AssetPortDTO struct {
	Port   int    `json:"port"`
	Kind   string `json:"kind"`
	Source string `json:"source"`
}
type AssetDTO struct {
	ID               string         `json:"id"`
	Kind             string         `json:"kind"`
	Address          string         `json:"address"`
	ResolvedIP       string         `json:"resolvedIp,omitempty"`
	BusinessGroup    string         `json:"businessGroup"`
	Owner            string         `json:"owner"`
	CreatedAt        time.Time      `json:"createdAt"`
	Ports            []AssetPortDTO `json:"ports"`
	QuarantinedPorts []int          `json:"quarantinedPorts,omitempty"`
}
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
type TimeWindowDTO struct {
	Weekdays []int  `json:"weekdays"`
	Start    string `json:"start"`
	End      string `json:"end"`
	TimeZone string `json:"timeZone"`
}
type AuthorizedScopeDTO struct {
	ID             string          `json:"id"`
	CIDROrHost     string          `json:"cidrOrHost"`
	MaxTargets     int             `json:"maxTargets"`
	TimeWindows    []TimeWindowDTO `json:"timeWindows"`
	ApprovedBy     string          `json:"approvedBy"`
	ApprovalTicket string          `json:"approvalTicket"`
	ExpiresAt      time.Time       `json:"expiresAt"`
	IsActive       bool            `json:"isActive"`
}
type TaskChunkDTO struct {
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
type ScanTaskDTO struct {
	ID              string         `json:"id"`
	ScopeID         string         `json:"scopeId"`
	ScopeName       string         `json:"scopeName"`
	Engines         []string       `json:"engines"`
	Status          string         `json:"status"`
	HardDeadline    time.Time      `json:"hardDeadline"`
	TotalChunks     int            `json:"totalChunks"`
	CompletedChunks int            `json:"completedChunks"`
	TargetCount     int            `json:"targetCount"`
	CreatedAt       time.Time      `json:"createdAt"`
	Chunks          []TaskChunkDTO `json:"chunks"`
}
type FindingDTO struct {
	ID                string    `json:"id"`
	Fingerprint       string    `json:"fingerprint"`
	Severity          string    `json:"severity"`
	Title             string    `json:"title"`
	Engine            string    `json:"engine"`
	TemplateOrCVE     string    `json:"templateOrCve"`
	Target            string    `json:"target"`
	Port              *int      `json:"port,omitempty"`
	Status            string    `json:"status"`
	FirstSeen         time.Time `json:"firstSeen"`
	LastSeen          time.Time `json:"lastSeen"`
	ConsecutiveMisses int       `json:"consecutiveMisses"`
	BusinessGroup     string    `json:"businessGroup"`
	Owner             string    `json:"owner"`
	VerifiedInRun     bool      `json:"verifiedInRun"`
}
type NodeInfoDTO struct {
	ID               string    `json:"id"`
	Kind             string    `json:"kind"`
	HostID           string    `json:"hostId"`
	IP               string    `json:"ip"`
	Status           string    `json:"status"`
	CurrentTask      string    `json:"currentTask,omitempty"`
	BoundRuleVersion string    `json:"boundRuleVersion,omitempty"`
	LastHeartbeat    time.Time `json:"lastHeartbeat"`
	FenceStatus      string    `json:"fenceStatus"`
	DropCount        int       `json:"dropCount"`
}
type RuleBundleDTO struct {
	Version        string    `json:"version"`
	Channel        string    `json:"channel"`
	ManifestSHA256 string    `json:"manifestSha256"`
	PublishedAt    time.Time `json:"publishedAt"`
	IsCurrent      bool      `json:"isCurrent"`
	IsBackup       bool      `json:"isBackup"`
	InUseByTasks   int       `json:"inUseByTasks"`
}
