package repo

import (
	"context"
	"time"
)

// These are storage contracts only. SQL migrations, credentials, transactions
// and backends are not connected in Phase 0. Only sec-server may own a
// production Repository; Worker and Updater communicate via authenticated API.

type Asset struct {
	ID            string
	Kind          string
	Address       string
	ResolvedIP    string
	BusinessGroup string
	Owner         string
}

type AuthorizedScope struct {
	ID             string
	CIDROrHost     string
	MaxTargets     int
	ApprovedBy     string
	ApprovalTicket string
	ExpiresAt      time.Time
	Active         bool
}

type ScanTask struct {
	ID           string
	ScopeID      string
	Status       string
	HardDeadline time.Time
	CreatedBy    string
}

type TaskChunk struct {
	ID                string
	TaskID            string
	Status            string
	WorkerNodeID      string
	PinnedRuleVersion string
	LeaseExpiresAt    time.Time
	CompletedFully    bool
}

// AssetReader is implemented by the future SQLite/PostgreSQL backends.
type AssetReader interface {
	ListAssets(context.Context) ([]Asset, error)
	GetScope(context.Context, string) (AuthorizedScope, error)
}

// TaskStore must implement atomic claim/complete semantics; it is NEVER
// directly accessible from sec-worker or sec-updater.
type TaskStore interface {
	CreateTask(context.Context, ScanTask) error
	ClaimChunk(context.Context, string) (TaskChunk, error)
	CompleteChunk(context.Context, string, bool) error
}

// LeaseRegistry must use a Server-owned transaction and pinned rule version.
// It is the future backing service for scheduler.Renewer and versionmgr.RunningTasks.
type LeaseRegistry interface {
	RenewChunkLease(context.Context, string, string, string) (time.Time, error)
	CountRunningByVersion(context.Context, string, string) (int, error)
}
