package versionmgr

import (
	"context"
	"errors"
	"fmt"
	"time"
)

const DefaultGCGrace = 2 * time.Hour

var (
	ErrGCProtected  = errors.New("rules version protected from garbage collection")
	ErrGCUnverified = errors.New("rules version retirement cannot be verified")
	ErrGCInUse      = errors.New("rules version is pinned by an active task")
)

// RunningTasks checks Server's authoritative RUNNING task records for a single
// node and version. Query failures MUST NOT be interpreted as zero running tasks.
type RunningTasks interface {
	CountRunning(context.Context, string, string) (int, error)
}

type GCPhase string

const (
	Quarantine GCPhase = "QUARANTINE"
	Delete     GCPhase = "DELETE"
)

// The Updater supplies this snapshot, never raw user task input.
type GCRequest struct {
	NodeID         string
	Version        string
	CurrentVersion string
	BackupVersion  string
	RetiredAt      time.Time
	QuarantinedAt  time.Time
	Phase          GCPhase
}

// GCPolicy is pure authorization, NOT a filesystem mutator. The actual Updater
// must safely rename into .trash and perform a fresh second check before delete.
type GCPolicy struct {
	Grace   time.Duration
	Running RunningTasks
}

// validBundleVersion rejects any separator, control character, path
// traversal component or nonnumeric version without regexp initialization.
func validBundleVersion(version string) bool {
	if len(version) < 11 || len(version) > 17 || version[8] != '.' {
		return false
	}
	for i := 0; i < len(version); i++ {
		if i == 8 {
			continue
		}
		if version[i] < '0' || version[i] > '9' {
			return false
		}
	}
	return true
}

// Check authorizes exactly ONE stage, checking live Server state each time.
func (p GCPolicy) Check(ctx context.Context, r GCRequest, now time.Time) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("%w: canceled: %w", ErrGCUnverified, err)
	}
	if p.Running == nil || p.Grace < DefaultGCGrace {
		return fmt.Errorf("%w: Server query and grace >= 2h required", ErrGCUnverified)
	}
	if r.NodeID == "" || !validBundleVersion(r.Version) ||
		!validBundleVersion(r.CurrentVersion) ||
		!validBundleVersion(r.BackupVersion) {
		return fmt.Errorf("%w: missing node or version snapshot", ErrGCUnverified)
	}
	if r.Version == r.CurrentVersion || r.Version == r.BackupVersion {
		return ErrGCProtected
	}
	if r.Phase != Quarantine && r.Phase != Delete {
		return fmt.Errorf("%w: invalid GC phase", ErrGCUnverified)
	}
	if r.RetiredAt.IsZero() || r.RetiredAt.After(now) || now.Sub(r.RetiredAt) < p.Grace {
		return fmt.Errorf("%w: retirement grace not elapsed", ErrGCProtected)
	}
	if r.Phase == Delete && (r.QuarantinedAt.IsZero() || r.QuarantinedAt.After(now)) {
		return fmt.Errorf("%w: quarantine must precede deletion", ErrGCUnverified)
	}
	count, err := p.Running.CountRunning(ctx, r.NodeID, r.Version)
	if err != nil {
		return fmt.Errorf("%w: Server RUNNING task query: %w", ErrGCUnverified, err)
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("%w: query canceled: %w", ErrGCUnverified, err)
	}
	if count < 0 {
		return fmt.Errorf("%w: invalid running count", ErrGCUnverified)
	}
	if count > 0 {
		return ErrGCInUse
	}
	return nil
}
