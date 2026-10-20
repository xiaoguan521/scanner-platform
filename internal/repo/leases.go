package repo

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"scanner-platform/internal/scheduler"
	"scanner-platform/internal/taskflow"
)

// leaseDuration returns the bounded local lease used for newly claimed real
// tasks. A zero value keeps RuntimeStore construction backwards compatible.
func (s *RuntimeStore) leaseDuration() time.Duration {
	if s.LeaseDuration > 0 {
		return s.LeaseDuration
	}
	return scheduler.DefaultLeaseDuration
}

// RenewChunkLease extends one Server-owned task lease. The caller supplies the
// original binding, never a requested expiration, so a Worker cannot switch
// tasks or rule versions while renewing. This local API is deliberately
// unauthenticated; production Node API TLS/tokens remain a separate task.
func (s *RuntimeStore) RenewChunkLease(ctx context.Context, taskID, workerID, pinnedRuleVersion string) (time.Time, error) {
	if taskID == "" || workerID == "" || pinnedRuleVersion == "" {
		return time.Time{}, ErrTaskLease
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return time.Time{}, fmt.Errorf("begin lease renewal: %w", err)
	}
	defer tx.Rollback()

	var status, owner, boundVersion, leaseText, details string
	if err := tx.QueryRowContext(ctx, `SELECT status,worker_id,pinned_rule_version,COALESCE(lease_expires_at,''),details FROM scan_tasks WHERE id=?`, taskID).
		Scan(&status, &owner, &boundVersion, &leaseText, &details); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return time.Time{}, ErrTaskConflict
		}
		return time.Time{}, err
	}
	if status != "RUNNING" || owner != workerID || boundVersion != pinnedRuleVersion || leaseText == "" {
		return time.Time{}, ErrTaskLease
	}
	oldExpiry, err := time.Parse(time.RFC3339Nano, leaseText)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid persisted task lease: %w", err)
	}
	now := time.Now().UTC()
	if !now.Before(oldExpiry) {
		return time.Time{}, ErrTaskLease
	}
	var detail taskDetails
	if err := json.Unmarshal([]byte(details), &detail); err != nil {
		return time.Time{}, err
	}
	deadline, err := taskDeadline(detail.Deadline)
	if err != nil {
		return time.Time{}, err
	}
	if !deadline.IsZero() && !now.Before(deadline) {
		return time.Time{}, ErrTaskLease
	}
	expires := now.Add(s.leaseDuration())
	if !deadline.IsZero() && deadline.Before(expires) {
		expires = deadline
	}
	if !expires.After(now) || !expires.After(oldExpiry) {
		return time.Time{}, ErrTaskLease
	}
	if _, err := tx.ExecContext(ctx, `UPDATE scan_tasks SET lease_expires_at=? WHERE id=? AND status='RUNNING' AND worker_id=? AND pinned_rule_version=?`, expires.Format(time.RFC3339Nano), taskID, workerID, pinnedRuleVersion); err != nil {
		return time.Time{}, fmt.Errorf("update task lease: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return time.Time{}, fmt.Errorf("commit lease renewal: %w", err)
	}
	return expires, nil
}

// CountRunningByVersion is the Server-side query used by the future Updater
// GC integration. The worker ID is the local node binding in Phase 0.
func (s *RuntimeStore) CountRunningByVersion(ctx context.Context, nodeID, version string) (int, error) {
	if nodeID == "" || version == "" {
		return 0, ErrTaskLease
	}
	var count int
	if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM scan_tasks WHERE status='RUNNING' AND worker_id=? AND pinned_rule_version=?`, nodeID, version).Scan(&count); err != nil {
		return 0, err
	}
	return count, nil
}

func taskDeadline(raw string) (time.Time, error) {
	if raw == "" {
		return time.Time{}, nil
	}
	deadline, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid task hard deadline: %w", err)
	}
	return deadline, nil
}

func validateTaskLease(task taskflow.Task, worker string, now time.Time) error {
	if task.Synthetic {
		return nil
	}
	if len(task.Chunks) != 1 || task.Chunks[0].WorkerNodeID != worker ||
		task.Chunks[0].PinnedRuleVersion == "" || task.Chunks[0].LeaseExpiresAt == nil ||
		!now.Before(*task.Chunks[0].LeaseExpiresAt) {
		return ErrTaskLease
	}
	return nil
}

// expireRuntimeLeases returns tasks whose Server-confirmed lease elapsed to a
// retryable queue state. A task whose hard deadline also elapsed is paused so a
// later scheduler tick can re-open it only when its window permits.
func (s *RuntimeStore) expireRuntimeLeases(ctx context.Context, now time.Time) error {
	rows, err := s.db.QueryContext(ctx, `SELECT id,details,lease_expires_at FROM scan_tasks WHERE status='RUNNING' AND lease_expires_at IS NOT NULL AND lease_expires_at<>''`)
	if err != nil {
		return fmt.Errorf("list expired leases: %w", err)
	}
	type expiredTask struct{ id, details, lease string }
	var expired []expiredTask
	for rows.Next() {
		var item expiredTask
		if err := rows.Scan(&item.id, &item.details, &item.lease); err != nil {
			rows.Close()
			return err
		}
		lease, err := time.Parse(time.RFC3339Nano, item.lease)
		if err != nil {
			rows.Close()
			return fmt.Errorf("parse task lease: %w", err)
		}
		if !now.Before(lease) {
			expired = append(expired, item)
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, item := range expired {
		status := "PENDING"
		var detail taskDetails
		if err := json.Unmarshal([]byte(item.details), &detail); err != nil {
			return err
		}
		deadline, err := taskDeadline(detail.Deadline)
		if err != nil {
			return err
		}
		if !deadline.IsZero() && !now.Before(deadline) {
			status = "PAUSED_WINDOW"
		}
		if _, err := s.db.ExecContext(ctx, `UPDATE scan_tasks SET status=?,worker_id='',lease_expires_at=NULL,pinned_rule_version='' WHERE id=? AND status='RUNNING' AND lease_expires_at=?`, status, item.id, item.lease); err != nil {
			return fmt.Errorf("reclaim expired task lease: %w", err)
		}
	}
	return nil
}
