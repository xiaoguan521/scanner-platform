package repo

import (
	"context"
	"database/sql"
	"time"

	"scanner-platform/internal/taskflow"
)

// postgresUpdateMissingFindingLifecycle mirrors the SQLite convergence rule
// while keeping PostgreSQL's normalized finding row authoritative. A finding
// is eligible only when the worker proves complete coverage and the rule
// bundle actually ran; partial SSH/system collection or an interrupted scan
// therefore cannot mark a finding FIXED.
func postgresUpdateMissingFindingLifecycle(ctx context.Context, tx *sql.Tx, task taskflow.Task, report taskflow.Report, now time.Time) error {
	if !lifecycleEligible(task, report) {
		return nil
	}
	threshold := task.FixedThreshold
	if threshold < 1 {
		return nil
	}
	observedRows, err := tx.QueryContext(ctx, `SELECT finding_id FROM task_finding_observations WHERE task_id=$1`, task.ID)
	if err != nil {
		return err
	}
	observed := make(map[string]bool)
	for observedRows.Next() {
		var findingID string
		if err := observedRows.Scan(&findingID); err != nil {
			observedRows.Close()
			return err
		}
		observed[findingID] = true
	}
	if err := observedRows.Err(); err != nil {
		observedRows.Close()
		return err
	}
	if err := observedRows.Close(); err != nil {
		return err
	}

	rows, err := tx.QueryContext(ctx, `SELECT sf.id FROM security_findings sf
		JOIN finding_projections fp ON fp.finding_id=sf.id
		WHERE sf.lifecycle_status NOT IN ('FIXED','FALSE_POSITIVE','ACCEPTED_RISK')
		ORDER BY sf.id FOR UPDATE OF sf`)
	if err != nil {
		return err
	}
	ids := make([]string, 0)
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}

	findingStore := &PostgresFindingStore{db: nil}
	for _, id := range ids {
		if observed[id] {
			continue
		}
		// Use the same normalized read path as manual disposition. The row was
		// locked by the ordered query above, so the projection cannot change
		// between the scope check and the lifecycle update.
		finding, err := findingStore.readFindingTx(ctx, tx, id)
		if err != nil {
			return err
		}
		if !lifecycleFindingInScope(finding, task, report) {
			continue
		}
		finding.ConsecutiveMisses++
		finding.VerifiedInRun = false
		if finding.ConsecutiveMisses >= threshold {
			if err := recordPostgresFindingEventTx(ctx, tx, id, finding.Status, "FIXED", "system", "完整扫描连续未检出达到阈值", now); err != nil {
				return err
			}
			finding.Status = "FIXED"
			resolved := now.UTC()
			finding.ResolvedAt = &resolved
		}
		if err := findingStore.updateFindingLifecycleTx(ctx, tx, finding, now); err != nil {
			return err
		}
	}
	return nil
}
