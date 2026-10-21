package repo

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"scanner-platform/internal/scanplans"
	"strings"
	"time"
)

var (
	ErrScanPlanConflict = errors.New("scan plan state conflict")
	ErrInvalidScanPlan  = errors.New("invalid scan plan")
)

func (s *RuntimeStore) ListScanPlans(ctx context.Context) ([]scanplans.Plan, error) {
	items := scanplans.Catalog()
	rows, err := s.db.QueryContext(ctx, "SELECT data FROM scan_plans ORDER BY updated_at DESC,id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var raw string
		var item scanplans.Plan
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(raw), &item); err != nil {
			return nil, fmt.Errorf("decode scan plan: %w", err)
		}
		// Stored plans are always server-created custom records. Keep the
		// response fail-closed if an old or manually edited row is malformed.
		if item.Kind != "CUSTOM" || item.ReadOnly || item.ID == "" {
			return nil, fmt.Errorf("invalid stored scan plan %q", item.ID)
		}
		validated, err := (scanplans.Input{Title: item.Title, Summary: item.Summary, Detail: item.Detail, Defaults: item.Defaults, SourceID: item.SourceID}).NormalizeAndValidate()
		if err != nil {
			return nil, fmt.Errorf("invalid stored scan plan %q: %w", item.ID, err)
		}
		item.Title, item.Summary, item.Detail, item.Defaults, item.SourceID = validated.Title, validated.Summary, validated.Detail, validated.Defaults, validated.SourceID
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *RuntimeStore) SaveScanPlan(ctx context.Context, actor string, input scanplans.Input, id string, update bool) (scanplans.Plan, error) {
	input, err := input.NormalizeAndValidate()
	if err != nil {
		return scanplans.Plan{}, fmt.Errorf("%w: %v", ErrInvalidScanPlan, err)
	}
	if actor == "" {
		actor = "local-test"
	}
	if !update {
		id = "plan-" + rand.Text()
	} else if strings.TrimSpace(id) == "" {
		return scanplans.Plan{}, ErrScanPlanConflict
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return scanplans.Plan{}, err
	}
	defer tx.Rollback()

	var existing scanplans.Plan
	var raw string
	lookupErr := tx.QueryRowContext(ctx, "SELECT data FROM scan_plans WHERE id=?", id).Scan(&raw)
	if errors.Is(lookupErr, sql.ErrNoRows) {
		if update {
			return scanplans.Plan{}, ErrScanPlanConflict
		}
	} else if lookupErr != nil {
		return scanplans.Plan{}, lookupErr
	} else {
		if !update {
			return scanplans.Plan{}, ErrScanPlanConflict
		}
		if err := json.Unmarshal([]byte(raw), &existing); err != nil {
			return scanplans.Plan{}, fmt.Errorf("decode existing scan plan: %w", err)
		}
		if existing.Kind != "CUSTOM" || existing.ReadOnly {
			return scanplans.Plan{}, ErrScanPlanConflict
		}
	}
	if !update {
		var count int
		if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM scan_plans").Scan(&count); err != nil {
			return scanplans.Plan{}, err
		}
		if count >= scanplans.MaxPlans {
			return scanplans.Plan{}, fmt.Errorf("%w: custom scan plan limit reached", ErrInvalidScanPlan)
		}
	}
	if err := validatePlanRuleIDs(ctx, tx, input.Defaults.CustomRuleIDs); err != nil {
		return scanplans.Plan{}, err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	item := scanplans.Plan{
		ID:        id,
		Title:     input.Title,
		Summary:   input.Summary,
		Detail:    input.Detail,
		Kind:      "CUSTOM",
		ReadOnly:  false,
		Defaults:  input.Defaults,
		SourceID:  input.SourceID,
		CreatedBy: existing.CreatedBy,
		CreatedAt: existing.CreatedAt,
		UpdatedAt: now,
	}
	if !update {
		item.CreatedBy = actor
		item.CreatedAt = now
	}
	data, err := json.Marshal(item)
	if err != nil {
		return scanplans.Plan{}, err
	}
	if update {
		_, err = tx.ExecContext(ctx, "UPDATE scan_plans SET data=?,updated_at=? WHERE id=?", string(data), now, id)
	} else {
		_, err = tx.ExecContext(ctx, "INSERT INTO scan_plans(id,data,created_by,created_at,updated_at) VALUES(?,?,?,?,?)", id, string(data), item.CreatedBy, now, now)
	}
	if err != nil {
		return scanplans.Plan{}, err
	}
	action := "create_scan_plan"
	if update {
		action = "update_scan_plan"
	}
	if err := logLocal(ctx, tx, actor, action, "scan_plan", id, ""); err != nil {
		return scanplans.Plan{}, err
	}
	if err := tx.Commit(); err != nil {
		return scanplans.Plan{}, err
	}
	return item, nil
}

func validatePlanRuleIDs(ctx context.Context, tx *sql.Tx, ids []string) error {
	for _, id := range ids {
		var enabled int
		err := tx.QueryRowContext(ctx, "SELECT enabled FROM custom_rules WHERE id=?", id).Scan(&enabled)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return fmt.Errorf("%w: selected custom rule is missing or disabled", ErrInvalidScanPlan)
			}
			return err
		}
		if enabled == 0 {
			return fmt.Errorf("%w: selected custom rule is missing or disabled", ErrInvalidScanPlan)
		}
	}
	return nil
}

func (s *RuntimeStore) DeleteScanPlan(ctx context.Context, id, actor string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var raw string
	if err := tx.QueryRowContext(ctx, "SELECT data FROM scan_plans WHERE id=?", id).Scan(&raw); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrScanPlanConflict
		}
		return err
	}
	var item scanplans.Plan
	if err := json.Unmarshal([]byte(raw), &item); err != nil {
		return err
	}
	if item.Kind != "CUSTOM" || item.ReadOnly {
		return ErrScanPlanConflict
	}
	result, err := tx.ExecContext(ctx, "DELETE FROM scan_plans WHERE id=?", id)
	if err != nil {
		return err
	}
	if count, err := result.RowsAffected(); err != nil {
		return err
	} else if count != 1 {
		return ErrScanPlanConflict
	}
	if err := logLocal(ctx, tx, actor, "delete_scan_plan", "scan_plan", id, ""); err != nil {
		return err
	}
	return tx.Commit()
}
