package repo

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"scanner-platform/internal/rules"
	"scanner-platform/internal/taskflow"
	"time"
)

var (
	ErrCustomRuleConflict = errors.New("custom rule state conflict")
	ErrInvalidCustomRule  = errors.New("invalid custom rule")
)

func (s *RuntimeStore) ListCustomRules(ctx context.Context) ([]rules.CustomRule, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT data FROM custom_rules ORDER BY updated_at DESC,id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []rules.CustomRule{}
	for rows.Next() {
		var data string
		var rule rules.CustomRule
		if err := rows.Scan(&data); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(data), &rule); err != nil {
			return nil, err
		}
		out = append(out, rule)
	}
	return out, rows.Err()
}

// SaveCustomRule persists a generated safe rule definition. The compiled
// template is regenerated from structured fields and never accepted from the
// API payload.
func (s *RuntimeStore) SaveCustomRule(ctx context.Context, actor string, input rules.CustomRule, create bool) (rules.CustomRule, error) {
	rule, err := rules.CompileCustomRule(input)
	if err != nil {
		return rules.CustomRule{}, fmt.Errorf("%w: %v", ErrInvalidCustomRule, err)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return rules.CustomRule{}, err
	}
	defer tx.Rollback()
	var count int
	if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM custom_rules WHERE id=?", rule.ID).Scan(&count); err != nil {
		return rules.CustomRule{}, err
	}
	if create && count != 0 || !create && count == 0 {
		return rules.CustomRule{}, ErrCustomRuleConflict
	}
	if count == 0 {
		if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM custom_rules").Scan(&count); err != nil {
			return rules.CustomRule{}, err
		}
		if count >= 200 {
			return rules.CustomRule{}, fmt.Errorf("custom rule limit reached")
		}
	}
	data, err := json.Marshal(rule)
	if err != nil {
		return rules.CustomRule{}, err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if create {
		_, err = tx.ExecContext(ctx, "INSERT INTO custom_rules(id,data,enabled,created_at,updated_at) VALUES(?,?,?,?,?)", rule.ID, string(data), rule.Enabled, now, now)
	} else {
		_, err = tx.ExecContext(ctx, "UPDATE custom_rules SET data=?,enabled=?,updated_at=? WHERE id=?", string(data), rule.Enabled, now, rule.ID)
	}
	if err != nil {
		return rules.CustomRule{}, err
	}
	action := "create_custom_rule"
	if !create {
		action = "update_custom_rule"
	}
	if err := logLocal(ctx, tx, actor, action, "custom_rule", rule.ID, rule.Severity); err != nil {
		return rules.CustomRule{}, err
	}
	if err := tx.Commit(); err != nil {
		return rules.CustomRule{}, err
	}
	return rule, nil
}

func (s *RuntimeStore) DeleteCustomRule(ctx context.Context, id, actor string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, "DELETE FROM custom_rules WHERE id=?", id)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count != 1 {
		return ErrCustomRuleConflict
	}
	if err := logLocal(ctx, tx, actor, "delete_custom_rule", "custom_rule", id, ""); err != nil {
		return err
	}
	return tx.Commit()
}

func customTemplates(ctx context.Context, tx *sql.Tx, input taskflow.TaskInput) ([][]byte, error) {
	if input.Engine != "auto" && input.Engine != "nuclei" {
		return nil, nil
	}
	if len(input.CustomRuleIDs) > 20 {
		return nil, fmt.Errorf("too many custom rules selected")
	}
	rows, err := tx.QueryContext(ctx, "SELECT data FROM custom_rules WHERE enabled=1 ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	wanted := map[string]bool{}
	for _, id := range input.CustomRuleIDs {
		if id == "" || wanted[id] {
			return nil, fmt.Errorf("invalid custom rule selection")
		}
		wanted[id] = true
	}
	templates := [][]byte{}
	found := map[string]bool{}
	for rows.Next() {
		var data string
		var rule rules.CustomRule
		if err := rows.Scan(&data); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(data), &rule); err != nil {
			return nil, err
		}
		if len(wanted) > 0 && !wanted[rule.ID] {
			continue
		}
		compiled, err := rules.CompileCustomRule(rule)
		if err != nil {
			return nil, fmt.Errorf("stored custom rule is invalid: %w", err)
		}
		templates = append(templates, []byte(compiled.Template))
		found[rule.ID] = true
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for id := range wanted {
		if !found[id] {
			return nil, fmt.Errorf("selected custom rule is missing or disabled")
		}
	}
	if len(templates) > 20 {
		return nil, fmt.Errorf("too many enabled custom rules; disable rules not needed for this task")
	}
	return templates, nil
}
