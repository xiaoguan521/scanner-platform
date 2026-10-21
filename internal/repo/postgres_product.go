package repo

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"scanner-platform/internal/findings"
	"scanner-platform/internal/inventory"
	"scanner-platform/internal/rules"
	"scanner-platform/internal/scanplans"
	"scanner-platform/internal/taskflow"
)

// readPostgresProductJSON reads one Server-owned product setting. Settings are
// JSON for parity with SQLite, but the selected PostgreSQL database remains the
// only source of truth in this runtime.
func (s *PostgresRuntimeStore) readPostgresProductJSON(ctx context.Context, id string, value any) error {
	var raw string
	if err := s.db.QueryRowContext(ctx, "SELECT data FROM product_settings WHERE id=$1", id).Scan(&raw); err != nil {
		return err
	}
	if err := json.Unmarshal([]byte(raw), value); err != nil {
		return fmt.Errorf("decode postgres product setting %q: %w", id, err)
	}
	return nil
}

func (s *PostgresRuntimeStore) GetSystemSettings(ctx context.Context) (SystemSettings, error) {
	settings := defaultSystemSettings()
	if err := s.readPostgresProductJSON(ctx, systemSettingsID, &settings); errors.Is(err, sql.ErrNoRows) {
		return settings, nil
	} else if err != nil {
		return settings, err
	}
	return validateSystemSettings(settings)
}

func (s *PostgresRuntimeStore) SaveSystemSettings(ctx context.Context, settings SystemSettings, actor string) (SystemSettings, error) {
	settings, err := validateSystemSettings(settings)
	if err != nil {
		return settings, err
	}
	if strings.TrimSpace(actor) == "" {
		return settings, ErrInvalidTask
	}
	data, err := json.Marshal(settings)
	if err != nil {
		return settings, fmt.Errorf("encode postgres system settings: %w", err)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return settings, fmt.Errorf("begin postgres system settings: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `INSERT INTO product_settings(id,data) VALUES($1,$2)
		ON CONFLICT(id) DO UPDATE SET data=EXCLUDED.data`, systemSettingsID, string(data)); err != nil {
		return settings, fmt.Errorf("save postgres system settings: %w", err)
	}
	if err := s.postgresAuditTx(ctx, tx, actor, "update_system_settings", "settings", systemSettingsID, ""); err != nil {
		return settings, err
	}
	if err := tx.Commit(); err != nil {
		return settings, fmt.Errorf("commit postgres system settings: %w", err)
	}
	return settings, nil
}

func (s *PostgresRuntimeStore) GetScanPolicy(ctx context.Context) (ScanPolicy, error) {
	policy := defaultPolicy()
	if err := s.readPostgresProductJSON(ctx, "scan-policy", &policy); errors.Is(err, sql.ErrNoRows) {
		return policy, nil
	} else if err != nil {
		return policy, err
	}
	return normalizeScanPolicy(policy)
}

func (s *PostgresRuntimeStore) SaveScanPolicy(ctx context.Context, policy ScanPolicy, actor string) (ScanPolicy, error) {
	policy, err := normalizeScanPolicy(policy)
	if err != nil {
		return policy, err
	}
	if strings.TrimSpace(actor) == "" {
		return policy, ErrInvalidTask
	}
	data, err := json.Marshal(policy)
	if err != nil {
		return policy, fmt.Errorf("encode postgres scan policy: %w", err)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return policy, fmt.Errorf("begin postgres scan policy: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `INSERT INTO product_settings(id,data) VALUES($1,$2)
		ON CONFLICT(id) DO UPDATE SET data=EXCLUDED.data`, "scan-policy", string(data)); err != nil {
		return policy, fmt.Errorf("save postgres scan policy: %w", err)
	}
	if err := s.postgresAuditTx(ctx, tx, actor, "update_scan_policy", "settings", "scan-policy", ""); err != nil {
		return policy, err
	}
	if err := tx.Commit(); err != nil {
		return policy, fmt.Errorf("commit postgres scan policy: %w", err)
	}
	return policy, nil
}

func decodePostgresScanPlan(raw string) (scanplans.Plan, error) {
	var item scanplans.Plan
	if err := json.Unmarshal([]byte(raw), &item); err != nil {
		return item, fmt.Errorf("decode postgres scan plan: %w", err)
	}
	if item.Kind != "CUSTOM" || item.ReadOnly || strings.TrimSpace(item.ID) == "" {
		return item, fmt.Errorf("%w: invalid stored scan plan", ErrInvalidScanPlan)
	}
	validated, err := (scanplans.Input{
		Title: item.Title, Summary: item.Summary, Detail: item.Detail,
		Defaults: item.Defaults, SourceID: item.SourceID,
	}).NormalizeAndValidate()
	if err != nil {
		return item, fmt.Errorf("%w: %v", ErrInvalidScanPlan, err)
	}
	item.Title, item.Summary, item.Detail = validated.Title, validated.Summary, validated.Detail
	item.Defaults, item.SourceID = validated.Defaults, validated.SourceID
	return item, nil
}

func (s *PostgresRuntimeStore) ListScanPlans(ctx context.Context) ([]scanplans.Plan, error) {
	items := scanplans.Catalog()
	rows, err := s.db.QueryContext(ctx, `SELECT data FROM scan_plans ORDER BY updated_at DESC,id LIMIT $1`, scanplans.MaxPlans)
	if err != nil {
		return nil, fmt.Errorf("list postgres scan plans: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return nil, fmt.Errorf("scan postgres scan plan: %w", err)
		}
		item, err := decodePostgresScanPlan(raw)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate postgres scan plans: %w", err)
	}
	return items, nil
}

func (s *PostgresRuntimeStore) validatePostgresPlanRuleIDs(ctx context.Context, tx *sql.Tx, ids []string) error {
	for _, id := range ids {
		var enabled bool
		err := tx.QueryRowContext(ctx, "SELECT enabled FROM custom_rules WHERE id=$1", id).Scan(&enabled)
		if errors.Is(err, sql.ErrNoRows) || err == nil && !enabled {
			return fmt.Errorf("%w: selected custom rule is missing or disabled", ErrInvalidScanPlan)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *PostgresRuntimeStore) SaveScanPlan(ctx context.Context, actor string, input scanplans.Input, id string, update bool) (scanplans.Plan, error) {
	input, err := input.NormalizeAndValidate()
	if err != nil {
		return scanplans.Plan{}, fmt.Errorf("%w: %v", ErrInvalidScanPlan, err)
	}
	if strings.TrimSpace(actor) == "" {
		return scanplans.Plan{}, ErrInvalidTask
	}
	if !update {
		id = "plan-" + randomLocalID()
	} else if strings.TrimSpace(id) == "" {
		return scanplans.Plan{}, ErrScanPlanConflict
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return scanplans.Plan{}, fmt.Errorf("begin postgres scan plan: %w", err)
	}
	defer tx.Rollback()
	var raw string
	var existing scanplans.Plan
	lookupErr := tx.QueryRowContext(ctx, `SELECT data FROM scan_plans WHERE id=$1 FOR UPDATE`, id).Scan(&raw)
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
		existing, err = decodePostgresScanPlan(raw)
		if err != nil {
			return scanplans.Plan{}, err
		}
	}
	if !update {
		var count int
		if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM scan_plans").Scan(&count); err != nil {
			return scanplans.Plan{}, err
		}
		if count >= scanplans.MaxPlans {
			return scanplans.Plan{}, fmt.Errorf("%w: custom scan plan limit reached", ErrInvalidScanPlan)
		}
	}
	if err := s.validatePostgresPlanRuleIDs(ctx, tx, input.Defaults.CustomRuleIDs); err != nil {
		return scanplans.Plan{}, err
	}
	now := time.Now().UTC()
	item := scanplans.Plan{
		ID: id, Title: input.Title, Summary: input.Summary, Detail: input.Detail,
		Kind: "CUSTOM", ReadOnly: false, Defaults: input.Defaults, SourceID: input.SourceID,
		CreatedBy: existing.CreatedBy, CreatedAt: existing.CreatedAt, UpdatedAt: now.Format(time.RFC3339Nano),
	}
	if !update {
		item.CreatedBy, item.CreatedAt = actor, now.Format(time.RFC3339Nano)
	}
	data, err := json.Marshal(item)
	if err != nil {
		return scanplans.Plan{}, fmt.Errorf("encode postgres scan plan: %w", err)
	}
	if update {
		_, err = tx.ExecContext(ctx, `UPDATE scan_plans SET data=$1,updated_at=$2 WHERE id=$3`, string(data), now, id)
	} else {
		_, err = tx.ExecContext(ctx, `INSERT INTO scan_plans(id,data,created_by,created_at,updated_at) VALUES($1,$2,$3,$4,$5)`, id, string(data), item.CreatedBy, now, now)
	}
	if err != nil {
		return scanplans.Plan{}, fmt.Errorf("save postgres scan plan: %w", err)
	}
	action := "create_scan_plan"
	if update {
		action = "update_scan_plan"
	}
	if err := s.postgresAuditTx(ctx, tx, actor, action, "scan_plan", id, ""); err != nil {
		return scanplans.Plan{}, err
	}
	if err := tx.Commit(); err != nil {
		return scanplans.Plan{}, fmt.Errorf("commit postgres scan plan: %w", err)
	}
	return item, nil
}

func (s *PostgresRuntimeStore) DeleteScanPlan(ctx context.Context, id, actor string) error {
	if strings.TrimSpace(id) == "" || strings.TrimSpace(actor) == "" {
		return ErrInvalidTask
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin postgres scan plan deletion: %w", err)
	}
	defer tx.Rollback()
	var raw string
	if err := tx.QueryRowContext(ctx, `SELECT data FROM scan_plans WHERE id=$1 FOR UPDATE`, id).Scan(&raw); errors.Is(err, sql.ErrNoRows) {
		return ErrScanPlanConflict
	} else if err != nil {
		return err
	}
	item, err := decodePostgresScanPlan(raw)
	if err != nil {
		return err
	}
	if item.Kind != "CUSTOM" || item.ReadOnly {
		return ErrScanPlanConflict
	}
	result, err := tx.ExecContext(ctx, "DELETE FROM scan_plans WHERE id=$1", id)
	if err != nil {
		return err
	}
	if count, err := result.RowsAffected(); err != nil {
		return err
	} else if count != 1 {
		return ErrScanPlanConflict
	}
	if err := s.postgresAuditTx(ctx, tx, actor, "delete_scan_plan", "scan_plan", id, ""); err != nil {
		return err
	}
	return tx.Commit()
}

func decodePostgresCustomRule(raw string) (rules.CustomRule, error) {
	var rule rules.CustomRule
	if err := json.Unmarshal([]byte(raw), &rule); err != nil {
		return rule, fmt.Errorf("decode postgres custom rule: %w", err)
	}
	compiled, err := rules.CompileCustomRule(rule)
	if err != nil {
		return rule, fmt.Errorf("invalid stored postgres custom rule: %w", err)
	}
	return compiled, nil
}

func (s *PostgresRuntimeStore) ListCustomRules(ctx context.Context) ([]rules.CustomRule, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT data FROM custom_rules ORDER BY updated_at DESC,id DESC LIMIT 200`)
	if err != nil {
		return nil, fmt.Errorf("list postgres custom rules: %w", err)
	}
	defer rows.Close()
	items := make([]rules.CustomRule, 0)
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		item, err := decodePostgresCustomRule(raw)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func postgresCustomRuleWhere(query CustomRuleListQuery, add func(any) string) string {
	where := []string{"TRUE"}
	if query.Severity != "" {
		where = append(where, "COALESCE(data::jsonb->>'severity','')="+add(query.Severity))
	}
	if query.Enabled != "" {
		where = append(where, "enabled="+add(query.Enabled == "true"))
	}
	if query.Search != "" {
		pattern := "%" + escapeFindingLike(query.Search) + "%"
		value := add(pattern)
		where = append(where, "(id ILIKE "+value+" ESCAPE '\\' OR COALESCE(data::jsonb->>'name','') ILIKE "+value+" ESCAPE '\\' OR COALESCE(data::jsonb->>'description','') ILIKE "+value+" ESCAPE '\\')")
	}
	return strings.Join(where, " AND ")
}

func (s *PostgresRuntimeStore) ListCustomRulesPage(ctx context.Context, in CustomRuleListQuery) (CustomRuleListPage, error) {
	query, err := NormalizeCustomRuleListQuery(in)
	if err != nil {
		return CustomRuleListPage{}, err
	}
	args := make([]any, 0, 6)
	add := func(value any) string {
		args = append(args, value)
		return fmt.Sprintf("$%d", len(args))
	}
	where := postgresCustomRuleWhere(query, add)
	var total int
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM custom_rules WHERE "+where, args...).Scan(&total); err != nil {
		return CustomRuleListPage{}, fmt.Errorf("count postgres custom rules: %w", err)
	}
	sortColumn := "updated_at"
	switch strings.TrimPrefix(query.Sort, "-") {
	case "name":
		sortColumn = "COALESCE(data::jsonb->>'name','')"
	case "severity":
		sortColumn = "COALESCE(data::jsonb->>'severity','')"
	case "id":
		sortColumn = "id"
	}
	direction := "DESC"
	if query.Sort != "" && !strings.HasPrefix(query.Sort, "-") {
		direction = "ASC"
	}
	statement := "SELECT data FROM custom_rules WHERE " + where + " ORDER BY " + sortColumn + " " + direction + ",id"
	selectArgs := append([]any(nil), args...)
	if query.PageSize > 0 {
		statement += fmt.Sprintf(" LIMIT $%d OFFSET $%d", len(selectArgs)+1, len(selectArgs)+2)
		selectArgs = append(selectArgs, query.PageSize, (query.Page-1)*query.PageSize)
	}
	rows, err := s.db.QueryContext(ctx, statement, selectArgs...)
	if err != nil {
		return CustomRuleListPage{}, fmt.Errorf("list postgres custom rules: %w", err)
	}
	defer rows.Close()
	items := make([]rules.CustomRule, 0)
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return CustomRuleListPage{}, err
		}
		item, err := decodePostgresCustomRule(raw)
		if err != nil {
			return CustomRuleListPage{}, err
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return CustomRuleListPage{}, err
	}
	return CustomRuleListPage{Items: items, Total: total, Page: query.Page, PageSize: pageSizeOrDefault(query.PageSize, len(items))}, nil
}

func (s *PostgresRuntimeStore) SaveCustomRule(ctx context.Context, actor string, input rules.CustomRule, create bool) (rules.CustomRule, error) {
	rule, err := rules.CompileCustomRule(input)
	if err != nil {
		return rules.CustomRule{}, fmt.Errorf("%w: %v", ErrInvalidCustomRule, err)
	}
	if strings.TrimSpace(actor) == "" {
		return rules.CustomRule{}, ErrInvalidTask
	}
	data, err := json.Marshal(rule)
	if err != nil {
		return rules.CustomRule{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return rules.CustomRule{}, fmt.Errorf("begin postgres custom rule: %w", err)
	}
	defer tx.Rollback()
	var count int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM custom_rules WHERE id=$1", rule.ID).Scan(&count); err != nil {
		return rules.CustomRule{}, err
	}
	if create && count != 0 || !create && count == 0 {
		return rules.CustomRule{}, ErrCustomRuleConflict
	}
	if create {
		if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM custom_rules").Scan(&count); err != nil {
			return rules.CustomRule{}, err
		}
		if count >= 200 {
			return rules.CustomRule{}, fmt.Errorf("custom rule limit reached")
		}
	}
	now := time.Now().UTC()
	if create {
		_, err = tx.ExecContext(ctx, `INSERT INTO custom_rules(id,data,enabled,created_at,updated_at)
			VALUES($1,$2,$3,$4,$4)`, rule.ID, string(data), rule.Enabled, now)
	} else {
		_, err = tx.ExecContext(ctx, `UPDATE custom_rules SET data=$1,enabled=$2,updated_at=$3 WHERE id=$4`, string(data), rule.Enabled, now, rule.ID)
	}
	if err != nil {
		return rules.CustomRule{}, err
	}
	action := "create_custom_rule"
	if !create {
		action = "update_custom_rule"
	}
	if err := s.postgresAuditTx(ctx, tx, actor, action, "custom_rule", rule.ID, rule.Severity); err != nil {
		return rules.CustomRule{}, err
	}
	if err := tx.Commit(); err != nil {
		return rules.CustomRule{}, err
	}
	return rule, nil
}

func (s *PostgresRuntimeStore) DeleteCustomRule(ctx context.Context, id, actor string) error {
	if strings.TrimSpace(id) == "" || strings.TrimSpace(actor) == "" {
		return ErrInvalidTask
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, "DELETE FROM custom_rules WHERE id=$1", id)
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
	if err := s.postgresAuditTx(ctx, tx, actor, "delete_custom_rule", "custom_rule", id, ""); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *PostgresRuntimeStore) postgresCustomTemplates(ctx context.Context, input taskflow.TaskInput) ([]json.RawMessage, error) {
	if len(input.CustomRuleIDs) > 20 {
		return nil, fmt.Errorf("too many custom rules selected")
	}
	wanted := make(map[string]bool, len(input.CustomRuleIDs))
	for _, id := range input.CustomRuleIDs {
		id = strings.TrimSpace(id)
		if id == "" || wanted[id] {
			return nil, fmt.Errorf("invalid custom rule selection")
		}
		wanted[id] = true
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id,data FROM custom_rules WHERE enabled=TRUE ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("list postgres enabled custom rules: %w", err)
	}
	defer rows.Close()
	templates := make([]json.RawMessage, 0)
	found := make(map[string]bool, len(wanted))
	for rows.Next() {
		var id, raw string
		if err := rows.Scan(&id, &raw); err != nil {
			return nil, err
		}
		if len(wanted) > 0 && !wanted[id] {
			continue
		}
		rule, err := decodePostgresCustomRule(raw)
		if err != nil {
			return nil, err
		}
		templates = append(templates, json.RawMessage(rule.Template))
		found[id] = true
		if len(templates) > 20 {
			return nil, fmt.Errorf("too many enabled custom rules; disable rules not needed for this task")
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for id := range wanted {
		if !found[id] {
			return nil, fmt.Errorf("selected custom rule is missing or disabled")
		}
	}
	return templates, nil
}

func (s *PostgresRuntimeStore) ListKnowledge(ctx context.Context) ([]findings.KnowledgeEntry, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT data FROM vulnerability_knowledge ORDER BY id LIMIT 5000`)
	if err != nil {
		return nil, fmt.Errorf("list postgres knowledge: %w", err)
	}
	defer rows.Close()
	items := make([]findings.KnowledgeEntry, 0)
	for rows.Next() {
		var raw string
		var item findings.KnowledgeEntry
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(raw), &item); err != nil {
			return nil, fmt.Errorf("decode postgres knowledge: %w", err)
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func postgresKnowledgeWhere(query KnowledgeListQuery, add func(any) string) string {
	if query.Search == "" {
		return "TRUE"
	}
	pattern := "%" + escapeKnowledgeLike(strings.ToLower(query.Search)) + "%"
	return "LOWER(data) ILIKE " + add(pattern) + " ESCAPE '\\'"
}

func (s *PostgresRuntimeStore) ListKnowledgePage(ctx context.Context, query KnowledgeListQuery) (KnowledgeListPage, error) {
	page, pageSize, offset, search, err := normalizeKnowledgeListQuery(query)
	if err != nil {
		return KnowledgeListPage{}, err
	}
	query.Search = search
	args := make([]any, 0, 3)
	add := func(value any) string {
		args = append(args, value)
		return fmt.Sprintf("$%d", len(args))
	}
	where := postgresKnowledgeWhere(query, add)
	var total int
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM vulnerability_knowledge WHERE "+where, args...).Scan(&total); err != nil {
		return KnowledgeListPage{}, fmt.Errorf("count postgres knowledge: %w", err)
	}
	statement := "SELECT data FROM vulnerability_knowledge WHERE " + where + " ORDER BY id"
	selectArgs := append([]any(nil), args...)
	statement += fmt.Sprintf(" LIMIT $%d OFFSET $%d", len(selectArgs)+1, len(selectArgs)+2)
	selectArgs = append(selectArgs, pageSize, offset)
	rows, err := s.db.QueryContext(ctx, statement, selectArgs...)
	if err != nil {
		return KnowledgeListPage{}, fmt.Errorf("list postgres knowledge: %w", err)
	}
	defer rows.Close()
	items := make([]findings.KnowledgeEntry, 0, pageSize)
	for rows.Next() {
		var raw string
		var item findings.KnowledgeEntry
		if err := rows.Scan(&raw); err != nil {
			return KnowledgeListPage{}, err
		}
		if err := json.Unmarshal([]byte(raw), &item); err != nil {
			return KnowledgeListPage{}, fmt.Errorf("decode postgres knowledge page: %w", err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return KnowledgeListPage{}, err
	}
	return KnowledgeListPage{Items: items, Total: total, Page: page, PageSize: pageSize}, nil
}

func (s *PostgresRuntimeStore) SaveKnowledge(ctx context.Context, item findings.KnowledgeEntry, actor string) (findings.KnowledgeEntry, error) {
	item = findings.PrepareKnowledge(item)
	if err := findings.ValidateKnowledge(item); err != nil {
		return item, fmt.Errorf("%w: %v", ErrInvalidTask, err)
	}
	if strings.TrimSpace(actor) == "" {
		return item, ErrInvalidTask
	}
	data, err := json.Marshal(item)
	if err != nil {
		return item, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return item, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `INSERT INTO vulnerability_knowledge(id,data) VALUES($1,$2)
		ON CONFLICT(id) DO UPDATE SET data=EXCLUDED.data`, item.ID, string(data)); err != nil {
		return item, err
	}
	if err := s.postgresAuditTx(ctx, tx, actor, "save_knowledge", "knowledge", item.ID, ""); err != nil {
		return item, err
	}
	if err := tx.Commit(); err != nil {
		return item, err
	}
	return item, nil
}

func (s *PostgresRuntimeStore) ImportKnowledge(ctx context.Context, items []findings.KnowledgeEntry, actor string) error {
	if len(items) < 1 || len(items) > 5000 || strings.TrimSpace(actor) == "" {
		return fmt.Errorf("%w: 一次导入1–5000条知识", ErrInvalidTask)
	}
	for i := range items {
		items[i] = findings.PrepareKnowledge(items[i])
		if err := findings.ValidateKnowledge(items[i]); err != nil {
			return fmt.Errorf("%w: %s: %v", ErrInvalidTask, items[i].ID, err)
		}
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, item := range items {
		data, err := json.Marshal(item)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO vulnerability_knowledge(id,data) VALUES($1,$2)
			ON CONFLICT(id) DO UPDATE SET data=EXCLUDED.data`, item.ID, string(data)); err != nil {
			return err
		}
	}
	if err := s.postgresAuditTx(ctx, tx, actor, "import_knowledge", "knowledge", "", fmt.Sprint(len(items))); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *PostgresRuntimeStore) DeleteKnowledge(ctx context.Context, id, actor string) error {
	if strings.TrimSpace(id) == "" || strings.TrimSpace(actor) == "" {
		return ErrInvalidTask
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, "DELETE FROM vulnerability_knowledge WHERE id=$1", id)
	if err != nil {
		return err
	}
	if count, err := result.RowsAffected(); err != nil {
		return err
	} else if count != 1 {
		return ErrInvalidTask
	}
	if err := s.postgresAuditTx(ctx, tx, actor, "delete_knowledge", "knowledge", id, ""); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *PostgresRuntimeStore) ListQuarantines(ctx context.Context) ([]map[string]any, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT q.asset_id,a.address,q.port,q.reason,q.detected_at,q.status
		FROM port_quarantine q JOIN assets a ON a.id=q.asset_id
		WHERE q.status='ACTIVE' ORDER BY a.address,q.port LIMIT 1000`)
	if err != nil {
		return nil, fmt.Errorf("list postgres quarantines: %w", err)
	}
	defer rows.Close()
	items := make([]map[string]any, 0)
	for rows.Next() {
		var id, address, reason, status string
		var port int
		var detected time.Time
		if err := rows.Scan(&id, &address, &port, &reason, &detected, &status); err != nil {
			return nil, err
		}
		items = append(items, map[string]any{
			"assetId": id, "address": address, "port": port, "reason": reason,
			"detectedAt": detected.UTC().Format(time.RFC3339Nano), "status": status,
		})
	}
	return items, rows.Err()
}

func (s *PostgresRuntimeStore) ReleaseQuarantine(ctx context.Context, assetID string, port int, reason, actor string) error {
	reason = strings.TrimSpace(reason)
	if strings.TrimSpace(assetID) == "" || port < 1 || port > 65535 || reason == "" || len(reason) > 1000 || strings.TrimSpace(actor) == "" {
		return fmt.Errorf("%w: 解除隔离需要资产、端口和复核原因", ErrInvalidTask)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin postgres quarantine release: %w", err)
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE port_quarantine SET status='RELEASED',reviewed_by=$1,reviewed_at=$2
		WHERE asset_id=$3 AND port=$4 AND status='ACTIVE'`, actor, time.Now().UTC(), assetID, port)
	if err != nil {
		return err
	}
	if count, err := result.RowsAffected(); err != nil {
		return err
	} else if count != 1 {
		return fmt.Errorf("%w: 未找到有效隔离记录", ErrInvalidTask)
	}
	var raw string
	if err := tx.QueryRowContext(ctx, "SELECT data FROM asset_services WHERE asset_id=$1 AND port=$2", assetID, port).Scan(&raw); err == nil {
		var service inventory.Service
		if err := json.Unmarshal([]byte(raw), &service); err != nil {
			return err
		}
		service.Quarantined, service.QuarantineReason = false, ""
		data, err := json.Marshal(service)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, "UPDATE asset_services SET data=$1 WHERE asset_id=$2 AND port=$3", string(data), assetID, port); err != nil {
			return err
		}
	} else if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if err := s.postgresAuditTx(ctx, tx, actor, "release_quarantine", "asset", assetID, fmt.Sprintf("port=%d; reason=%s", port, reason)); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *PostgresRuntimeStore) ListAuditLogs(ctx context.Context, query AuditLogQuery) ([]AuditLog, int, error) {
	if query.Limit <= 0 {
		query.Limit = 50
	}
	if query.Limit > 200 || query.Offset < 0 || query.Offset > 100000 {
		return nil, 0, fmt.Errorf("%w: invalid audit pagination", ErrInvalidTask)
	}
	clauses := []string{"TRUE"}
	args := make([]any, 0, 8)
	add := func(value any) string {
		args = append(args, value)
		return fmt.Sprintf("$%d", len(args))
	}
	if query.Actor != "" {
		clauses = append(clauses, "actor="+add(query.Actor))
	}
	if query.Action != "" {
		clauses = append(clauses, "action="+add(query.Action))
	}
	if query.ObjectType != "" {
		clauses = append(clauses, "object_type="+add(query.ObjectType))
	}
	if query.From != "" {
		clauses = append(clauses, "created_at>="+add(query.From))
	}
	if query.To != "" {
		clauses = append(clauses, "created_at<="+add(query.To))
	}
	where := strings.Join(clauses, " AND ")
	var total int
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM audit_logs WHERE "+where, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count postgres audit logs: %w", err)
	}
	selectArgs := append([]any(nil), args...)
	statement := `SELECT id,actor,action,object_type,object_id,created_at
		FROM audit_logs WHERE ` + where + ` ORDER BY created_at DESC,id DESC`
	statement += fmt.Sprintf(" LIMIT $%d OFFSET $%d", len(selectArgs)+1, len(selectArgs)+2)
	selectArgs = append(selectArgs, query.Limit, query.Offset)
	rows, err := s.db.QueryContext(ctx, statement, selectArgs...)
	if err != nil {
		return nil, 0, fmt.Errorf("list postgres audit logs: %w", err)
	}
	defer rows.Close()
	items := make([]AuditLog, 0, query.Limit)
	for rows.Next() {
		var item AuditLog
		var created time.Time
		if err := rows.Scan(&item.ID, &item.Actor, &item.Action, &item.ObjectType, &item.ObjectID, &created); err != nil {
			return nil, 0, err
		}
		item.CreatedAt = created.UTC().Format(time.RFC3339Nano)
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	return items, total, nil
}

func (s *PostgresRuntimeStore) ListTaskLogs(ctx context.Context, taskID string) ([]TaskLog, error) {
	if _, err := s.GetRuntimeTask(ctx, taskID); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id,actor,action,created_at FROM audit_logs
		WHERE object_type='task' AND object_id=$1 ORDER BY created_at ASC,id ASC LIMIT 100`, taskID)
	if err != nil {
		return nil, fmt.Errorf("list postgres task logs: %w", err)
	}
	defer rows.Close()
	items := make([]TaskLog, 0, 16)
	for rows.Next() {
		var item TaskLog
		var created time.Time
		if err := rows.Scan(&item.ID, &item.Actor, &item.Action, &created); err != nil {
			return nil, err
		}
		item.CreatedAt = created.UTC().Format(time.RFC3339Nano)
		item.Message = taskLogMessage(item.Action)
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

// postgresCustomTaskTemplates is called by task creation after the scope and
// port checks have succeeded. It stores only generated read-only templates in
// the task projection; the API never accepts raw Nuclei YAML.
func (s *PostgresRuntimeStore) postgresCustomTaskTemplates(ctx context.Context, input taskflow.TaskInput) ([]json.RawMessage, error) {
	return s.postgresCustomTemplates(ctx, input)
}
