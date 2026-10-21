package repo

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"scanner-platform/internal/assets"
	"scanner-platform/internal/portprobe"
	"scanner-platform/internal/reporting"
	"scanner-platform/internal/rules"
	"scanner-platform/internal/scheduler"
	"scanner-platform/internal/taskflow"
)

// PostgresRuntimeStore is the Server runtime backed by the normalized
// PostgreSQL queue, task projection, finding projection and report stores.
// Optional legacy administrative surfaces are deliberately inherited from an
// explicit capability backend until their PostgreSQL tables are implemented;
// no request falls back to SQLite.
type PostgresRuntimeStore struct {
	RuntimeBackend
	db         *sql.DB
	queue      *PostgresTaskStore
	projection *PostgresTaskProjection
	finding    *PostgresFindingStore
	reports    *PostgresReportStore
}

var _ RuntimeBackend = (*PostgresRuntimeStore)(nil)

func NewPostgresRuntime(db *sql.DB) (*PostgresRuntimeStore, error) {
	if db == nil {
		return nil, ErrPostgresDSNRequired
	}
	queue, err := NewPostgresTaskStore(db)
	if err != nil {
		return nil, err
	}
	projection, err := NewPostgresTaskProjection(db)
	if err != nil {
		return nil, err
	}
	finding, err := NewPostgresFindingStore(db)
	if err != nil {
		return nil, err
	}
	reports, err := NewPostgresReportStore(db)
	if err != nil {
		return nil, err
	}
	return &PostgresRuntimeStore{
		RuntimeBackend: unsupportedRuntimeBackend{},
		db:             db,
		queue:          queue,
		projection:     projection,
		finding:        finding,
		reports:        reports,
	}, nil
}

// RuntimeMode lets diagnostics report the selected persistence backend without
// exposing connection details or silently mixing stores.
func (s *PostgresRuntimeStore) RuntimeMode() string { return "postgres" }

// UnavailableRuntimeCapabilities is intentionally explicit. The API must not
// advertise SQLite-only scheduling, notifications or rule administration when
// the Server is connected to PostgreSQL.
func (s *PostgresRuntimeStore) UnavailableRuntimeCapabilities() []string {
	return []string{"synthetic-worker", "schedules", "rule-import", "rule-activation", "notifications"}
}

// Close is intentionally a no-op. The bootstrap owns the shared pool used by
// account, asset, approval and runtime repositories.
func (s *PostgresRuntimeStore) Close() error { return nil }

func (s *PostgresRuntimeStore) InitReports(ctx context.Context) error {
	return s.reports.InitReports(ctx)
}

func (s *PostgresRuntimeStore) ListReportTemplates(ctx context.Context) ([]reporting.Template, error) {
	return s.reports.ListReportTemplates(ctx)
}

func (s *PostgresRuntimeStore) GetReportTemplate(ctx context.Context, id string) (reporting.Template, error) {
	return s.reports.GetReportTemplate(ctx, id)
}

func (s *PostgresRuntimeStore) SaveReportTemplate(ctx context.Context, in reporting.Template, actor string) (reporting.Template, error) {
	return s.reports.SaveReportTemplate(ctx, in, actor)
}

func (s *PostgresRuntimeStore) CreateReport(ctx context.Context, in reporting.Request, actor string) (reporting.Job, error) {
	return s.reports.CreateReport(ctx, in, actor)
}

func (s *PostgresRuntimeStore) GetReport(ctx context.Context, id string) (reporting.Job, error) {
	return s.reports.GetReport(ctx, id)
}

func (s *PostgresRuntimeStore) ListReports(ctx context.Context) ([]reporting.Job, error) {
	return s.reports.ListReports(ctx)
}

func (s *PostgresRuntimeStore) ListReportsPage(ctx context.Context, in ReportListQuery) (ReportListPage, error) {
	return s.reports.ListReportsPage(ctx, in)
}

func (s *PostgresRuntimeStore) ReportSnapshot(ctx context.Context, id string) (reporting.Snapshot, error) {
	return s.reports.ReportSnapshot(ctx, id)
}

func (s *PostgresRuntimeStore) RetryReport(ctx context.Context, id, actor string) (reporting.Job, error) {
	return s.reports.RetryReport(ctx, id, actor)
}

func (s *PostgresRuntimeStore) CreateReportFormat(ctx context.Context, id, format, actor string) (reporting.Job, error) {
	return s.reports.CreateReportFormat(ctx, id, format, actor)
}

func (s *PostgresRuntimeStore) OpenReport(ctx context.Context, id string) (reporting.Job, *os.File, error) {
	return s.reports.OpenReport(ctx, id)
}

func (s *PostgresRuntimeStore) ProcessNextReport(ctx context.Context, directory string) (bool, error) {
	return s.reports.ProcessNextReport(ctx, directory)
}

func (s *PostgresRuntimeStore) RecoverReports(ctx context.Context) error {
	return s.reports.RecoverReports(ctx)
}

func (s *PostgresRuntimeStore) RunReports(ctx context.Context, directory string) error {
	return s.reports.RunReports(ctx, directory)
}

// ListRules and SyncRules are the small PostgreSQL rule-catalog projection
// needed by an explicit runtime. The signed release files and CURRENT pointer
// remain owned by sec-updater; this table never stores rule bytes.
func (s *PostgresRuntimeStore) ListRules(ctx context.Context) ([]rules.Bundle, error) {
	page, err := s.ListRulesPage(ctx, RuleListQuery{Page: 1})
	if err != nil {
		return nil, err
	}
	return page.Items, nil
}

func (s *PostgresRuntimeStore) ListRulesPage(ctx context.Context, in RuleListQuery) (RuleListPage, error) {
	query, err := NormalizeRuleListQuery(in)
	if err != nil {
		return RuleListPage{}, err
	}
	where := []string{"TRUE"}
	args := make([]any, 0, 1)
	if query.Search != "" {
		pattern := "%" + escapeTaskLike(query.Search) + "%"
		args = append(args, pattern)
		where = append(where, fmt.Sprintf("(version ILIKE $%d OR channel ILIKE $%d)", len(args), len(args)))
	}
	whereSQL := strings.Join(where, " AND ")
	var total int
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM rule_bundles WHERE "+whereSQL, args...).Scan(&total); err != nil {
		return RuleListPage{}, fmt.Errorf("count postgres rule bundles: %w", err)
	}
	sortColumn := "published_at"
	switch strings.TrimPrefix(query.Sort, "-") {
	case "version":
		sortColumn = "version"
	case "channel":
		sortColumn = "channel"
	case "published_at":
		sortColumn = "published_at"
	}
	direction := "DESC"
	if query.Sort != "" && !strings.HasPrefix(query.Sort, "-") {
		direction = "ASC"
	}
	statement := "SELECT version,engines,channel,manifest_sha256,published_at,is_current,is_backup,in_use_by_tasks,integrity_verified,signature_verified,engine_validated FROM rule_bundles WHERE " + whereSQL + " ORDER BY " + sortColumn + " " + direction + ",version DESC"
	selectArgs := append([]any(nil), args...)
	if query.PageSize > 0 {
		statement += fmt.Sprintf(" LIMIT $%d OFFSET $%d", len(selectArgs)+1, len(selectArgs)+2)
		selectArgs = append(selectArgs, query.PageSize, (query.Page-1)*query.PageSize)
	}
	rows, err := s.db.QueryContext(ctx, statement, selectArgs...)
	if err != nil {
		return RuleListPage{}, fmt.Errorf("list postgres rule bundles: %w", err)
	}
	defer rows.Close()
	items := make([]rules.Bundle, 0)
	for rows.Next() {
		var bundle rules.Bundle
		var engines string
		var publishedAt time.Time
		if err := rows.Scan(&bundle.Version, &engines, &bundle.Channel, &bundle.ManifestSHA256, &publishedAt, &bundle.IsCurrent, &bundle.IsBackup, &bundle.InUseByTasks, &bundle.IntegrityVerified, &bundle.SignatureVerified, &bundle.EngineValidated); err != nil {
			return RuleListPage{}, fmt.Errorf("scan postgres rule bundle: %w", err)
		}
		if err := json.Unmarshal([]byte(engines), &bundle.Engines); err != nil {
			return RuleListPage{}, fmt.Errorf("decode postgres rule engines: %w", err)
		}
		bundle.PublishedAt = publishedAt.UTC().Format(time.RFC3339Nano)
		items = append(items, bundle)
	}
	if err := rows.Err(); err != nil {
		return RuleListPage{}, fmt.Errorf("iterate postgres rule bundles: %w", err)
	}
	pageSize := query.PageSize
	if pageSize == 0 {
		pageSize = len(items)
		if pageSize == 0 {
			pageSize = DefaultSystemListPageSize
		}
	}
	return RuleListPage{Items: items, Total: total, Page: query.Page, PageSize: pageSize}, nil
}

func (s *PostgresRuntimeStore) SyncRules(ctx context.Context, bundles []rules.Bundle) error {
	if len(bundles) > 1000 {
		return ErrInvalidTask
	}
	current := 0
	for _, bundle := range bundles {
		if !rules.ValidateVersion(bundle.Version) || strings.TrimSpace(bundle.Channel) == "" || strings.TrimSpace(bundle.ManifestSHA256) == "" {
			return ErrInvalidTask
		}
		decodedHash, err := hex.DecodeString(bundle.ManifestSHA256)
		if err != nil || len(decodedHash) != sha256.Size {
			return ErrInvalidTask
		}
		if len(bundle.Engines) == 0 || len(bundle.Engines) > 2 {
			return ErrInvalidTask
		}
		seenEngines := map[string]bool{}
		for _, engine := range bundle.Engines {
			if (engine != "nuclei" && engine != "trivy") || seenEngines[engine] {
				return ErrInvalidTask
			}
			seenEngines[engine] = true
		}
		if _, err := time.Parse(time.RFC3339Nano, bundle.PublishedAt); err != nil {
			return ErrInvalidTask
		}
		if bundle.InUseByTasks < 0 {
			return ErrInvalidTask
		}
		if bundle.IsCurrent {
			current++
		}
	}
	if current > 1 {
		return ErrInvalidTask
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin postgres rule sync: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, "DELETE FROM rule_bundles"); err != nil {
		return fmt.Errorf("clear postgres rule catalog: %w", err)
	}
	for _, bundle := range bundles {
		engines, err := json.Marshal(bundle.Engines)
		if err != nil {
			return fmt.Errorf("encode postgres rule engines: %w", err)
		}
		publishedAt, _ := time.Parse(time.RFC3339Nano, bundle.PublishedAt)
		if _, err := tx.ExecContext(ctx, `INSERT INTO rule_bundles
			(version,channel,manifest_sha256,published_at,engines,is_current,is_backup,in_use_by_tasks,integrity_verified,signature_verified,engine_validated)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, bundle.Version, bundle.Channel, bundle.ManifestSHA256, publishedAt.UTC(), string(engines), bundle.IsCurrent, bundle.IsBackup, bundle.InUseByTasks, bundle.IntegrityVerified, bundle.SignatureVerified, bundle.EngineValidated); err != nil {
			return fmt.Errorf("insert postgres rule bundle: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit postgres rule sync: %w", err)
	}
	return nil
}

func (s *PostgresRuntimeStore) ListRuntimeAssets(ctx context.Context) ([]assets.Asset, error) {
	store, err := assets.NewPostgres(s.db)
	if err != nil {
		return nil, err
	}
	return store.List(ctx)
}

func (s *PostgresRuntimeStore) ListRuntimeFindings(ctx context.Context) ([]taskflow.Finding, error) {
	page, err := s.finding.ListPage(ctx, FindingListQuery{Page: 1})
	if err != nil {
		return nil, err
	}
	return page.Items, nil
}

func (s *PostgresRuntimeStore) ListRuntimeFindingsPage(ctx context.Context, in FindingListQuery) (FindingListPage, error) {
	return s.finding.ListPage(ctx, in)
}

func (s *PostgresRuntimeStore) ListTaskFindings(ctx context.Context, id string) ([]taskflow.Finding, error) {
	return s.finding.ListTaskFindings(ctx, id)
}

func (s *PostgresRuntimeStore) GetRuntimeTask(ctx context.Context, id string) (taskflow.Task, error) {
	task, err := s.projection.Get(ctx, id)
	if err != nil {
		if errors.Is(err, ErrPostgresProjectionMissing) {
			return taskflow.Task{}, ErrTaskNotFound
		}
		return taskflow.Task{}, err
	}
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM task_finding_observations WHERE task_id=$1`, id).Scan(&task.FindingCount); err != nil {
		return taskflow.Task{}, fmt.Errorf("count postgres task findings: %w", err)
	}
	return task, nil
}

func (s *PostgresRuntimeStore) ListRuntimeTasks(ctx context.Context) ([]taskflow.Task, error) {
	page, err := s.ListRuntimeTasksPage(ctx, TaskListQuery{Page: 1, Archived: "all"})
	if err != nil {
		return nil, err
	}
	return page.Items, nil
}

func (s *PostgresRuntimeStore) ListRuntimeTasksPage(ctx context.Context, in TaskListQuery) (TaskListPage, error) {
	query, err := NormalizeTaskListQuery(in)
	if err != nil {
		return TaskListPage{}, err
	}
	where, args := postgresRuntimeTaskWhere(query)
	var total int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM scan_tasks t
		JOIN scan_task_projections p ON p.task_id=t.id WHERE `+where, args...).Scan(&total); err != nil {
		return TaskListPage{}, fmt.Errorf("count postgres runtime tasks: %w", err)
	}
	statusWhere, statusArgs := postgresRuntimeTaskWhere(func() TaskListQuery {
		copy := query
		copy.Status = ""
		return copy
	}())
	statusRows, err := s.db.QueryContext(ctx, `SELECT t.status,COUNT(*) FROM scan_tasks t
		JOIN scan_task_projections p ON p.task_id=t.id WHERE `+statusWhere+` GROUP BY t.status`, statusArgs...)
	if err != nil {
		return TaskListPage{}, fmt.Errorf("count postgres runtime task statuses: %w", err)
	}
	statusCounts := map[string]int{}
	for statusRows.Next() {
		var status string
		var count int
		if err := statusRows.Scan(&status, &count); err != nil {
			statusRows.Close()
			return TaskListPage{}, err
		}
		statusCounts[status] = count
	}
	if err := statusRows.Err(); err != nil {
		statusRows.Close()
		return TaskListPage{}, err
	}
	if err := statusRows.Close(); err != nil {
		return TaskListPage{}, err
	}

	sortExpr, direction := postgresRuntimeTaskSort(query.Sort)
	selectSQL := `SELECT t.id FROM scan_tasks t JOIN scan_task_projections p ON p.task_id=t.id WHERE ` + where +
		` ORDER BY ` + sortExpr + ` ` + direction + `,t.id ASC`
	selectArgs := append([]any(nil), args...)
	if query.PageSize > 0 {
		selectSQL += fmt.Sprintf(" LIMIT $%d OFFSET $%d", len(selectArgs)+1, len(selectArgs)+2)
		selectArgs = append(selectArgs, query.PageSize, (query.Page-1)*query.PageSize)
	}
	rows, err := s.db.QueryContext(ctx, selectSQL, selectArgs...)
	if err != nil {
		return TaskListPage{}, fmt.Errorf("list postgres runtime tasks: %w", err)
	}
	ids := make([]string, 0)
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return TaskListPage{}, err
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return TaskListPage{}, err
	}
	if err := rows.Close(); err != nil {
		return TaskListPage{}, err
	}
	items := make([]taskflow.Task, 0, len(ids))
	for _, id := range ids {
		item, err := s.GetRuntimeTask(ctx, id)
		if err != nil {
			return TaskListPage{}, err
		}
		items = append(items, item)
	}
	pageSize := query.PageSize
	if pageSize == 0 {
		pageSize = len(items)
		if pageSize == 0 {
			pageSize = DefaultTaskPageSize
		}
	}
	return TaskListPage{Items: items, Total: total, Page: query.Page, PageSize: pageSize, StatusCounts: statusCounts}, nil
}

func postgresRuntimeTaskWhere(query TaskListQuery) (string, []any) {
	clauses := []string{"TRUE"}
	args := make([]any, 0, 6)
	add := func(value any) string {
		args = append(args, value)
		return fmt.Sprintf("$%d", len(args))
	}
	switch query.Archived {
	case "true":
		clauses = append(clauses, "t.archived_at IS NOT NULL")
	case "false", "":
		clauses = append(clauses, "t.archived_at IS NULL")
	}
	if query.Status != "" {
		clauses = append(clauses, "t.status="+add(query.Status))
	}
	if query.Engine != "" {
		engine := add(query.Engine)
		clauses = append(clauses, "(p.data::jsonb -> 'engines') ? "+engine)
	}
	if query.Search != "" {
		pattern := "%" + escapeTaskLike(query.Search) + "%"
		value := add(pattern)
		clauses = append(clauses, "(t.id ILIKE "+value+" ESCAPE '\\' OR p.data ILIKE "+value+" ESCAPE '\\')")
	}
	return strings.Join(clauses, " AND "), args
}

func postgresRuntimeTaskSort(value string) (string, string) {
	direction := "ASC"
	if value == "" || strings.HasPrefix(value, "-") {
		direction = "DESC"
	}
	switch strings.TrimPrefix(strings.TrimPrefix(value, "+"), "-") {
	case "status":
		return "t.status", direction
	case "engine":
		return "COALESCE(p.data::jsonb -> 'engines' ->> 0,'')", direction
	default:
		return "t.created_at", direction
	}
}

func (s *PostgresRuntimeStore) CreateSyntheticTask(context.Context) (taskflow.Task, error) {
	return taskflow.Task{}, backendCapabilityError("CreateSyntheticTask")
}

func (s *PostgresRuntimeStore) CancelTask(ctx context.Context, id, actor string) error {
	if strings.TrimSpace(id) == "" || strings.TrimSpace(actor) == "" {
		return ErrInvalidTask
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin postgres task cancellation: %w", err)
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE scan_tasks SET status='CANCELED'
		WHERE id=$1 AND status IN ('PENDING','WAITING_WINDOW','PAUSED_WINDOW','PAUSED','RUNNING')`, id)
	if err != nil {
		return fmt.Errorf("cancel postgres task: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil || changed != 1 {
		return ErrTaskConflict
	}
	if _, err := tx.ExecContext(ctx, `UPDATE scan_task_chunks SET status='CANCELED',worker_node_id=NULL,lease_expires_at=NULL WHERE task_id=$1 AND status IN ('PENDING','PAUSED','RUNNING')`, id); err != nil {
		return fmt.Errorf("cancel postgres task chunks: %w", err)
	}
	if err := s.postgresAuditTx(ctx, tx, actor, "cancel_task", "task", id, ""); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *PostgresRuntimeStore) PauseTask(ctx context.Context, id, actor string) error {
	if strings.TrimSpace(id) == "" || strings.TrimSpace(actor) == "" {
		return ErrInvalidTask
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin postgres task pause: %w", err)
	}
	defer tx.Rollback()
	var status string
	if err := tx.QueryRowContext(ctx, `SELECT status FROM scan_tasks WHERE id=$1 FOR UPDATE`, id).Scan(&status); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrTaskNotFound
		}
		return err
	}
	if status == "PAUSED" {
		return tx.Commit()
	}
	if status != "PENDING" && status != "WAITING_WINDOW" && status != "PAUSED_WINDOW" && status != "RUNNING" {
		return ErrTaskNotPausable
	}
	if _, err := tx.ExecContext(ctx, `UPDATE scan_tasks SET status='PAUSED' WHERE id=$1`, id); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE scan_task_chunks SET status='PAUSED',worker_node_id=NULL,lease_expires_at=NULL WHERE task_id=$1 AND status IN ('PENDING','RUNNING')`, id); err != nil {
		return err
	}
	if err := s.postgresAuditTx(ctx, tx, actor, "pause_task", "task", id, "扫描任务已暂停"); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *PostgresRuntimeStore) ResumeTask(ctx context.Context, id, actor string) error {
	if strings.TrimSpace(id) == "" || strings.TrimSpace(actor) == "" {
		return ErrInvalidTask
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin postgres task resume: %w", err)
	}
	defer tx.Rollback()
	var status string
	if err := tx.QueryRowContext(ctx, `SELECT status FROM scan_tasks WHERE id=$1 FOR UPDATE`, id).Scan(&status); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrTaskNotFound
		}
		return err
	}
	if status == "PENDING" {
		return tx.Commit()
	}
	if status != "PAUSED" {
		return ErrTaskNotResumable
	}
	if _, err := tx.ExecContext(ctx, `UPDATE scan_tasks SET status='PENDING' WHERE id=$1 AND status='PAUSED'`, id); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE scan_task_chunks SET status='PENDING' WHERE task_id=$1 AND status='PAUSED'`, id); err != nil {
		return err
	}
	if err := s.postgresAuditTx(ctx, tx, actor, "resume_task", "task", id, "扫描任务已恢复到队列"); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *PostgresRuntimeStore) SetTaskArchived(ctx context.Context, id, actor string, archived bool) error {
	if strings.TrimSpace(id) == "" || strings.TrimSpace(actor) == "" {
		return ErrInvalidTask
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin postgres task archive: %w", err)
	}
	defer tx.Rollback()
	var status string
	if err := tx.QueryRowContext(ctx, `SELECT status FROM scan_tasks WHERE id=$1 FOR UPDATE`, id).Scan(&status); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrTaskNotFound
		}
		return err
	}
	if !terminalTaskStatus(status) {
		return ErrTaskNotTerminal
	}
	var archive any
	if archived {
		archive = time.Now().UTC()
	}
	if _, err := tx.ExecContext(ctx, `UPDATE scan_tasks SET archived_at=$1 WHERE id=$2`, archive, id); err != nil {
		return err
	}
	action, detail := "archive_task", "扫描任务已归档"
	if !archived {
		action, detail = "restore_task", "扫描任务已从归档恢复"
	}
	if err := s.postgresAuditTx(ctx, tx, actor, action, "task", id, detail); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *PostgresRuntimeStore) DeleteRuntimeTask(ctx context.Context, id, actor string) error {
	if strings.TrimSpace(id) == "" || strings.TrimSpace(actor) == "" {
		return ErrInvalidTask
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin postgres task deletion: %w", err)
	}
	defer tx.Rollback()
	var status string
	if err := tx.QueryRowContext(ctx, `SELECT status FROM scan_tasks WHERE id=$1 FOR UPDATE`, id).Scan(&status); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrTaskNotFound
		}
		return err
	}
	if !terminalTaskStatus(status) {
		return ErrTaskNotTerminal
	}
	var findingsCount int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM (
		SELECT finding_id FROM task_finding_observations WHERE task_id=$1
		UNION
		SELECT id FROM security_findings WHERE first_seen_task_id=$1 OR last_seen_task_id=$1
	) findings`, id).Scan(&findingsCount); err != nil {
		return err
	}
	if findingsCount > 0 {
		return ErrTaskHasFindings
	}
	if err := s.postgresAuditTx(ctx, tx, actor, "delete_task", "task", id, "终态任务无关联发现项，已彻底删除任务记录"); err != nil {
		return err
	}
	for _, table := range []string{"scan_task_progress", "scan_task_chunks", "scan_task_projections", "task_finding_observations"} {
		if _, err := tx.ExecContext(ctx, `DELETE FROM `+table+` WHERE task_id=$1`, id); err != nil {
			return fmt.Errorf("delete postgres task %s: %w", table, err)
		}
	}
	result, err := tx.ExecContext(ctx, `DELETE FROM scan_tasks WHERE id=$1 AND status IN ('COMPLETED','FAILED','CANCELED')`, id)
	if err != nil {
		return err
	}
	if changed, err := result.RowsAffected(); err != nil || changed != 1 {
		return ErrTaskConflict
	}
	return tx.Commit()
}

func (s *PostgresRuntimeStore) CreateLocalTask(ctx context.Context, in taskflow.TaskInput, actor string) (taskflow.Task, error) {
	if strings.TrimSpace(actor) == "" || strings.TrimSpace(in.AssetID) == "" ||
		(in.Engine != "auto" && in.Engine != "port-probe") || !in.PortProbe.OpsApproved {
		return taskflow.Task{}, ErrInvalidTask
	}
	if len(in.Targets) > 1 {
		return taskflow.Task{}, ErrInvalidTask
	}
	var address, assetGroup, owner string
	if err := s.db.QueryRowContext(ctx, `SELECT address,business_group,owner FROM assets
		WHERE id=$1 AND kind='host'`, in.AssetID).Scan(&address, &assetGroup, &owner); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return taskflow.Task{}, ErrInvalidTask
		}
		return taskflow.Task{}, fmt.Errorf("read postgres task asset: %w", err)
	}
	ip, err := netip.ParseAddr(address)
	if err != nil || ip.IsUnspecified() || ip.IsMulticast() || ip.Zone() != "" {
		return taskflow.Task{}, ErrInvalidTask
	}
	address = ip.Unmap().String()
	if len(in.Targets) == 1 && strings.TrimSpace(in.Targets[0]) != address {
		return taskflow.Task{}, ErrInvalidTask
	}

	var scopeID, scopeHost, windowsRaw string
	var expires time.Time
	err = s.db.QueryRowContext(ctx, `SELECT id,cidr_or_host,time_windows,expires_at
		FROM authorized_scopes WHERE asset_id=$1 AND status='APPROVED'
		AND expires_at>CURRENT_TIMESTAMP ORDER BY expires_at DESC,id LIMIT 1`, in.AssetID).
		Scan(&scopeID, &scopeHost, &windowsRaw, &expires)
	if errors.Is(err, sql.ErrNoRows) || scopeHost != address || !expires.After(time.Now().UTC()) {
		return taskflow.Task{}, ErrInvalidTask
	}
	var scopeWindows []scheduler.Window
	if err := json.Unmarshal([]byte(windowsRaw), &scopeWindows); err != nil {
		return taskflow.Task{}, fmt.Errorf("decode postgres scope windows: %w", err)
	}
	if len(in.TimeWindows) == 0 {
		in.TimeWindows = scopeWindows
	} else {
		requested, _ := json.Marshal(in.TimeWindows)
		approved, _ := json.Marshal(scopeWindows)
		if string(requested) != string(approved) {
			return taskflow.Task{}, fmt.Errorf("%w: task window must stay within approved scope", ErrInvalidTask)
		}
	}
	if err := scheduler.ValidateWindows(in.TimeWindows); err != nil {
		return taskflow.Task{}, ErrInvalidTask
	}

	config := in.PortProbe
	if config.Preset == "" {
		config.Preset = portprobe.PresetCommon
	}
	if len(config.CommonPorts) == 0 {
		config.CommonPorts = portprobe.CommonPorts()
	}
	config.RegisteredPorts, err = s.postgresRegisteredPorts(ctx, in.AssetID)
	if err != nil {
		return taskflow.Task{}, err
	}
	selected, err := portprobe.SelectPorts(config)
	if err != nil {
		return taskflow.Task{}, fmt.Errorf("%w: %v", ErrInvalidTask, err)
	}
	excluded, err := s.postgresExcludedPorts(ctx, in.AssetID)
	if err != nil {
		return taskflow.Task{}, err
	}
	effective := make([]int, 0, len(selected))
	skipped := make([]string, 0)
	for _, port := range selected {
		if excluded[port] {
			skipped = append(skipped, net.JoinHostPort(address, strconv.Itoa(port)))
			continue
		}
		effective = append(effective, port)
	}
	if len(effective) == 0 {
		return taskflow.Task{}, fmt.Errorf("%w: all ports are excluded", ErrInvalidTask)
	}
	if in.Engine == "auto" {
		approved, err := s.postgresApprovedVulnerabilityPorts(ctx, in.AssetID, effective)
		if err != nil {
			return taskflow.Task{}, err
		}
		if approved != len(effective) {
			return taskflow.Task{}, fmt.Errorf("%w: 自动综合扫描端口必须先完成端口授权", ErrInvalidTask)
		}
	}

	now := time.Now().UTC()
	deadline, allowed, err := scheduler.AllowedUntil(in.TimeWindows, now)
	if err != nil {
		return taskflow.Task{}, ErrInvalidTask
	}
	status := "PENDING"
	if !allowed {
		status = "WAITING_WINDOW"
		deadline = time.Time{}
	}
	ruleVersion := NoRuleLeaseVersion
	if in.Engine == "auto" {
		ruleVersion, err = s.currentPostgresRuleVersion(ctx)
		if err != nil {
			return taskflow.Task{}, err
		}
	}
	id := "task-" + randomLocalID()
	chunkID := id + "-chunk"
	input := in
	input.Targets = []string{address}
	input.PortProbe = config
	input.PortProbe.RegisteredPorts = nil
	task := taskflow.Task{
		ID: id, ScopeID: scopeID, ScopeName: "单台资产自动端口与 HTTP 漏洞检查", Engines: []string{in.Engine},
		Status: status, AssetID: in.AssetID, CreatedAt: now, FixedThreshold: defaultPolicy().FixedThreshold,
		TargetCount: 1, TotalChunks: 1, RuleVersion: ruleVersion, TimeWindows: in.TimeWindows,
		Chunks:              []taskflow.Chunk{{ID: chunkID, TaskID: id, Targets: []string{address}, Status: status, PinnedRuleVersion: ruleVersion}},
		EffectiveExclusions: compactPostgresPortRanges(appendRanges(config.Exclusions, excluded)),
		SkippedTargets:      skipped, PortProbeConfig: config, PortProbePorts: effective, AssetProfile: taskflow.Task{}.AssetProfile,
	}
	if in.Engine == "port-probe" {
		task.ScopeName = "单台资产 TCP 端口探测"
		task.RuleVersion = NoRuleLeaseVersion
		task.Chunks[0].PinnedRuleVersion = NoRuleLeaseVersion
	} else {
		task.VulnerabilityPorts = append([]int(nil), effective...)
		task.SystemScanStatus = taskflow.SystemScanNotStarted
	}
	if allowed {
		task.HardDeadline = deadline.UTC().Format(time.RFC3339Nano)
	}
	if owner != "" || assetGroup != "" {
		// Owner/group are retained in the task only through finding ownership;
		// the asset table remains authoritative and is re-read on completion.
		_ = owner
		_ = assetGroup
	}
	if err := s.queue.CreateTaskWithProjection(ctx, ScanTask{
		ID: id, ScopeID: scopeID, Status: status, HardDeadline: deadline,
		CreatedBy: actor, Engines: task.Engines, Targets: []string{address}, PinnedRuleVersion: ruleVersion,
	}, s.projection, task); err != nil {
		return taskflow.Task{}, err
	}
	if err := s.postgresAudit(ctx, actor, "create_task", "task", id, "创建 PostgreSQL 扫描任务"); err != nil {
		return taskflow.Task{}, err
	}
	return s.GetRuntimeTask(ctx, id)
}

func (s *PostgresRuntimeStore) postgresRegisteredPorts(ctx context.Context, assetID string) ([]int, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT port FROM asset_ports WHERE asset_id=$1
		AND kind<>'EXCLUDED_PROXY' AND NOT EXISTS (
		SELECT 1 FROM port_quarantine q WHERE q.asset_id=asset_ports.asset_id
		AND q.port=asset_ports.port AND q.status='ACTIVE') ORDER BY port`, assetID)
	if err != nil {
		return nil, fmt.Errorf("list postgres registered ports: %w", err)
	}
	defer rows.Close()
	ports := make([]int, 0)
	for rows.Next() {
		var port int
		if err := rows.Scan(&port); err != nil {
			return nil, err
		}
		ports = append(ports, port)
	}
	return ports, rows.Err()
}

func (s *PostgresRuntimeStore) postgresExcludedPorts(ctx context.Context, assetID string) (map[int]bool, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT port FROM asset_ports WHERE asset_id=$1 AND kind='EXCLUDED_PROXY'
		UNION SELECT port FROM port_quarantine WHERE asset_id=$1 AND status='ACTIVE'`, assetID)
	if err != nil {
		return nil, fmt.Errorf("list postgres excluded ports: %w", err)
	}
	defer rows.Close()
	ports := map[int]bool{}
	for rows.Next() {
		var port int
		if err := rows.Scan(&port); err != nil {
			return nil, err
		}
		ports[port] = true
	}
	return ports, rows.Err()
}

func (s *PostgresRuntimeStore) postgresApprovedVulnerabilityPorts(ctx context.Context, assetID string, ports []int) (int, error) {
	if len(ports) == 0 {
		return 0, nil
	}
	args := []any{assetID}
	placeholders := make([]string, len(ports))
	for i, port := range ports {
		args = append(args, port)
		placeholders[i] = fmt.Sprintf("$%d", len(args))
	}
	var count int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM asset_port_reviews r
		JOIN asset_ports p ON p.asset_id=r.asset_id AND p.port=r.port
		WHERE r.asset_id=$1 AND r.status='APPROVED' AND p.kind IN ('WEB','NON_WEB')
		AND r.port IN (`+strings.Join(placeholders, ",")+")", args...).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("check postgres port approvals: %w", err)
	}
	return count, nil
}

func (s *PostgresRuntimeStore) currentPostgresRuleVersion(ctx context.Context) (string, error) {
	var version string
	err := s.db.QueryRowContext(ctx, `SELECT version FROM rule_bundles WHERE is_current=TRUE ORDER BY published_at DESC,version DESC LIMIT 1`).Scan(&version)
	if errors.Is(err, sql.ErrNoRows) {
		return "", fmt.Errorf("%w: PostgreSQL 尚未登记活动规则包", ErrInvalidTask)
	}
	if err != nil {
		return "", fmt.Errorf("read postgres current rule version: %w", err)
	}
	if !rules.ValidateVersion(version) {
		return "", fmt.Errorf("%w: PostgreSQL 规则版本无效", ErrInvalidTask)
	}
	return version, nil
}

func appendRanges(ranges []portprobe.Range, excluded map[int]bool) []portprobe.Range {
	result := append([]portprobe.Range(nil), ranges...)
	for port := range excluded {
		result = append(result, portprobe.Range{Start: port, End: port})
	}
	return result
}

func compactPostgresPortRanges(ranges []portprobe.Range) []portprobe.Range {
	ports := map[int]bool{}
	for _, value := range ranges {
		if value.Start < 1 || value.End < value.Start || value.End > 65535 {
			continue
		}
		for port := value.Start; port <= value.End; port++ {
			ports[port] = true
		}
	}
	ordered := make([]int, 0, len(ports))
	for port := range ports {
		ordered = append(ordered, port)
	}
	sort.Ints(ordered)
	result := make([]portprobe.Range, 0)
	for _, port := range ordered {
		if len(result) == 0 || port != result[len(result)-1].End+1 {
			result = append(result, portprobe.Range{Start: port, End: port})
		} else {
			result[len(result)-1].End = port
		}
	}
	return result
}

func (s *PostgresRuntimeStore) ClaimRuntimeTask(ctx context.Context, worker string) (*taskflow.Task, error) {
	chunk, err := s.queue.ClaimChunkWithRules(ctx, worker, "", false)
	if errors.Is(err, ErrPostgresTaskUnavailable) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	task, err := s.GetRuntimeTask(ctx, chunk.TaskID)
	if err != nil {
		return nil, err
	}
	return &task, nil
}

func (s *PostgresRuntimeStore) ClaimRuntimeTaskWithRules(ctx context.Context, worker, localRuleVersion string, rulesReady bool) (*taskflow.Task, error) {
	chunk, err := s.queue.ClaimChunkWithRules(ctx, worker, localRuleVersion, rulesReady)
	if errors.Is(err, ErrPostgresTaskUnavailable) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	task, err := s.GetRuntimeTask(ctx, chunk.TaskID)
	if err != nil {
		return nil, err
	}
	return &task, nil
}

func (s *PostgresRuntimeStore) UpdateRuntimeTaskProgress(ctx context.Context, worker string, update taskflow.ProgressUpdate) error {
	return s.projection.SaveProgress(ctx, worker, update)
}

func (s *PostgresRuntimeStore) TaskStateForWorker(ctx context.Context, id, worker string) string {
	var status string
	err := s.db.QueryRowContext(ctx, `SELECT t.status FROM scan_tasks t JOIN scan_task_chunks c ON c.task_id=t.id
		WHERE t.id=$1 AND c.worker_node_id=$2`, id, worker).Scan(&status)
	if err != nil {
		return ""
	}
	return status
}

func (s *PostgresRuntimeStore) RenewChunkLease(ctx context.Context, taskID, workerID, pinnedRuleVersion string) (time.Time, error) {
	if strings.TrimSpace(taskID) == "" {
		return time.Time{}, ErrTaskLease
	}
	return s.queue.RenewChunkLease(ctx, taskID+"-chunk", workerID, pinnedRuleVersion)
}

func (s *PostgresRuntimeStore) CountRunningByVersion(ctx context.Context, nodeID, version string) (int, error) {
	return s.queue.CountRunningByVersion(ctx, version, nodeID)
}

func (s *PostgresRuntimeStore) CompleteRuntimeTask(ctx context.Context, report taskflow.Report) error {
	if strings.TrimSpace(report.TaskID) == "" || strings.TrimSpace(report.WorkerID) == "" || report.Status == "" {
		return ErrInvalidTask
	}
	if len(report.Findings) > 100000 || len(report.Error) > 500 {
		return ErrInvalidTask
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin postgres runtime completion: %w", err)
	}
	defer tx.Rollback()
	var status, worker, pinned, target string
	var lease sql.NullTime
	err = tx.QueryRowContext(ctx, `SELECT t.status,c.worker_node_id,COALESCE(c.pinned_rule_version,''),
		c.targets,c.lease_expires_at FROM scan_tasks t JOIN scan_task_chunks c ON c.task_id=t.id
		WHERE t.id=$1 AND c.id=$2 FOR UPDATE OF t,c`, report.TaskID, report.TaskID+"-chunk").Scan(
		&status, &worker, &pinned, &target, &lease)
	if errors.Is(err, sql.ErrNoRows) || status != "RUNNING" || worker != report.WorkerID || !lease.Valid || !lease.Time.After(time.Now().UTC()) {
		return ErrTaskConflict
	}
	var targets []string
	if err := json.Unmarshal([]byte(target), &targets); err != nil || len(targets) != 1 || report.Target != targets[0] {
		return fmt.Errorf("validate postgres report target: %w", ErrInvalidTask)
	}
	var raw string
	if err := tx.QueryRowContext(ctx, `SELECT data FROM scan_task_projections WHERE task_id=$1 FOR UPDATE`, report.TaskID).Scan(&raw); err != nil {
		return fmt.Errorf("read postgres task projection for completion: %w", err)
	}
	var task taskflow.Task
	if err := json.Unmarshal([]byte(raw), &task); err != nil {
		return fmt.Errorf("decode postgres task projection for completion: %w", err)
	}
	if len(task.Chunks) != 1 || len(task.Engines) != 1 {
		return ErrTaskConflict
	}
	if report.Status == "COMPLETED" {
		// CompletedFully gates lifecycle convergence (for example FIXED), not
		// ingestion of a completed HTTP/port result with an explicit SSH or
		// system collection failure state.
		if task.Engines[0] == "auto" && (!report.RulesExecuted || report.RuleVersion != pinned) {
			return fmt.Errorf("validate postgres auto completion: %w", ErrInvalidTask)
		}
		if err := validatePostgresReportOutputs(task, report); err != nil {
			return fmt.Errorf("validate postgres report outputs: %w", err)
		}
		for _, detection := range report.Findings {
			finding, err := postgresFindingFromDetection(ctx, tx, task, detection, report.TaskID)
			if err != nil {
				return fmt.Errorf("normalize postgres finding: %w", err)
			}
			if _, err := s.finding.SaveFindingTx(ctx, tx, finding, time.Now().UTC()); err != nil {
				return fmt.Errorf("save postgres finding: %w", err)
			}
		}
		if err := savePostgresInventoryTx(ctx, tx, task.AssetID, report); err != nil {
			return fmt.Errorf("save postgres inventory: %w", err)
		}
		task.PortProbeResults = append([]taskflow.PortProbeResult(nil), report.PortProbeResults...)
		task.ServiceResults = append([]taskflow.ServiceResult(nil), report.ServiceResults...)
		task.SystemScanStatus = report.SystemScanStatus
		task.ApplicationScanStatus = report.ApplicationScanStatus
		task.ApplicationResults = append([]taskflow.ApplicationResult(nil), report.ApplicationResults...)
		task.AssetProfile = report.AssetProfile
		task.Error = ""
		task.Status = "COMPLETED"
		if err := s.projection.SaveTx(ctx, tx, task); err != nil {
			return err
		}
		if err := s.queue.CompleteChunkTx(ctx, tx, report.TaskID+"-chunk", true); err != nil {
			return err
		}
	} else if report.Status == "PAUSED_WINDOW" {
		task.Status = "PAUSED_WINDOW"
		task.Error = ""
		if err := s.projection.SaveTx(ctx, tx, task); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE scan_task_chunks SET status='PENDING',worker_node_id=NULL,lease_expires_at=NULL WHERE id=$1`, report.TaskID+"-chunk"); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE scan_tasks SET status='PAUSED_WINDOW' WHERE id=$1`, report.TaskID); err != nil {
			return err
		}
	} else if report.Status == "FAILED" {
		if len(report.Findings) != 0 || len(report.PortProbeResults) != 0 || len(report.ServiceResults) != 0 {
			return ErrInvalidTask
		}
		task.Status, task.Error = "FAILED", safePostgresRuntimeError(report.Error)
		if err := s.projection.SaveTx(ctx, tx, task); err != nil {
			return err
		}
		if err := s.queue.CompleteChunkTx(ctx, tx, report.TaskID+"-chunk", false); err != nil {
			return err
		}
	} else {
		return ErrInvalidTask
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit postgres runtime completion: %w", err)
	}
	return nil
}

func safePostgresRuntimeError(value string) string {
	value = strings.TrimSpace(value)
	if len(value) > 500 {
		return value[:500]
	}
	return value
}

func validatePostgresReportOutputs(task taskflow.Task, report taskflow.Report) error {
	allowed := map[int]bool{}
	for _, port := range task.PortProbePorts {
		allowed[port] = true
	}
	for _, port := range report.PortProbeResults {
		if !allowed[port.Port] {
			return ErrInvalidTask
		}
	}
	for _, service := range report.ServiceResults {
		if !allowed[service.Port] || service.Excluded || service.Quarantined {
			return ErrInvalidTask
		}
	}
	return nil
}

func postgresFindingFromDetection(ctx context.Context, tx *sql.Tx, task taskflow.Task, detection taskflow.Detection, taskID string) (taskflow.Finding, error) {
	if detection.Engine == "" || detection.TemplateID == "" || detection.Title == "" || detection.Target == "" {
		return taskflow.Finding{}, ErrInvalidTask
	}
	host, portText, err := net.SplitHostPort(detection.Target)
	if err != nil || host != task.Chunks[0].Targets[0] {
		return taskflow.Finding{}, ErrInvalidTask
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return taskflow.Finding{}, ErrInvalidTask
	}
	allowed := map[int]bool{}
	for _, item := range task.VulnerabilityPorts {
		allowed[item] = true
	}
	if len(allowed) == 0 {
		for _, item := range task.PortProbePorts {
			allowed[item] = true
		}
	}
	if !allowed[port] {
		return taskflow.Finding{}, ErrInvalidTask
	}
	if detection.Engine != "nuclei" && detection.Engine != "trivy" && detection.Engine != "zap" && detection.Engine != "knowledge" {
		return taskflow.Finding{}, ErrInvalidTask
	}
	matchedPath := detection.MatchedPath
	if detection.Engine == "trivy" && task.InputKind == "rootfs" {
		matchedPath = ""
	}
	stable, _ := json.Marshal([]string{detection.Target, detection.Engine, detection.TemplateID, matchedPath, detection.Package, detection.InstalledVersion})
	digest := sha256.Sum256(stable)
	fingerprint := hex.EncodeToString(digest[:])
	var group, owner string
	if err := tx.QueryRowContext(ctx, `SELECT business_group,owner FROM assets WHERE id=$1`, task.AssetID).Scan(&group, &owner); err != nil {
		return taskflow.Finding{}, err
	}
	now := time.Now().UTC()
	return taskflow.Finding{
		ID: "finding-" + fingerprint, TaskID: taskID, AssetID: task.AssetID, Fingerprint: fingerprint,
		Severity: detection.Severity, Title: detection.Title, Engine: detection.Engine, TemplateOrCVE: detection.TemplateID,
		Target: detection.Target, Status: "OPEN", FirstSeen: now, LastSeen: now, BusinessGroup: group, Owner: owner,
		VerifiedInRun: true, MatchedPath: detection.MatchedPath, Package: detection.Package, InstalledVersion: detection.InstalledVersion,
		FixedVersion: detection.FixedVersion, ArtifactID: detection.ArtifactID, Description: detection.Description,
		RiskType: detection.RiskType, DetectMethod: detection.DetectMethod, Confidence: detection.Confidence, CVSSScore: detection.CVSSScore,
		VulnCategory: detection.VulnCategory, Identifiers: detection.Identifiers, Impact: detection.Impact, Solution: detection.Solution,
		References: detection.References, Evidence: detection.Evidence, Port: detection.Port, Component: detection.Component,
		ContentLanguage: detection.ContentLanguage,
	}, nil
}

func savePostgresInventoryTx(ctx context.Context, tx *sql.Tx, assetID string, report taskflow.Report) error {
	profile, err := json.Marshal(report.AssetProfile)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO asset_profiles(asset_id,data) VALUES ($1,$2)
		ON CONFLICT(asset_id) DO UPDATE SET data=EXCLUDED.data`, assetID, string(profile)); err != nil {
		return fmt.Errorf("save postgres asset profile: %w", err)
	}
	for _, service := range report.ServiceResults {
		data, err := json.Marshal(service)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO asset_services(asset_id,port,data) VALUES ($1,$2,$3)
			ON CONFLICT(asset_id,port) DO UPDATE SET data=EXCLUDED.data`, assetID, service.Port, string(data)); err != nil {
			return fmt.Errorf("save postgres asset service: %w", err)
		}
		for index, login := range service.LoginEntries {
			data, err := json.Marshal(login)
			if err != nil {
				return err
			}
			key := fmt.Sprintf("%d:%s:%s", service.Port, login.Type, login.Name)
			if _, err := tx.ExecContext(ctx, `INSERT INTO asset_login_entries(asset_id,entry_key,data) VALUES ($1,$2,$3)
				ON CONFLICT(asset_id,entry_key) DO UPDATE SET data=EXCLUDED.data`, assetID, key+":"+strconv.Itoa(index), string(data)); err != nil {
				return fmt.Errorf("save postgres asset login entry: %w", err)
			}
		}
	}
	return nil
}

func (s *PostgresRuntimeStore) ExpireAcceptedRisks(ctx context.Context, now time.Time) error {
	return s.finding.ExpireAcceptedRisks(ctx, now)
}

func (s *PostgresRuntimeStore) UpdateFindingDisposition(ctx context.Context, id string, in FindingDisposition, actor string) (taskflow.Finding, error) {
	return s.finding.UpdateFindingDisposition(ctx, id, in, actor)
}

func (s *PostgresRuntimeStore) UpdateFinding(ctx context.Context, id, status, actor string) (taskflow.Finding, error) {
	return s.finding.UpdateFindingDisposition(ctx, id, FindingDisposition{Status: status}, actor)
}

func (s *PostgresRuntimeStore) Tick(ctx context.Context, now time.Time) error {
	if err := s.ExpireAcceptedRisks(ctx, now); err != nil {
		return err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT t.id,p.data FROM scan_tasks t
		JOIN scan_task_projections p ON p.task_id=t.id
		WHERE t.status IN ('WAITING_WINDOW','PAUSED_WINDOW')`)
	if err != nil {
		return err
	}
	type waiting struct{ id, raw string }
	items := make([]waiting, 0)
	for rows.Next() {
		var item waiting
		if err := rows.Scan(&item.id, &item.raw); err != nil {
			rows.Close()
			return err
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, item := range items {
		var task taskflow.Task
		if err := json.Unmarshal([]byte(item.raw), &task); err != nil {
			return err
		}
		deadline, allowed, err := scheduler.AllowedUntil(task.TimeWindows, now)
		if err != nil || !allowed {
			continue
		}
		if _, err := s.db.ExecContext(ctx, `UPDATE scan_tasks SET status='PENDING',hard_deadline=$1
			WHERE id=$2 AND status IN ('WAITING_WINDOW','PAUSED_WINDOW')`, deadline.UTC(), item.id); err != nil {
			return err
		}
		if _, err := s.db.ExecContext(ctx, `UPDATE scan_task_chunks SET status='PENDING',worker_node_id=NULL,lease_expires_at=NULL
			WHERE task_id=$1 AND status IN ('PENDING','FAILED')`, item.id); err != nil {
			return err
		}
	}
	_, err = s.db.ExecContext(ctx, `UPDATE scan_task_chunks c SET status='PENDING',worker_node_id=NULL,lease_expires_at=NULL
		FROM scan_tasks t WHERE c.task_id=t.id AND c.status='RUNNING' AND c.lease_expires_at<=CURRENT_TIMESTAMP
		AND t.status='RUNNING'`)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `UPDATE scan_tasks t SET status='PENDING' WHERE t.status='RUNNING'
		AND NOT EXISTS (SELECT 1 FROM scan_task_chunks c WHERE c.task_id=t.id AND c.status='RUNNING')
		AND EXISTS (SELECT 1 FROM scan_task_chunks c WHERE c.task_id=t.id AND c.status='PENDING')`)
	return err
}

func (s *PostgresRuntimeStore) TouchNode(ctx context.Context, id, kind, task string, engineStatus ...[]taskflow.EngineStatus) error {
	return s.TouchNodeState(ctx, id, kind, task, "", "ONLINE", engineStatus...)
}

func (s *PostgresRuntimeStore) TouchNodeState(ctx context.Context, id, kind, task, localRuleVersion, nodeStatus string, engineStatus ...[]taskflow.EngineStatus) error {
	if strings.TrimSpace(id) == "" || (kind != "worker" && kind != "updater") {
		return ErrInvalidTask
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO nodes(id,kind,host_id,token_hash,last_heartbeat)
		VALUES ($1,$2,$3,$4,CURRENT_TIMESTAMP)
		ON CONFLICT(id) DO UPDATE SET kind=EXCLUDED.kind,last_heartbeat=EXCLUDED.last_heartbeat`, id, kind, "server", "runtime:"+id)
	return err
}

func (s *PostgresRuntimeStore) ListNodes(ctx context.Context) ([]LocalNode, error) {
	page, err := s.ListNodesPage(ctx, NodeListQuery{Page: 1})
	if err != nil {
		return nil, err
	}
	return page.Items, nil
}

func (s *PostgresRuntimeStore) ListNodesPage(ctx context.Context, in NodeListQuery) (NodeListPage, error) {
	query, err := NormalizeNodeListQuery(in)
	if err != nil {
		return NodeListPage{}, err
	}
	var total int
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM nodes").Scan(&total); err != nil {
		return NodeListPage{}, err
	}
	args := []any{}
	querySQL := `SELECT id,kind,host_id,last_heartbeat FROM nodes ORDER BY id`
	if query.PageSize > 0 {
		querySQL += fmt.Sprintf(" LIMIT $1 OFFSET $2")
		args = append(args, query.PageSize, (query.Page-1)*query.PageSize)
	}
	rows, err := s.db.QueryContext(ctx, querySQL, args...)
	if err != nil {
		return NodeListPage{}, err
	}
	defer rows.Close()
	items := make([]LocalNode, 0)
	for rows.Next() {
		var item LocalNode
		if err := rows.Scan(&item.ID, &item.Kind, &item.HostID, &item.LastHeartbeat); err != nil {
			return NodeListPage{}, err
		}
		item.Status = "UNKNOWN"
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return NodeListPage{}, err
	}
	pageSize := query.PageSize
	if pageSize == 0 {
		pageSize = len(items)
		if pageSize == 0 {
			pageSize = DefaultSystemListPageSize
		}
	}
	return NodeListPage{Items: items, Total: total, Page: query.Page, PageSize: pageSize}, nil
}

func (s *PostgresRuntimeStore) postgresAudit(ctx context.Context, actor, action, objectType, objectID, detail string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := s.postgresAuditTx(ctx, tx, actor, action, objectType, objectID, detail); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *PostgresRuntimeStore) postgresAuditTx(ctx context.Context, tx *sql.Tx, actor, action, objectType, objectID, detail string) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO audit_logs(id,actor,action,object_type,object_id,detail,created_at)
		VALUES ($1,$2,$3,$4,$5,$6,CURRENT_TIMESTAMP)`, "audit-"+randomLocalID(), actor, action, objectType, objectID, detail)
	return err
}

// Keep the netip import tied to a direct validation path even when the
// compiler inlines the helper on a future Go release.
var _ = netip.Addr{}
