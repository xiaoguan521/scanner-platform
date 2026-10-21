package repo

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"scanner-platform/internal/assets"
	"scanner-platform/internal/inventory"
	"scanner-platform/internal/reporting"
	"scanner-platform/internal/taskflow"
)

// PostgresReportStore is the Server-owned report repository. It freezes a
// snapshot from PostgreSQL rows before enqueueing a job; workers only receive
// the node API work and never receive this database handle.
type PostgresReportStore struct {
	db  *sql.DB
	now func() time.Time
}

func NewPostgresReportStore(db *sql.DB) (*PostgresReportStore, error) {
	if db == nil {
		return nil, ErrPostgresDSNRequired
	}
	return &PostgresReportStore{db: db, now: time.Now}, nil
}

func (s *PostgresReportStore) currentTime() time.Time {
	if s != nil && s.now != nil {
		return s.now().UTC()
	}
	return time.Now().UTC()
}

func (s *PostgresReportStore) InitReports(ctx context.Context) error {
	if s == nil || s.db == nil {
		return ErrPostgresDSNRequired
	}
	template := reporting.DefaultTemplate()
	data, err := json.Marshal(template)
	if err != nil {
		return fmt.Errorf("encode postgres report template: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, `INSERT INTO report_templates(id,data)
		VALUES ($1,$2) ON CONFLICT(id) DO NOTHING`, template.ID, string(data)); err != nil {
		return fmt.Errorf("initialize postgres reports: %w", err)
	}
	return nil
}

func (s *PostgresReportStore) ListReportTemplates(ctx context.Context) ([]reporting.Template, error) {
	if s == nil || s.db == nil {
		return nil, ErrPostgresDSNRequired
	}
	rows, err := s.db.QueryContext(ctx, `SELECT data FROM report_templates ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("list postgres report templates: %w", err)
	}
	defer rows.Close()
	items := make([]reporting.Template, 0)
	for rows.Next() {
		var raw string
		var item reporting.Template
		if err := rows.Scan(&raw); err != nil {
			return nil, fmt.Errorf("scan postgres report template: %w", err)
		}
		if err := json.Unmarshal([]byte(raw), &item); err != nil {
			return nil, fmt.Errorf("decode postgres report template: %w", err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate postgres report templates: %w", err)
	}
	return items, nil
}

func (s *PostgresReportStore) GetReportTemplate(ctx context.Context, id string) (reporting.Template, error) {
	if s == nil || s.db == nil || strings.TrimSpace(id) == "" || len(id) > 100 {
		return reporting.Template{}, ErrReportNotFound
	}
	var raw string
	if err := s.db.QueryRowContext(ctx, `SELECT data FROM report_templates WHERE id=$1`, id).Scan(&raw); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return reporting.Template{}, ErrReportNotFound
		}
		return reporting.Template{}, fmt.Errorf("read postgres report template: %w", err)
	}
	var item reporting.Template
	if err := json.Unmarshal([]byte(raw), &item); err != nil {
		return reporting.Template{}, fmt.Errorf("decode postgres report template: %w", err)
	}
	return item, nil
}

func (s *PostgresReportStore) SaveReportTemplate(ctx context.Context, template reporting.Template, actor string) (reporting.Template, error) {
	if s == nil || s.db == nil || strings.TrimSpace(actor) == "" {
		return template, reporting.ErrInvalid
	}
	if err := reporting.ValidateTemplate(template); err != nil {
		return template, err
	}
	data, err := json.Marshal(template)
	if err != nil {
		return template, fmt.Errorf("encode postgres report template: %w", err)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return template, fmt.Errorf("begin postgres report template: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `INSERT INTO report_templates(id,data)
		VALUES ($1,$2) ON CONFLICT(id) DO UPDATE SET data=EXCLUDED.data`, template.ID, string(data)); err != nil {
		return template, fmt.Errorf("save postgres report template: %w", err)
	}
	if err := logPostgresReportTx(ctx, tx, actor, "save_report_template", "report_template", template.ID, "更新报告模板", s.currentTime()); err != nil {
		return template, err
	}
	if err := tx.Commit(); err != nil {
		return template, fmt.Errorf("commit postgres report template: %w", err)
	}
	return template, nil
}

func (s *PostgresReportStore) CreateReport(ctx context.Context, input reporting.Request, actor string) (reporting.Job, error) {
	var job reporting.Job
	if s == nil || s.db == nil || strings.TrimSpace(actor) == "" {
		return job, reporting.ErrInvalid
	}
	if input.TemplateID == "" {
		input.TemplateID = "default"
	}
	if err := reporting.ValidateRequest(input); err != nil {
		return job, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return job, fmt.Errorf("begin postgres report: %w", err)
	}
	defer tx.Rollback()
	var pending int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM report_jobs
		WHERE status IN ('QUEUED','GENERATING')`).Scan(&pending); err != nil {
		return job, fmt.Errorf("count postgres report queue: %w", err)
	}
	if pending >= 100 {
		return job, fmt.Errorf("%w: 报告队列已满，请等待当前任务完成", reporting.ErrInvalid)
	}
	snapshot, err := s.freezePostgresReport(ctx, tx, input)
	if err != nil {
		return job, err
	}
	snapshotData, err := json.Marshal(snapshot)
	if err != nil {
		return job, fmt.Errorf("encode postgres report snapshot: %w", err)
	}
	if len(snapshotData) > reporting.MaxSnapshotBytes {
		return job, fmt.Errorf("%w: 数据快照超过 32 MiB，请缩小范围", reporting.ErrInvalid)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO report_snapshots(id,schema_version,data)
		VALUES ($1,$2,$3) ON CONFLICT(id) DO NOTHING`, snapshot.ID, snapshot.SchemaVersion, string(snapshotData)); err != nil {
		return job, fmt.Errorf("save postgres report snapshot: %w", err)
	}
	job = reporting.Job{
		ID: "report-" + rand.Text(), Name: snapshot.Name, TemplateID: input.TemplateID,
		Format: input.Format, Scope: input.Scope, Status: "QUEUED", CreatedBy: actor,
		CreatedAt: snapshot.CreatedAt, SnapshotVersion: snapshot.SchemaVersion,
		SnapshotID: snapshot.ID, FileName: snapshot.Name + "." + input.Format,
	}
	jobData, err := json.Marshal(job)
	if err != nil {
		return job, fmt.Errorf("encode postgres report job: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO report_jobs(id,status,created_at,snapshot_id,data)
		VALUES ($1,$2,$3,$4,$5)`, job.ID, job.Status, job.CreatedAt.Format(time.RFC3339Nano), job.SnapshotID, string(jobData)); err != nil {
		return job, fmt.Errorf("save postgres report job: %w", err)
	}
	if err := logPostgresReportTx(ctx, tx, actor, "create_report", "report", job.ID, "已冻结数据快照并加入报告队列", s.currentTime()); err != nil {
		return job, err
	}
	if err := tx.Commit(); err != nil {
		return job, fmt.Errorf("commit postgres report: %w", err)
	}
	return job, nil
}

func (s *PostgresReportStore) GetReport(ctx context.Context, id string) (reporting.Job, error) {
	if s == nil || s.db == nil || strings.TrimSpace(id) == "" || len(id) > 256 {
		return reporting.Job{}, ErrReportNotFound
	}
	return readPostgresReport(s.db.QueryRowContext(ctx, `SELECT data,status,file_path
		FROM report_jobs WHERE id=$1`, id))
}

func (s *PostgresReportStore) ListReports(ctx context.Context) ([]reporting.Job, error) {
	page, err := s.ListReportsPage(ctx, ReportListQuery{Page: 1})
	if err != nil {
		return nil, err
	}
	return page.Items, nil
}

func (s *PostgresReportStore) ReportSnapshot(ctx context.Context, id string) (reporting.Snapshot, error) {
	if s == nil || s.db == nil || strings.TrimSpace(id) == "" || len(id) > 256 {
		return reporting.Snapshot{}, ErrReportNotFound
	}
	var raw string
	if err := s.db.QueryRowContext(ctx, `SELECT data FROM report_snapshots WHERE id=$1`, id).Scan(&raw); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return reporting.Snapshot{}, ErrReportNotFound
		}
		return reporting.Snapshot{}, fmt.Errorf("read postgres report snapshot: %w", err)
	}
	var snapshot reporting.Snapshot
	if err := json.Unmarshal([]byte(raw), &snapshot); err != nil {
		return reporting.Snapshot{}, fmt.Errorf("decode postgres report snapshot: %w", err)
	}
	return snapshot, nil
}

func (s *PostgresReportStore) RetryReport(ctx context.Context, id, actor string) (reporting.Job, error) {
	if s == nil || s.db == nil || strings.TrimSpace(actor) == "" {
		return reporting.Job{}, reporting.ErrInvalid
	}
	job, err := s.GetReport(ctx, id)
	if err != nil {
		return job, err
	}
	if job.Status != "FAILED" {
		return job, ErrReportConflict
	}
	job.Status, job.Progress, job.Error = "QUEUED", 0, ""
	job.FilePath, job.FileSize = "", 0
	data, err := json.Marshal(job)
	if err != nil {
		return job, fmt.Errorf("encode postgres retry report: %w", err)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return job, fmt.Errorf("begin postgres report retry: %w", err)
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE report_jobs SET status='QUEUED',data=$1,
		file_path='' WHERE id=$2 AND status='FAILED'`, string(data), id)
	if err != nil {
		return job, fmt.Errorf("retry postgres report: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil || changed != 1 {
		return job, ErrReportConflict
	}
	if err := logPostgresReportTx(ctx, tx, actor, "retry_report", "report", id, "使用原冻结数据快照重试", s.currentTime()); err != nil {
		return job, err
	}
	if err := tx.Commit(); err != nil {
		return job, fmt.Errorf("commit postgres report retry: %w", err)
	}
	return job, nil
}

func (s *PostgresReportStore) RecoverReports(ctx context.Context) error {
	if s == nil || s.db == nil {
		return ErrPostgresDSNRequired
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE report_jobs SET status='QUEUED'
		WHERE status='GENERATING'`); err != nil {
		return fmt.Errorf("recover postgres reports: %w", err)
	}
	return nil
}

func (s *PostgresReportStore) RunReports(ctx context.Context, directory string) error {
	if s == nil || s.db == nil {
		return ErrPostgresDSNRequired
	}
	if strings.TrimSpace(directory) == "" {
		return fmt.Errorf("report directory required")
	}
	dir, err := filepath.Abs(directory)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	if err := s.RecoverReports(ctx); err != nil {
		return err
	}
	timer := time.NewTicker(300 * time.Millisecond)
	defer timer.Stop()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		processed, err := s.ProcessNextReport(ctx, dir)
		if err != nil {
			return err
		}
		if processed {
			continue
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func (s *PostgresReportStore) ProcessNextReport(ctx context.Context, directory string) (bool, error) {
	if s == nil || s.db == nil || strings.TrimSpace(directory) == "" {
		return false, ErrPostgresDSNRequired
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("begin postgres report worker: %w", err)
	}
	defer tx.Rollback()
	job, err := readPostgresReport(tx.QueryRowContext(ctx, `SELECT data,status,file_path
		FROM report_jobs WHERE status='QUEUED' ORDER BY created_at,id
		LIMIT 1 FOR UPDATE SKIP LOCKED`))
	if errors.Is(err, ErrReportNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	job.Status, job.Progress = "GENERATING", 10
	job.Attempts++
	data, err := json.Marshal(job)
	if err != nil {
		return false, fmt.Errorf("encode postgres generating report: %w", err)
	}
	result, err := tx.ExecContext(ctx, `UPDATE report_jobs SET status='GENERATING',data=$1
		WHERE id=$2 AND status='QUEUED'`, string(data), job.ID)
	if err != nil {
		return false, fmt.Errorf("claim postgres report: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil || changed != 1 {
		return false, nil
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("commit postgres report claim: %w", err)
	}
	snapshot, runErr := s.ReportSnapshot(ctx, job.SnapshotID)
	var output string
	var size int64
	if runErr == nil {
		output, size, runErr = writeReportArtifact(ctx, directory, job, snapshot)
	}
	job.Progress, job.FileSize = 100, size
	job.Status = "READY"
	if runErr != nil {
		job.Status, job.Progress = "FAILED", 0
		job.Error = "报告生成失败，请重试或缩小范围后重新生成"
		if errors.Is(runErr, reporting.ErrTooLarge) {
			job.Error = reporting.ErrTooLarge.Error()
		}
		if snapshot.SchemaVersion != reporting.SchemaVersion {
			job.Error = "报告数据快照版本不受支持，请创建新报告"
		}
		output = ""
	}
	data, err = json.Marshal(job)
	if err != nil {
		return true, fmt.Errorf("encode postgres completed report: %w", err)
	}
	updateCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	if _, err := s.db.ExecContext(updateCtx, `UPDATE report_jobs SET status=$1,data=$2,
		file_path=$3 WHERE id=$4 AND status='GENERATING'`, job.Status, string(data), output, job.ID); err != nil {
		return true, fmt.Errorf("save postgres report result: %w", err)
	}
	return true, nil
}

func (s *PostgresReportStore) OpenReport(ctx context.Context, id string) (reporting.Job, *os.File, error) {
	job, err := s.GetReport(ctx, id)
	if err != nil {
		return job, nil, err
	}
	if job.Status != "READY" || job.FilePath == "" {
		return job, nil, ErrReportConflict
	}
	file, err := os.Open(job.FilePath)
	if err != nil {
		return job, nil, ErrReportNotFound
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() != job.FileSize {
		_ = file.Close()
		return job, nil, ErrReportNotFound
	}
	return job, file, nil
}

func (s *PostgresReportStore) CreateReportFormat(ctx context.Context, id, format, actor string) (reporting.Job, error) {
	if s == nil || s.db == nil || strings.TrimSpace(actor) == "" {
		return reporting.Job{}, reporting.ErrInvalid
	}
	if err := reporting.ValidateRequest(reporting.Request{Format: format}); err != nil {
		return reporting.Job{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return reporting.Job{}, fmt.Errorf("begin postgres report format: %w", err)
	}
	defer tx.Rollback()
	source, err := readPostgresReport(tx.QueryRowContext(ctx, `SELECT data,status,file_path
		FROM report_jobs WHERE id=$1`, id))
	if err != nil {
		return reporting.Job{}, err
	}
	var pending int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM report_jobs
		WHERE status IN ('QUEUED','GENERATING')`).Scan(&pending); err != nil {
		return reporting.Job{}, fmt.Errorf("count postgres report queue: %w", err)
	}
	if pending >= 100 {
		return reporting.Job{}, fmt.Errorf("%w: 报告队列已满，请等待当前任务完成", reporting.ErrInvalid)
	}
	now := s.currentTime()
	job := reporting.Job{ID: "report-" + rand.Text(), Name: source.Name,
		TemplateID: source.TemplateID, Format: format, Scope: source.Scope, Status: "QUEUED",
		CreatedBy: actor, CreatedAt: now, SnapshotVersion: source.SnapshotVersion,
		SnapshotID: source.SnapshotID, FileName: source.Name + "." + format}
	data, err := json.Marshal(job)
	if err != nil {
		return job, fmt.Errorf("encode postgres report format: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO report_jobs(id,status,created_at,snapshot_id,data)
		VALUES ($1,$2,$3,$4,$5)`, job.ID, job.Status, job.CreatedAt.Format(time.RFC3339Nano), job.SnapshotID, string(data)); err != nil {
		return job, fmt.Errorf("save postgres report format: %w", err)
	}
	if err := logPostgresReportTx(ctx, tx, actor, "export_report_format", "report", job.ID, "复用原报告冻结快照，来源报告 "+source.ID, now); err != nil {
		return job, err
	}
	if err := tx.Commit(); err != nil {
		return job, fmt.Errorf("commit postgres report format: %w", err)
	}
	return job, nil
}

func readPostgresReport(row rowScanner) (reporting.Job, error) {
	var job reporting.Job
	var raw, status, path string
	if err := row.Scan(&raw, &status, &path); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return job, ErrReportNotFound
		}
		return job, fmt.Errorf("read postgres report: %w", err)
	}
	if err := json.Unmarshal([]byte(raw), &job); err != nil {
		return job, fmt.Errorf("decode postgres report: %w", err)
	}
	job.Status, job.FilePath = status, path
	return job, nil
}

func logPostgresReportTx(ctx context.Context, tx *sql.Tx, actor, action, objectType, objectID, detail string, now time.Time) error {
	if strings.TrimSpace(actor) == "" || strings.TrimSpace(action) == "" || strings.TrimSpace(objectType) == "" || strings.TrimSpace(objectID) == "" {
		return reporting.ErrInvalid
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO audit_logs
		(id,actor,action,object_type,object_id,detail,created_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7)`, "audit-"+rand.Text(), actor, action, objectType, objectID, detail, now); err != nil {
		return fmt.Errorf("audit postgres report: %w", err)
	}
	return nil
}

func (s *PostgresReportStore) ListReportsPage(ctx context.Context, in ReportListQuery) (ReportListPage, error) {
	if s == nil || s.db == nil {
		return ReportListPage{}, ErrPostgresDSNRequired
	}
	query, err := NormalizeReportListQuery(in)
	if err != nil {
		return ReportListPage{}, err
	}
	where, args := postgresReportWhere(query)
	from := ` FROM report_jobs WHERE ` + where
	var total int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*)`+from, args...).Scan(&total); err != nil {
		return ReportListPage{}, fmt.Errorf("count postgres reports: %w", err)
	}
	sortExpr, direction := postgresReportSort(query.Sort)
	queryArgs := append([]any(nil), args...)
	selectSQL := `SELECT data,status,file_path` + from + ` ORDER BY ` + sortExpr + ` ` + direction + `,id ASC`
	if query.PageSize > 0 {
		selectSQL += fmt.Sprintf(" LIMIT $%d OFFSET $%d", len(queryArgs)+1, len(queryArgs)+2)
		queryArgs = append(queryArgs, query.PageSize, (query.Page-1)*query.PageSize)
	}
	rows, err := s.db.QueryContext(ctx, selectSQL, queryArgs...)
	if err != nil {
		return ReportListPage{}, fmt.Errorf("list postgres reports: %w", err)
	}
	defer rows.Close()
	items := make([]reporting.Job, 0)
	for rows.Next() {
		job, err := readPostgresReport(rows)
		if err != nil {
			return ReportListPage{}, err
		}
		items = append(items, job)
	}
	if err := rows.Err(); err != nil {
		return ReportListPage{}, fmt.Errorf("iterate postgres reports: %w", err)
	}
	pageSize := query.PageSize
	if pageSize == 0 {
		pageSize = len(items)
		if pageSize == 0 {
			pageSize = DefaultReportPageSize
		}
	}
	return ReportListPage{Items: items, Total: total, Page: query.Page, PageSize: pageSize}, nil
}

func postgresReportWhere(query ReportListQuery) (string, []any) {
	clauses := []string{"TRUE"}
	args := make([]any, 0, 6)
	add := func(fragment string, value any) {
		args = append(args, value)
		clauses = append(clauses, fmt.Sprintf(fragment, len(args)))
	}
	if query.Status != "" {
		add("status=$%d", query.Status)
	}
	if query.Format != "" {
		add("COALESCE(data::jsonb ->> 'format','')=$%d", query.Format)
	}
	if query.Search != "" {
		pattern := "%" + escapeFindingLike(query.Search) + "%"
		base := len(args)
		clauses = append(clauses, fmt.Sprintf(`(id ILIKE $%d ESCAPE '\' OR COALESCE(data::jsonb ->> 'name','') ILIKE $%d ESCAPE '\' OR COALESCE(data::jsonb ->> 'createdBy','') ILIKE $%d ESCAPE '\' OR COALESCE(data::jsonb ->> 'snapshotId','') ILIKE $%d ESCAPE '\')`, base+1, base+2, base+3, base+4))
		args = append(args, pattern, pattern, pattern, pattern)
	}
	return strings.Join(clauses, " AND "), args
}

func postgresReportSort(value string) (string, string) {
	direction := "ASC"
	if value == "" || strings.HasPrefix(value, "-") {
		direction = "DESC"
	}
	switch strings.TrimPrefix(strings.TrimPrefix(value, "+"), "-") {
	case "name":
		return `COALESCE(data::jsonb ->> 'name','')`, direction
	case "status":
		return "status", direction
	case "format":
		return `COALESCE(data::jsonb ->> 'format','')`, direction
	default:
		return "created_at", direction
	}
}

type postgresReportTask struct {
	task taskflow.Task
	item reporting.Task
}

func (s *PostgresReportStore) freezePostgresReport(ctx context.Context, tx *sql.Tx, input reporting.Request) (reporting.Snapshot, error) {
	var snapshot reporting.Snapshot
	templateRaw := ""
	if err := tx.QueryRowContext(ctx, `SELECT data FROM report_templates WHERE id=$1`, input.TemplateID).Scan(&templateRaw); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return snapshot, fmt.Errorf("%w: 报告模板不存在", reporting.ErrInvalid)
		}
		return snapshot, fmt.Errorf("read postgres report template: %w", err)
	}
	if err := json.Unmarshal([]byte(templateRaw), &snapshot.Template); err != nil {
		return snapshot, fmt.Errorf("decode postgres report template: %w", err)
	}
	if err := reporting.ValidateTemplate(snapshot.Template); err != nil {
		return snapshot, err
	}
	snapshot.Scope = input.Scope
	assetItems, err := loadPostgresReportAssets(ctx, tx)
	if err != nil {
		return snapshot, err
	}
	tasks, err := loadPostgresReportTasks(ctx, tx, input.Scope)
	if err != nil {
		return snapshot, err
	}
	if input.Scope.TaskID != "" && len(tasks) == 0 {
		return snapshot, fmt.Errorf("%w: 扫描任务不存在", reporting.ErrInvalid)
	}
	targetHosts := map[string]bool{}
	for _, task := range tasks {
		for _, chunk := range task.task.Chunks {
			for _, target := range chunk.Targets {
				targetHosts[reporting.TargetHost(target)] = true
			}
		}
	}
	selectedAssets := make([]assets.Asset, 0, len(assetItems))
	for _, asset := range assetItems {
		if input.Scope.AssetID != "" && asset.ID != input.Scope.AssetID {
			continue
		}
		if input.Scope.BusinessGroup != "" && asset.BusinessGroup != input.Scope.BusinessGroup {
			continue
		}
		if input.Scope.TaskID != "" {
			matched := false
			for _, task := range tasks {
				if task.task.AssetID == asset.ID {
					matched = true
					for _, chunk := range task.task.Chunks {
						if len(chunk.Targets) > 0 {
							asset.Address = reporting.TargetHost(chunk.Targets[0])
							break
						}
					}
				}
			}
			if !matched {
				matched = targetHosts[asset.Address] || targetHosts[asset.ResolvedIP]
			}
			if !matched {
				continue
			}
		}
		selectedAssets = append(selectedAssets, asset)
	}
	if input.Scope.AssetID != "" && len(selectedAssets) == 0 {
		return snapshot, fmt.Errorf("%w: 资产不在所选报告范围", reporting.ErrInvalid)
	}
	if input.Scope.TaskID != "" && len(selectedAssets) == 0 {
		return snapshot, fmt.Errorf("%w: 所选任务没有匹配当前资产或业务组的已登记目标", reporting.ErrInvalid)
	}
	for _, asset := range selectedAssets {
		var item reporting.Asset
		if err := convertReportValue(asset, &item); err != nil {
			return snapshot, fmt.Errorf("convert postgres report asset: %w", err)
		}
		snapshot.Assets = append(snapshot.Assets, item)
	}
	assetHosts := map[string]bool{}
	assetIDs := map[string]bool{}
	for _, asset := range snapshot.Assets {
		assetHosts[asset.Address] = true
	}
	for _, asset := range selectedAssets {
		assetIDs[asset.ID] = true
	}
	for _, task := range tasks {
		matched := input.Scope.AssetID == "" && input.Scope.BusinessGroup == ""
		if input.Scope.TaskID != "" {
			matched = true
		}
		if !matched {
			for _, chunk := range task.task.Chunks {
				for _, target := range chunk.Targets {
					if assetHosts[reporting.TargetHost(target)] {
						matched = true
					}
				}
			}
		}
		if matched {
			snapshot.Tasks = append(snapshot.Tasks, task.item)
		}
	}
	findings, err := loadPostgresReportFindings(ctx, tx, input.Scope, assetHosts, assetIDs)
	if err != nil {
		return snapshot, err
	}
	snapshot.Findings = findings
	snapshot.CreatedAt = s.currentTime()
	if input.Scope.TaskID != "" {
		snapshot.Notes = append(snapshot.Notes, "任务报告只使用本任务持久化观察记录；服务识别取本任务执行结果。资产归属和登记信息为生成报告时的快照。")
	}
	return reporting.Freeze(snapshot), nil
}

func loadPostgresReportAssets(ctx context.Context, q interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}) ([]assets.Asset, error) {
	rows, err := q.QueryContext(ctx, `SELECT a.id,a.kind,a.address,COALESCE(a.resolved_ip,''),
		a.business_group,a.owner,a.created_at,
		COALESCE(r.status,'UNCHECKED'),COALESCE(r.checked_at,'')
		FROM assets a LEFT JOIN asset_reachability r ON r.asset_id=a.id
		ORDER BY a.address,a.id`)
	if err != nil {
		return nil, fmt.Errorf("list postgres report assets: %w", err)
	}
	defer rows.Close()
	items := make([]assets.Asset, 0)
	indices := map[string]int{}
	for rows.Next() {
		var item assets.Asset
		var resolved sql.NullString
		var created time.Time
		if err := rows.Scan(&item.ID, &item.Kind, &item.Address, &resolved, &item.BusinessGroup,
			&item.Owner, &created, &item.ReachabilityStatus, &item.ReachabilityCheckedAt); err != nil {
			return nil, fmt.Errorf("scan postgres report asset: %w", err)
		}
		if resolved.Valid {
			item.ResolvedIP = resolved.String
		}
		item.CreatedAt = created.UTC().Format(time.RFC3339Nano)
		item.Ports, item.RequestedPorts, item.QuarantinedPorts, item.SkippedPorts = []assets.Port{}, []int{}, []int{}, []int{}
		item.Services, item.LoginEntries = []inventory.Service{}, []inventory.LoginEntry{}
		indices[item.ID] = len(items)
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate postgres report assets: %w", err)
	}
	if err := loadPostgresReportAssetRelations(ctx, q, items, indices); err != nil {
		return nil, err
	}
	return items, nil
}

func loadPostgresReportAssetRelations(ctx context.Context, q interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}, items []assets.Asset, indices map[string]int) error {
	rows, err := q.QueryContext(ctx, `SELECT asset_id,port FROM asset_port_requests ORDER BY asset_id,port`)
	if err != nil {
		return fmt.Errorf("list postgres report requested ports: %w", err)
	}
	for rows.Next() {
		var id string
		var port int
		if err := rows.Scan(&id, &port); err != nil {
			rows.Close()
			return err
		}
		if i, ok := indices[id]; ok {
			items[i].RequestedPorts = append(items[i].RequestedPorts, port)
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	rows, err = q.QueryContext(ctx, `SELECT p.asset_id,p.port,p.kind,p.source FROM asset_ports p
		WHERE NOT EXISTS (SELECT 1 FROM port_quarantine q
			WHERE q.asset_id=p.asset_id AND q.port=p.port AND q.status='ACTIVE')
		ORDER BY p.asset_id,p.port`)
	if err != nil {
		return fmt.Errorf("list postgres report ports: %w", err)
	}
	for rows.Next() {
		var id string
		var port assets.Port
		if err := rows.Scan(&id, &port.Port, &port.Kind, &port.Source); err != nil {
			rows.Close()
			return err
		}
		if i, ok := indices[id]; ok {
			items[i].Ports = append(items[i].Ports, port)
			if port.Kind == "EXCLUDED_PROXY" {
				items[i].SkippedPorts = append(items[i].SkippedPorts, port.Port)
			}
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	rows, err = q.QueryContext(ctx, `SELECT asset_id,port FROM port_quarantine
		WHERE status='ACTIVE' ORDER BY asset_id,port`)
	if err != nil {
		return fmt.Errorf("list postgres report quarantine: %w", err)
	}
	for rows.Next() {
		var id string
		var port int
		if err := rows.Scan(&id, &port); err != nil {
			rows.Close()
			return err
		}
		if i, ok := indices[id]; ok {
			items[i].QuarantinedPorts = append(items[i].QuarantinedPorts, port)
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	rows, err = q.QueryContext(ctx, `SELECT asset_id,data FROM asset_profiles ORDER BY asset_id`)
	if err != nil {
		return fmt.Errorf("list postgres report profiles: %w", err)
	}
	for rows.Next() {
		var id, raw string
		if err := rows.Scan(&id, &raw); err != nil {
			rows.Close()
			return err
		}
		if i, ok := indices[id]; ok {
			stable := items[i]
			if err := json.Unmarshal([]byte(raw), &items[i]); err != nil {
				rows.Close()
				return fmt.Errorf("decode postgres report profile: %w", err)
			}
			// Profile JSON is a bounded presentation record. Keep identity,
			// authorization and relation fields from normalized tables authoritative.
			items[i].ID, items[i].Kind, items[i].Address, items[i].ResolvedIP = stable.ID, stable.Kind, stable.Address, stable.ResolvedIP
			items[i].BusinessGroup, items[i].Owner, items[i].CreatedAt = stable.BusinessGroup, stable.Owner, stable.CreatedAt
			items[i].ReachabilityStatus, items[i].ReachabilityCheckedAt = stable.ReachabilityStatus, stable.ReachabilityCheckedAt
			items[i].Ports, items[i].RequestedPorts, items[i].QuarantinedPorts, items[i].SkippedPorts = stable.Ports, stable.RequestedPorts, stable.QuarantinedPorts, stable.SkippedPorts
			items[i].Services, items[i].LoginEntries = stable.Services, stable.LoginEntries
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	rows, err = q.QueryContext(ctx, `SELECT asset_id,data FROM asset_services ORDER BY asset_id,port`)
	if err != nil {
		return fmt.Errorf("list postgres report services: %w", err)
	}
	for rows.Next() {
		var id, raw string
		if err := rows.Scan(&id, &raw); err != nil {
			rows.Close()
			return err
		}
		if i, ok := indices[id]; ok {
			var service inventory.Service
			if err := json.Unmarshal([]byte(raw), &service); err != nil {
				rows.Close()
				return fmt.Errorf("decode postgres report service: %w", err)
			}
			for _, port := range items[i].SkippedPorts {
				service.Excluded = service.Excluded || port == service.Port
			}
			for _, port := range items[i].QuarantinedPorts {
				service.Quarantined = service.Quarantined || port == service.Port
			}
			items[i].Services = append(items[i].Services, service)
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	rows, err = q.QueryContext(ctx, `SELECT asset_id,data FROM asset_login_entries ORDER BY asset_id,entry_key`)
	if err != nil {
		return fmt.Errorf("list postgres report login entries: %w", err)
	}
	for rows.Next() {
		var id, raw string
		if err := rows.Scan(&id, &raw); err != nil {
			rows.Close()
			return err
		}
		if i, ok := indices[id]; ok {
			var entry inventory.LoginEntry
			if err := json.Unmarshal([]byte(raw), &entry); err != nil {
				rows.Close()
				return fmt.Errorf("decode postgres report login entry: %w", err)
			}
			items[i].LoginEntries = append(items[i].LoginEntries, entry)
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	return rows.Close()
}

func loadPostgresReportTasks(ctx context.Context, tx *sql.Tx, scope reporting.Scope) ([]postgresReportTask, error) {
	query := `SELECT t.id,t.scope_id,t.status,t.engines,t.hard_deadline,t.created_at,
		COALESCE(s.cidr_or_host,''),COALESCE(s.asset_id,''),COALESCE(p.data,'')
		FROM scan_tasks t JOIN authorized_scopes s ON s.id=t.scope_id
		LEFT JOIN scan_task_projections p ON p.task_id=t.id`
	args := []any{}
	if scope.TaskID != "" {
		query += ` WHERE t.id=$1`
		args = append(args, scope.TaskID)
	}
	query += ` ORDER BY t.created_at,t.id`
	rows, err := tx.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list postgres report tasks: %w", err)
	}
	type taskRow struct {
		id, scopeID, status, enginesRaw, scopeName, assetID, projection string
		deadline                                                        sql.NullTime
		created                                                         time.Time
	}
	rowsData := make([]taskRow, 0)
	for rows.Next() {
		var id, scopeID, status, enginesRaw, scopeName, assetID, projection string
		var deadline sql.NullTime
		var created time.Time
		if err := rows.Scan(&id, &scopeID, &status, &enginesRaw, &deadline, &created, &scopeName, &assetID, &projection); err != nil {
			rows.Close()
			return nil, fmt.Errorf("scan postgres report task: %w", err)
		}
		rowsData = append(rowsData, taskRow{id: id, scopeID: scopeID, status: status, enginesRaw: enginesRaw,
			scopeName: scopeName, assetID: assetID, projection: projection, deadline: deadline, created: created})
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, fmt.Errorf("iterate postgres report tasks: %w", err)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("close postgres report tasks: %w", err)
	}
	items := make([]postgresReportTask, 0, len(rowsData))
	for _, row := range rowsData {
		id, scopeID, status, enginesRaw := row.id, row.scopeID, row.status, row.enginesRaw
		scopeName, assetID, projection := row.scopeName, row.assetID, row.projection
		deadline, created := row.deadline, row.created
		var engines []string
		if err := json.Unmarshal([]byte(enginesRaw), &engines); err != nil {
			return nil, fmt.Errorf("decode postgres report engines: %w", err)
		}
		task := taskflow.Task{ID: id, ScopeID: scopeID, ScopeName: scopeName, AssetID: assetID,
			Status: status, Engines: engines, CreatedAt: created.UTC(), Synthetic: false}
		if deadline.Valid {
			task.HardDeadline = deadline.Time.UTC().Format(time.RFC3339Nano)
		}
		if projection != "" {
			if err := json.Unmarshal([]byte(projection), &task); err != nil {
				return nil, fmt.Errorf("decode postgres report task projection: %w", err)
			}
			task.ID, task.ScopeID, task.ScopeName, task.AssetID = id, scopeID, scopeName, assetID
			task.Status, task.Engines, task.CreatedAt = status, engines, created.UTC()
			if deadline.Valid {
				task.HardDeadline = deadline.Time.UTC().Format(time.RFC3339Nano)
			} else {
				task.HardDeadline = ""
			}
		}
		chunks, err := loadPostgresReportChunks(ctx, tx, id)
		if err != nil {
			return nil, err
		}
		task.Chunks = chunks
		task.TotalChunks, task.TargetCount = len(chunks), 0
		task.CompletedChunks = 0
		for _, chunk := range chunks {
			task.TargetCount += len(chunk.Targets)
			if chunk.Status == "COMPLETED" {
				task.CompletedChunks++
			}
			if task.RuleVersion == "" {
				task.RuleVersion = chunk.PinnedRuleVersion
			}
		}
		var item reporting.Task
		if err := convertReportValue(task, &item); err != nil {
			return nil, fmt.Errorf("convert postgres report task: %w", err)
		}
		if !reportDateMatches(item.CreatedAt, scope) {
			continue
		}
		items = append(items, postgresReportTask{task: task, item: item})
	}
	return items, nil
}

func loadPostgresReportChunks(ctx context.Context, tx *sql.Tx, taskID string) ([]taskflow.Chunk, error) {
	rows, err := tx.QueryContext(ctx, `SELECT id,task_id,status,COALESCE(worker_node_id,''),
		COALESCE(pinned_rule_version,''),targets,lease_expires_at,completed_fully,started_at,finished_at
		FROM scan_task_chunks WHERE task_id=$1 ORDER BY id`, taskID)
	if err != nil {
		return nil, fmt.Errorf("list postgres report chunks: %w", err)
	}
	defer rows.Close()
	items := make([]taskflow.Chunk, 0)
	for rows.Next() {
		var item taskflow.Chunk
		var targets string
		var lease, started, finished sql.NullTime
		if err := rows.Scan(&item.ID, &item.TaskID, &item.Status, &item.WorkerNodeID,
			&item.PinnedRuleVersion, &targets, &lease, &item.CompletedFully, &started, &finished); err != nil {
			return nil, fmt.Errorf("scan postgres report chunk: %w", err)
		}
		if err := json.Unmarshal([]byte(targets), &item.Targets); err != nil {
			return nil, fmt.Errorf("decode postgres report targets: %w", err)
		}
		if lease.Valid {
			value := lease.Time.UTC()
			item.LeaseExpiresAt = &value
		}
		if started.Valid {
			value := started.Time.UTC()
			item.StartedAt = &value
		}
		if finished.Valid {
			value := finished.Time.UTC()
			item.FinishedAt = &value
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate postgres report chunks: %w", err)
	}
	return items, nil
}

func loadPostgresReportFindings(ctx context.Context, tx *sql.Tx, scope reporting.Scope, assetHosts, assetIDs map[string]bool) ([]reporting.Finding, error) {
	query := `SELECT data FROM finding_projections`
	args := []any{}
	if scope.TaskID != "" {
		query = `SELECT data FROM task_finding_observations WHERE task_id=$1`
		args = append(args, scope.TaskID)
	}
	rows, err := tx.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list postgres report findings: %w", err)
	}
	defer rows.Close()
	items := make([]reporting.Finding, 0)
	totalBytes := 0
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return nil, fmt.Errorf("scan postgres report finding: %w", err)
		}
		totalBytes += len(raw)
		if totalBytes > reporting.MaxSnapshotBytes {
			return nil, fmt.Errorf("%w: 发现项快照超过 32 MiB，请缩小范围", reporting.ErrInvalid)
		}
		var finding taskflow.Finding
		if err := json.Unmarshal([]byte(raw), &finding); err != nil {
			return nil, fmt.Errorf("decode postgres report finding: %w", err)
		}
		if !reportDateMatches(finding.LastSeen, scope) {
			continue
		}
		if scope.AssetID != "" && finding.AssetID != scope.AssetID {
			continue
		}
		if scope.BusinessGroup != "" && finding.AssetID != "" && !assetIDs[finding.AssetID] {
			continue
		}
		if scope.AssetID != "" || scope.BusinessGroup != "" || scope.TaskID != "" {
			if finding.AssetID != "" {
				if !assetIDs[finding.AssetID] && !assetHosts[reporting.TargetHost(finding.Target)] {
					continue
				}
			} else if !assetHosts[reporting.TargetHost(finding.Target)] {
				continue
			}
		}
		var item reporting.Finding
		if err := convertReportValue(finding, &item); err != nil {
			return nil, fmt.Errorf("convert postgres report finding: %w", err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate postgres report findings: %w", err)
	}
	return items, nil
}
