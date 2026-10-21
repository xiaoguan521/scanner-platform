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
	"scanner-platform/internal/reporting"
)

var ErrReportNotFound = errors.New("report not found")
var ErrReportConflict = errors.New("report state conflict")

func (s *RuntimeStore) InitReports(ctx context.Context) error {
	for _, stmt := range []string{`CREATE TABLE IF NOT EXISTS report_templates(id TEXT PRIMARY KEY,data TEXT NOT NULL)`, `CREATE TABLE IF NOT EXISTS report_snapshots(id TEXT PRIMARY KEY,schema_version INTEGER NOT NULL,data TEXT NOT NULL)`, `CREATE TABLE IF NOT EXISTS report_jobs(id TEXT PRIMARY KEY,status TEXT NOT NULL,created_at TEXT NOT NULL,snapshot_id TEXT NOT NULL REFERENCES report_snapshots(id),data TEXT NOT NULL,file_path TEXT NOT NULL DEFAULT '')`, `CREATE INDEX IF NOT EXISTS report_job_queue ON report_jobs(status,created_at,id)`} {
		if _, err := s.db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("initialize reports: %w", err)
		}
	}
	t := reporting.DefaultTemplate()
	data, _ := json.Marshal(t)
	_, err := s.db.ExecContext(ctx, `INSERT INTO report_templates(id,data) VALUES (?,?) ON CONFLICT(id) DO NOTHING`, t.ID, string(data))
	return err
}
func (s *RuntimeStore) ListReportTemplates(ctx context.Context) ([]reporting.Template, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT data FROM report_templates ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []reporting.Template{}
	for rows.Next() {
		var data string
		var item reporting.Template
		if err := rows.Scan(&data); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(data), &item); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}
func (s *RuntimeStore) GetReportTemplate(ctx context.Context, id string) (reporting.Template, error) {
	var data string
	var t reporting.Template
	err := s.db.QueryRowContext(ctx, `SELECT data FROM report_templates WHERE id=?`, id).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return t, ErrReportNotFound
	}
	if err != nil {
		return t, err
	}
	err = json.Unmarshal([]byte(data), &t)
	return t, err
}
func (s *RuntimeStore) SaveReportTemplate(ctx context.Context, t reporting.Template, actor string) (reporting.Template, error) {
	if err := reporting.ValidateTemplate(t); err != nil {
		return t, err
	}
	data, err := json.Marshal(t)
	if err != nil {
		return t, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return t, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `INSERT INTO report_templates(id,data) VALUES (?,?) ON CONFLICT(id) DO UPDATE SET data=excluded.data`, t.ID, string(data)); err != nil {
		return t, err
	}
	if err = logLocal(ctx, tx, actor, "save_report_template", "report_template", t.ID, "更新报告模板"); err != nil {
		return t, err
	}
	return t, tx.Commit()
}
func convertReportValue(src, dst any) error {
	raw, err := json.Marshal(src)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, dst)
}
func reportDateMatches(value time.Time, scope reporting.Scope) bool {
	if scope.From != "" {
		from, _ := time.Parse(time.RFC3339Nano, scope.From)
		if value.Before(from) {
			return false
		}
	}
	if scope.To != "" {
		to, _ := time.Parse(time.RFC3339Nano, scope.To)
		if value.After(to) {
			return false
		}
	}
	return true
}
func (s *RuntimeStore) CreateReport(ctx context.Context, input reporting.Request, actor string) (reporting.Job, error) {
	var job reporting.Job
	if input.TemplateID == "" {
		input.TemplateID = "default"
	}
	if err := reporting.ValidateRequest(input); err != nil {
		return job, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return job, err
	}
	defer tx.Rollback()
	var pending int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM report_jobs WHERE status IN ('QUEUED','GENERATING')`).Scan(&pending); err != nil {
		return job, err
	}
	if pending >= 100 {
		return job, fmt.Errorf("%w: 报告队列已满，请等待当前任务完成", reporting.ErrInvalid)
	}
	snap, err := s.freezeReport(ctx, tx, input)
	if err != nil {
		return job, err
	}
	data, err := json.Marshal(snap)
	if err != nil {
		return job, err
	}
	if len(data) > reporting.MaxSnapshotBytes {
		return job, fmt.Errorf("%w: 数据快照超过 32 MiB，请缩小范围", reporting.ErrInvalid)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO report_snapshots(id,schema_version,data) VALUES (?,?,?) ON CONFLICT(id) DO NOTHING`, snap.ID, snap.SchemaVersion, string(data)); err != nil {
		return job, err
	}
	job = reporting.Job{ID: "report-" + rand.Text(), Name: snap.Name, TemplateID: input.TemplateID, Format: input.Format, Scope: input.Scope, Status: "QUEUED", CreatedBy: actor, CreatedAt: snap.CreatedAt, SnapshotVersion: snap.SchemaVersion, SnapshotID: snap.ID, FileName: snap.Name + "." + input.Format}
	encoded, _ := json.Marshal(job)
	if _, err := tx.ExecContext(ctx, `INSERT INTO report_jobs(id,status,created_at,snapshot_id,data) VALUES (?,?,?,?,?)`, job.ID, job.Status, job.CreatedAt.Format(time.RFC3339Nano), snap.ID, string(encoded)); err != nil {
		return job, err
	}
	if err := logLocal(ctx, tx, actor, "create_report", "report", job.ID, "已冻结数据快照并加入报告队列"); err != nil {
		return job, err
	}
	return job, tx.Commit()
}
func (s *RuntimeStore) freezeReport(ctx context.Context, tx *sql.Tx, input reporting.Request) (reporting.Snapshot, error) {
	snap := reporting.Snapshot{SchemaVersion: reporting.SchemaVersion, CreatedAt: time.Now().UTC(), Scope: input.Scope, Assets: []reporting.Asset{}, Tasks: []reporting.Task{}, Findings: []reporting.Finding{}}
	var templateData string
	if err := tx.QueryRowContext(ctx, `SELECT data FROM report_templates WHERE id=?`, input.TemplateID).Scan(&templateData); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return snap, fmt.Errorf("%w: 报告模板不存在", reporting.ErrInvalid)
		}
		return snap, err
	}
	if err := json.Unmarshal([]byte(templateData), &snap.Template); err != nil {
		return snap, err
	}
	if err := reporting.ValidateTemplate(snap.Template); err != nil {
		return snap, err
	}
	assetItems, err := assets.ListSnapshot(ctx, tx)
	if err != nil {
		return snap, err
	}
	allAssets := []reporting.Asset{}
	if err := convertReportValue(assetItems, &allAssets); err != nil {
		return snap, err
	}
	taskQuery := `SELECT ` + taskColumns + ` FROM scan_tasks`
	args := []any{}
	if input.Scope.TaskID != "" {
		taskQuery += ` WHERE id=?`
		args = append(args, input.Scope.TaskID)
	}
	taskQuery += ` ORDER BY created_at,id`
	rows, err := tx.QueryContext(ctx, taskQuery, args...)
	if err != nil {
		return snap, err
	}
	tasks := []reporting.Task{}
	for rows.Next() {
		task, err := readRuntimeTask(rows)
		if err != nil {
			rows.Close()
			return snap, err
		}
		var item reporting.Task
		if err := convertReportValue(task, &item); err != nil {
			rows.Close()
			return snap, err
		}
		if input.Scope.TaskID != "" || reportDateMatches(item.CreatedAt, input.Scope) {
			tasks = append(tasks, item)
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return snap, err
	}
	if input.Scope.TaskID != "" && len(tasks) == 0 {
		return snap, fmt.Errorf("%w: 扫描任务不存在", reporting.ErrInvalid)
	}
	targetHosts := map[string]bool{}
	for _, task := range tasks {
		for _, chunk := range task.Chunks {
			for _, target := range chunk.Targets {
				targetHosts[reporting.TargetHost(target)] = true
			}
		}
	}
	assetHosts := map[string]bool{}
	for _, a := range allAssets {
		if input.Scope.AssetID != "" && a.ID != input.Scope.AssetID || input.Scope.BusinessGroup != "" && a.BusinessGroup != input.Scope.BusinessGroup {
			continue
		}
		if input.Scope.TaskID != "" && !targetHosts[a.Address] {
			matched := false
			for _, task := range tasks {
				if task.AssetID == a.ID {
					for _, chunk := range task.Chunks {
						if len(chunk.Targets) > 0 {
							a.Address = reporting.TargetHost(chunk.Targets[0])
							matched = true
							break
						}
					}
				}
			}
			if !matched {
				continue
			}
		}
		if input.Scope.TaskID != "" {
			a.Services = []reporting.Service{}
			a.Ports = nil
			a.SkippedPorts = nil
			a.QuarantinedPorts = nil
			a.ReachabilityStatus = ""
			a.ReachabilityCheckedAt = ""
			a.Alive = nil
			a.LastAliveAt = ""
			a.LoginEntries = []reporting.LoginEntry{}
			for _, task := range tasks {
				if task.AssetID == a.ID || targetHosts[a.Address] {
					a.Services = append(a.Services, task.ServiceResults...)
					a.OSName = task.AssetProfile.OSName
					a.OSFamily = task.AssetProfile.OSFamily
					a.DeviceType = task.AssetProfile.DeviceType
					a.DeviceSubtype = task.AssetProfile.DeviceSubtype
					a.Vendor = task.AssetProfile.Vendor
					a.Model = task.AssetProfile.Model
					a.RuntimeServices = task.AssetProfile.RuntimeServices
				}
			}
		}
		snap.Assets = append(snap.Assets, a)
		assetHosts[a.Address] = true
	}
	if input.Scope.AssetID != "" && len(snap.Assets) == 0 {
		return snap, fmt.Errorf("%w: 资产不在所选报告范围", reporting.ErrInvalid)
	}
	if input.Scope.TaskID != "" && len(snap.Assets) == 0 {
		return snap, fmt.Errorf("%w: 所选任务没有匹配当前资产或业务组的已登记目标", reporting.ErrInvalid)
	}
	for _, task := range tasks {
		matched := input.Scope.AssetID == "" && input.Scope.BusinessGroup == ""
		for _, chunk := range task.Chunks {
			for _, target := range chunk.Targets {
				if assetHosts[reporting.TargetHost(target)] {
					matched = true
				}
			}
		}
		if matched {
			snap.Tasks = append(snap.Tasks, task)
		}
	}
	findingsQuery := `SELECT data FROM security_findings`
	args = nil
	if input.Scope.TaskID != "" {
		findingsQuery = `SELECT data FROM task_finding_observations WHERE task_id=?`
		args = append(args, input.Scope.TaskID)
	}
	rows, err = tx.QueryContext(ctx, findingsQuery, args...)
	if err != nil {
		return snap, err
	}
	totalFindingBytes := 0
	for rows.Next() {
		var data string
		var f reporting.Finding
		if err := rows.Scan(&data); err != nil {
			rows.Close()
			return snap, err
		}
		totalFindingBytes += len(data)
		if totalFindingBytes > reporting.MaxSnapshotBytes {
			rows.Close()
			return snap, fmt.Errorf("%w: 发现项快照超过 32 MiB，请缩小范围", reporting.ErrInvalid)
		}
		if err := json.Unmarshal([]byte(data), &f); err != nil {
			rows.Close()
			return snap, err
		}
		if !reportDateMatches(f.LastSeen, input.Scope) {
			continue
		}
		host := reporting.TargetHost(f.Target)
		if input.Scope.AssetID != "" || input.Scope.BusinessGroup != "" || input.Scope.TaskID != "" {
			if !assetHosts[host] {
				continue
			}
		}
		snap.Findings = append(snap.Findings, f)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return snap, err
	}
	if input.Scope.TaskID != "" {
		snap.Notes = append(snap.Notes, "任务报告只使用本任务持久化观察记录；服务识别取本任务执行结果。资产归属和登记信息为生成报告时的快照。")
	}
	return reporting.Freeze(snap), nil
}
func readReport(row rowScanner) (reporting.Job, error) {
	var job reporting.Job
	var data, status, path string
	if err := row.Scan(&data, &status, &path); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return job, ErrReportNotFound
		}
		return job, err
	}
	if err := json.Unmarshal([]byte(data), &job); err != nil {
		return job, err
	}
	job.Status = status
	job.FilePath = path
	return job, nil
}
func (s *RuntimeStore) GetReport(ctx context.Context, id string) (reporting.Job, error) {
	return readReport(s.db.QueryRowContext(ctx, `SELECT data,status,file_path FROM report_jobs WHERE id=?`, id))
}
func (s *RuntimeStore) ListReports(ctx context.Context) ([]reporting.Job, error) {
	page, err := s.ListReportsPage(ctx, ReportListQuery{Page: 1})
	if err != nil {
		return nil, err
	}
	return page.Items, nil
}
func (s *RuntimeStore) ReportSnapshot(ctx context.Context, id string) (reporting.Snapshot, error) {
	var snap reporting.Snapshot
	var data string
	err := s.db.QueryRowContext(ctx, `SELECT data FROM report_snapshots WHERE id=?`, id).Scan(&data)
	if err != nil {
		return snap, err
	}
	err = json.Unmarshal([]byte(data), &snap)
	return snap, err
}
func (s *RuntimeStore) RetryReport(ctx context.Context, id, actor string) (reporting.Job, error) {
	job, err := s.GetReport(ctx, id)
	if err != nil {
		return job, err
	}
	if job.Status != "FAILED" {
		return job, ErrReportConflict
	}
	job.Status = "QUEUED"
	job.Progress = 0
	job.Error = ""
	job.FilePath = ""
	job.FileSize = 0
	data, _ := json.Marshal(job)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return job, err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE report_jobs SET status='QUEUED',data=?,file_path='' WHERE id=? AND status='FAILED'`, string(data), id)
	if err != nil {
		return job, err
	}
	n, _ := result.RowsAffected()
	if n != 1 {
		return job, ErrReportConflict
	}
	if err := logLocal(ctx, tx, actor, "retry_report", "report", id, "使用原冻结数据快照重试"); err != nil {
		return job, err
	}
	return job, tx.Commit()
}

// RecoverReports requeues interrupted generation. Call once before starting the dispatcher.
func (s *RuntimeStore) RecoverReports(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `UPDATE report_jobs SET status='QUEUED' WHERE status='GENERATING'`)
	return err
}

// RunReports is a single bounded dispatcher owned by Server; it never scans targets.
func (s *RuntimeStore) RunReports(ctx context.Context, directory string) error {
	if directory == "" {
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

// ProcessNextReport is also exposed for deterministic offline acceptance tests.
func (s *RuntimeStore) ProcessNextReport(ctx context.Context, directory string) (bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	job, err := readReport(tx.QueryRowContext(ctx, `SELECT data,status,file_path FROM report_jobs WHERE status='QUEUED' ORDER BY created_at,id LIMIT 1`))
	if errors.Is(err, ErrReportNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	job.Status = "GENERATING"
	job.Progress = 10
	job.Attempts++
	data, _ := json.Marshal(job)
	result, err := tx.ExecContext(ctx, `UPDATE report_jobs SET status='GENERATING',data=? WHERE id=? AND status='QUEUED'`, string(data), job.ID)
	if err != nil {
		return false, err
	}
	n, _ := result.RowsAffected()
	if n != 1 {
		return false, nil
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	snap, runErr := s.ReportSnapshot(ctx, job.SnapshotID)
	var output string
	var size int64
	if runErr == nil {
		output, size, runErr = writeReportArtifact(ctx, directory, job, snap)
	}
	job.Progress = 100
	job.Status = "READY"
	if runErr != nil {
		job.Status = "FAILED"
		job.Progress = 0
		job.Error = "报告生成失败，请重试或缩小范围后重新生成"
		if errors.Is(runErr, reporting.ErrTooLarge) {
			job.Error = reporting.ErrTooLarge.Error()
		}
		if snap.SchemaVersion != reporting.SchemaVersion {
			job.Error = "报告数据快照版本不受支持，请创建新报告"
		}
		output = ""
	}
	job.FileSize = size
	data, _ = json.Marshal(job)
	updateCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	_, err = s.db.ExecContext(updateCtx, `UPDATE report_jobs SET status=?,data=?,file_path=? WHERE id=? AND status='GENERATING'`, job.Status, string(data), output, job.ID)
	return true, err
}
func writeReportArtifact(ctx context.Context, dir string, job reporting.Job, snap reporting.Snapshot) (string, int64, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", 0, err
	}
	file, err := os.CreateTemp(dir, ".report-*.tmp")
	if err != nil {
		return "", 0, err
	}
	tmp := file.Name()
	defer os.Remove(tmp)
	if err := file.Chmod(0600); err != nil {
		file.Close()
		return "", 0, err
	}
	err = reporting.Render(ctx, file, snap, job.Format)
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return "", 0, err
	}
	if strings.ContainsAny(job.ID, "/\\") || !strings.HasPrefix(job.ID, "report-") {
		return "", 0, reporting.ErrInvalid
	}
	path := filepath.Join(dir, job.ID+"."+job.Format)
	// An interrupted GENERATING job can leave a completed orphan artifact. The
	// dispatcher owns this job's path; remove only its regular orphan so Windows
	// can rename the regenerated file without requiring overwrite semantics.
	if info, statErr := os.Lstat(path); statErr == nil {
		if !info.Mode().IsRegular() {
			return "", 0, fmt.Errorf("report artifact destination is not a regular file")
		}
		if err := os.Remove(path); err != nil {
			return "", 0, err
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return "", 0, statErr
	}
	if err := os.Rename(tmp, path); err != nil {
		return "", 0, err
	}
	info, err := os.Stat(path)
	if err != nil {
		return "", 0, err
	}
	return path, info.Size(), nil
}
func (s *RuntimeStore) OpenReport(ctx context.Context, id string) (reporting.Job, *os.File, error) {
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
		file.Close()
		return job, nil, ErrReportNotFound
	}
	return job, file, nil
}

// CreateReportFormat enqueues another representation of the original immutable
// snapshot. Asset, finding and template changes after creation are not re-read.
func (s *RuntimeStore) CreateReportFormat(ctx context.Context, id, format, actor string) (reporting.Job, error) {
	var job reporting.Job
	if err := reporting.ValidateRequest(reporting.Request{Format: format}); err != nil {
		return job, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return job, err
	}
	defer tx.Rollback()
	source, err := readReport(tx.QueryRowContext(ctx, `SELECT data,status,file_path FROM report_jobs WHERE id=?`, id))
	if err != nil {
		return job, err
	}
	var pending int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM report_jobs WHERE status IN ('QUEUED','GENERATING')`).Scan(&pending); err != nil {
		return job, err
	}
	if pending >= 100 {
		return job, fmt.Errorf("%w: 报告队列已满，请等待当前任务完成", reporting.ErrInvalid)
	}
	job = reporting.Job{ID: "report-" + rand.Text(), Name: source.Name, TemplateID: source.TemplateID, Format: format, Scope: source.Scope, Status: "QUEUED", CreatedBy: actor, CreatedAt: time.Now().UTC(), SnapshotVersion: source.SnapshotVersion, SnapshotID: source.SnapshotID, FileName: source.Name + "." + format}
	data, err := json.Marshal(job)
	if err != nil {
		return job, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO report_jobs(id,status,created_at,snapshot_id,data) VALUES (?,?,?,?,?)`, job.ID, job.Status, job.CreatedAt.Format(time.RFC3339Nano), job.SnapshotID, string(data)); err != nil {
		return job, err
	}
	if err := logLocal(ctx, tx, actor, "export_report_format", "report", job.ID, "复用原报告冻结快照，来源报告 "+source.ID); err != nil {
		return job, err
	}
	return job, tx.Commit()
}
