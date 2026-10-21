package repo

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"scanner-platform/internal/rules"
)

func validatePostgresRuleBundles(bundles []rules.Bundle) error {
	if len(bundles) > 1000 {
		return ErrInvalidTask
	}
	current := 0
	for _, bundle := range bundles {
		if !rules.ValidateVersion(bundle.Version) || strings.TrimSpace(bundle.Channel) == "" || strings.TrimSpace(bundle.ManifestSHA256) == "" {
			return ErrInvalidTask
		}
		decodedHash, err := hex.DecodeString(bundle.ManifestSHA256)
		if err != nil || len(decodedHash) != 32 {
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
	return nil
}

func syncPostgresRuleCatalogTx(ctx context.Context, tx *sql.Tx, bundles []rules.Bundle) error {
	if err := validatePostgresRuleBundles(bundles); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM rule_bundles"); err != nil {
		return fmt.Errorf("clear postgres rule catalog: %w", err)
	}
	for _, bundle := range bundles {
		engines, err := json.Marshal(bundle.Engines)
		if err != nil {
			return fmt.Errorf("encode postgres rule engines: %w", err)
		}
		publishedAt, err := time.Parse(time.RFC3339Nano, bundle.PublishedAt)
		if err != nil {
			return ErrInvalidTask
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO rule_bundles
			(version,channel,manifest_sha256,published_at,engines,is_current,is_backup,in_use_by_tasks,integrity_verified,signature_verified,engine_validated)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, bundle.Version, bundle.Channel, bundle.ManifestSHA256, publishedAt.UTC(), string(engines), bundle.IsCurrent, bundle.IsBackup, bundle.InUseByTasks, bundle.IntegrityVerified, bundle.SignatureVerified, bundle.EngineValidated); err != nil {
			return fmt.Errorf("insert postgres rule bundle: %w", err)
		}
	}
	return nil
}

func (s *PostgresRuntimeStore) QueueRuleJob(ctx context.Context, job rules.Job, actor string) (rules.Job, error) {
	if strings.TrimSpace(actor) == "" {
		return job, ErrInvalidTask
	}
	switch job.Kind {
	case "IMPORT":
		if len(job.Bundle) == 0 || len(job.Bundle) > rules.MaxArchive {
			return job, ErrInvalidTask
		}
	case "FETCH":
		if err := rules.ValidateSource(job.URL, job.ExpectedSHA256); err != nil {
			return job, ErrInvalidTask
		}
	case "ACTIVATE":
		if !rules.ValidateVersion(job.Version) {
			return job, ErrInvalidTask
		}
	default:
		return job, ErrInvalidTask
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return job, fmt.Errorf("begin postgres rule job: %w", err)
	}
	defer tx.Rollback()
	var pending int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM rule_jobs WHERE status IN ('PENDING','RUNNING')").Scan(&pending); err != nil {
		return job, fmt.Errorf("count postgres rule jobs: %w", err)
	}
	if pending >= 10 {
		return job, ErrTaskConflict
	}
	bundle := append([]byte(nil), job.Bundle...)
	job.ID = "rules-" + randomLocalID()
	job.Status = "PENDING"
	job.CreatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	job.CompletedAt = ""
	job.Message = ""
	job.NodeID = ""
	job.Bundle = nil
	data, err := json.Marshal(job)
	if err != nil {
		return job, fmt.Errorf("encode postgres rule job: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO rule_jobs(id,status,data,bundle,created_at) VALUES ($1,$2,$3,$4,$5)`, job.ID, job.Status, string(data), bundle, job.CreatedAt); err != nil {
		return job, fmt.Errorf("insert postgres rule job: %w", err)
	}
	if err := s.postgresAuditTx(ctx, tx, actor, "queue_rule_"+job.Kind, "rule_job", job.ID, job.Version); err != nil {
		return job, err
	}
	if err := tx.Commit(); err != nil {
		return job, fmt.Errorf("commit postgres rule job: %w", err)
	}
	return job, nil
}

func (s *PostgresRuntimeStore) ClaimRuleJob(ctx context.Context, nodeID string) (*rules.Job, error) {
	if strings.TrimSpace(nodeID) == "" || len(nodeID) > 128 {
		return nil, ErrInvalidTask
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin postgres rule claim: %w", err)
	}
	defer tx.Rollback()
	var id, data, status string
	var bundle []byte
	err = tx.QueryRowContext(ctx, `SELECT id,data,status,bundle FROM rule_jobs
		WHERE status='PENDING' ORDER BY created_at,id LIMIT 1 FOR UPDATE SKIP LOCKED`).Scan(&id, &data, &status, &bundle)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("select postgres rule job: %w", err)
	}
	var job rules.Job
	if err := json.Unmarshal([]byte(data), &job); err != nil {
		return nil, fmt.Errorf("decode postgres rule job: %w", err)
	}
	job.ID = id
	job.NodeID = nodeID
	job.Status = "RUNNING"
	job.Bundle = bundle
	encodedJob := job
	encodedJob.Bundle = nil
	encoded, err := json.Marshal(encodedJob)
	if err != nil {
		return nil, fmt.Errorf("encode claimed postgres rule job: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE rule_jobs SET status='RUNNING',data=$1 WHERE id=$2 AND status='PENDING'`, string(encoded), id); err != nil {
		return nil, fmt.Errorf("claim postgres rule job: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit postgres rule claim: %w", err)
	}
	return &job, nil
}

func (s *PostgresRuntimeStore) ReportRuleJob(ctx context.Context, report rules.Report) error {
	if strings.TrimSpace(report.JobID) == "" || strings.TrimSpace(report.NodeID) == "" || (report.Status != "COMPLETED" && report.Status != "FAILED") || len(report.Message) > 500 {
		return ErrInvalidTask
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin postgres rule report: %w", err)
	}
	defer tx.Rollback()
	var data, status string
	if err := tx.QueryRowContext(ctx, `SELECT data,status FROM rule_jobs WHERE id=$1 FOR UPDATE`, report.JobID).Scan(&data, &status); errors.Is(err, sql.ErrNoRows) {
		return ErrTaskConflict
	} else if err != nil {
		return fmt.Errorf("read postgres rule job: %w", err)
	}
	var job rules.Job
	if err := json.Unmarshal([]byte(data), &job); err != nil {
		return fmt.Errorf("decode postgres rule job report: %w", err)
	}
	if job.NodeID != report.NodeID {
		return ErrTaskConflict
	}
	if status == "COMPLETED" || status == "FAILED" {
		return nil
	}
	if status != "RUNNING" {
		return ErrTaskConflict
	}
	job.Status = report.Status
	job.Message = report.Message
	job.Version = report.Version
	job.CompletedAt = time.Now().UTC().Format(time.RFC3339Nano)
	job.Bundle = nil
	encoded, err := json.Marshal(job)
	if err != nil {
		return fmt.Errorf("encode postgres rule report: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE rule_jobs SET status=$1,data=$2,bundle=NULL WHERE id=$3`, job.Status, string(encoded), job.ID); err != nil {
		return fmt.Errorf("update postgres rule job: %w", err)
	}
	if report.Bundles != nil {
		if err := syncPostgresRuleCatalogTx(ctx, tx, report.Bundles); err != nil {
			return err
		}
	}
	if err := s.postgresAuditTx(ctx, tx, report.NodeID, "rule_job_"+job.Status, "rule_job", job.ID, job.Message); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *PostgresRuntimeStore) ListRuleJobs(ctx context.Context) ([]rules.Job, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT data,status FROM rule_jobs ORDER BY created_at DESC,id LIMIT 100")
	if err != nil {
		return nil, fmt.Errorf("list postgres rule jobs: %w", err)
	}
	defer rows.Close()
	out := make([]rules.Job, 0)
	for rows.Next() {
		var data, status string
		var job rules.Job
		if err := rows.Scan(&data, &status); err != nil {
			return nil, fmt.Errorf("scan postgres rule job: %w", err)
		}
		if err := json.Unmarshal([]byte(data), &job); err != nil {
			return nil, fmt.Errorf("decode postgres rule job: %w", err)
		}
		job.Status = status
		out = append(out, job)
	}
	return out, rows.Err()
}

func (s *PostgresRuntimeStore) ListRuleJobsPage(ctx context.Context, in RuleJobListQuery) (RuleJobListPage, error) {
	query, err := NormalizeRuleJobListQuery(in)
	if err != nil {
		return RuleJobListPage{}, err
	}
	where := []string{"TRUE"}
	args := make([]any, 0, 8)
	add := func(value any) string {
		args = append(args, value)
		return fmt.Sprintf("$%d", len(args))
	}
	if query.Status != "" {
		where = append(where, "status="+add(query.Status))
	}
	if query.Kind != "" {
		where = append(where, "COALESCE(data::jsonb->>'kind','')="+add(query.Kind))
	}
	if query.Search != "" {
		pattern := "%" + escapeTaskLike(query.Search) + "%"
		placeholder := add(pattern)
		where = append(where, "(id ILIKE "+placeholder+" ESCAPE '\\' OR COALESCE(data::jsonb->>'kind','') ILIKE "+placeholder+" ESCAPE '\\' OR COALESCE(data::jsonb->>'version','') ILIKE "+placeholder+" ESCAPE '\\' OR COALESCE(data::jsonb->>'message','') ILIKE "+placeholder+" ESCAPE '\\')")
	}
	whereSQL := strings.Join(where, " AND ")
	var total int
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM rule_jobs WHERE "+whereSQL, args...).Scan(&total); err != nil {
		return RuleJobListPage{}, fmt.Errorf("count postgres rule jobs: %w", err)
	}
	sortColumn := "created_at"
	switch strings.TrimPrefix(query.Sort, "-") {
	case "status":
		sortColumn = "status"
	case "kind":
		sortColumn = "COALESCE(data::jsonb->>'kind','')"
	case "version":
		sortColumn = "COALESCE(data::jsonb->>'version','')"
	}
	direction := "DESC"
	if query.Sort != "" && !strings.HasPrefix(query.Sort, "-") {
		direction = "ASC"
	}
	statement := "SELECT data,status FROM rule_jobs WHERE " + whereSQL + " ORDER BY " + sortColumn + " " + direction + ",id"
	selectArgs := append([]any(nil), args...)
	if query.PageSize > 0 {
		statement += fmt.Sprintf(" LIMIT $%d OFFSET $%d", len(selectArgs)+1, len(selectArgs)+2)
		selectArgs = append(selectArgs, query.PageSize, (query.Page-1)*query.PageSize)
	}
	rows, err := s.db.QueryContext(ctx, statement, selectArgs...)
	if err != nil {
		return RuleJobListPage{}, fmt.Errorf("list postgres rule jobs page: %w", err)
	}
	defer rows.Close()
	items := make([]rules.Job, 0)
	for rows.Next() {
		var data, status string
		var job rules.Job
		if err := rows.Scan(&data, &status); err != nil {
			return RuleJobListPage{}, fmt.Errorf("scan postgres rule job page: %w", err)
		}
		if err := json.Unmarshal([]byte(data), &job); err != nil {
			return RuleJobListPage{}, fmt.Errorf("decode postgres rule job page: %w", err)
		}
		job.Status = status
		items = append(items, job)
	}
	if err := rows.Err(); err != nil {
		return RuleJobListPage{}, fmt.Errorf("iterate postgres rule job page: %w", err)
	}
	pageSize := query.PageSize
	if pageSize == 0 {
		pageSize = len(items)
		if pageSize == 0 {
			pageSize = DefaultSystemListPageSize
		}
	}
	return RuleJobListPage{Items: items, Total: total, Page: query.Page, PageSize: pageSize}, nil
}
