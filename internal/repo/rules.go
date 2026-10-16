package repo

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"scanner-platform/internal/rules"
)

func (s *RuntimeStore) QueueRuleJob(ctx context.Context, job rules.Job, actor string) (rules.Job, error) {
	if job.Kind != "IMPORT" && job.Kind != "FETCH" && job.Kind != "ACTIVATE" {
		return job, ErrInvalidTask
	}
	if job.Kind == "IMPORT" && (len(job.Bundle) == 0 || len(job.Bundle) > rules.MaxArchive) {
		return job, ErrInvalidTask
	}
	if job.Kind == "FETCH" {
		if err := rules.ValidateSource(job.URL, job.ExpectedSHA256); err != nil {
			return job, ErrInvalidTask
		}
	}
	if job.Kind == "ACTIVATE" && !rules.ValidateVersion(job.Version) {
		return job, ErrInvalidTask
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return job, err
	}
	defer tx.Rollback()
	var pending int
	if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM rule_jobs WHERE status IN ('PENDING','RUNNING')").Scan(&pending); err != nil {
		return job, err
	}
	if pending >= 10 {
		return job, ErrTaskConflict
	}
	bundle := job.Bundle
	job.Bundle = nil
	job.ID = "rules-" + randomLocalID()
	job.Status = "PENDING"
	job.CreatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	job.CompletedAt = ""
	job.Message = ""
	job.NodeID = ""
	data, _ := json.Marshal(job)
	if _, err := tx.ExecContext(ctx, "INSERT INTO rule_jobs(id,status,data,bundle,created_at) VALUES(?,?,?,?,?)", job.ID, job.Status, string(data), bundle, job.CreatedAt); err != nil {
		return job, err
	}
	if err := logLocal(ctx, tx, actor, "queue_rule_"+job.Kind, "rule_job", job.ID, job.Version); err != nil {
		return job, err
	}
	return job, tx.Commit()
}

func (s *RuntimeStore) ClaimRuleJob(ctx context.Context, nodeID string) (*rules.Job, error) {
	var data, status string
	var bundle []byte
	err := s.db.QueryRowContext(ctx, `UPDATE rule_jobs SET status='RUNNING',data=json_set(data,'$.nodeId',?)
  WHERE id=(SELECT id FROM rule_jobs WHERE status='PENDING' ORDER BY created_at,id LIMIT 1) AND status='PENDING'
  RETURNING data,status,bundle`, nodeID).Scan(&data, &status, &bundle)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var job rules.Job
	if err := json.Unmarshal([]byte(data), &job); err != nil {
		return nil, err
	}
	job.Status = status
	job.Bundle = bundle
	return &job, nil
}

func syncRuleCatalog(ctx context.Context, tx *sql.Tx, bundles []rules.Bundle) error {
	if len(bundles) > 1000 {
		return ErrInvalidTask
	}
	current := 0
	for _, bundle := range bundles {
		if !rules.ValidateVersion(bundle.Version) {
			return ErrInvalidTask
		}
		if bundle.IsCurrent {
			current++
		}
	}
	if current > 1 {
		return ErrInvalidTask
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM local_rule_bundles"); err != nil {
		return err
	}
	for _, bundle := range bundles {
		data, _ := json.Marshal(bundle)
		if _, err := tx.ExecContext(ctx, "INSERT INTO local_rule_bundles(version,data) VALUES(?,?)", bundle.Version, string(data)); err != nil {
			return err
		}
	}
	return nil
}
func (s *RuntimeStore) SyncRules(ctx context.Context, bundles []rules.Bundle) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := syncRuleCatalog(ctx, tx, bundles); err != nil {
		return err
	}
	return tx.Commit()
}
func (s *RuntimeStore) ReportRuleJob(ctx context.Context, report rules.Report) error {
	if report.Status != "COMPLETED" && report.Status != "FAILED" || len(report.Message) > 500 {
		return ErrInvalidTask
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var data, status string
	if err := tx.QueryRowContext(ctx, "SELECT data,status FROM rule_jobs WHERE id=?", report.JobID).Scan(&data, &status); err != nil {
		return ErrTaskConflict
	}
	var job rules.Job
	if err := json.Unmarshal([]byte(data), &job); err != nil {
		return err
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
	encoded, _ := json.Marshal(job)
	if _, err := tx.ExecContext(ctx, `UPDATE rule_jobs SET status=?,data=?,bundle=NULL WHERE id=?`, job.Status, string(encoded), job.ID); err != nil {
		return err
	}
	if report.Bundles != nil {
		if err := syncRuleCatalog(ctx, tx, report.Bundles); err != nil {
			return err
		}
	}
	if err := logLocal(ctx, tx, report.NodeID, "rule_job_"+job.Status, "rule_job", job.ID, job.Message); err != nil {
		return err
	}
	return tx.Commit()
}
func (s *RuntimeStore) ListRuleJobs(ctx context.Context) ([]rules.Job, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT data,status FROM rule_jobs ORDER BY created_at DESC LIMIT 100")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []rules.Job{}
	for rows.Next() {
		var data, status string
		var job rules.Job
		if err := rows.Scan(&data, &status); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(data), &job); err != nil {
			return nil, err
		}
		job.Status = status
		out = append(out, job)
	}
	return out, rows.Err()
}
func (s *RuntimeStore) ListRules(ctx context.Context) ([]rules.Bundle, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT data FROM local_rule_bundles ORDER BY version DESC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []rules.Bundle{}
	for rows.Next() {
		var data string
		var bundle rules.Bundle
		if err := rows.Scan(&data); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(data), &bundle); err != nil {
			return nil, err
		}
		out = append(out, bundle)
	}
	return out, rows.Err()
}
