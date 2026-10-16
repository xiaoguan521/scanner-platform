package repo

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"scanner-platform/internal/taskflow"
)

// Upgrade the early single-finding-per-task schema without dropping its data.
func (s *RuntimeStore) migrateFindings(ctx context.Context) error {
	var schema string
	if err := s.db.QueryRowContext(ctx, "SELECT sql FROM sqlite_master WHERE type='table' AND name='security_findings'").Scan(&schema); err != nil {
		return err
	}
	if !strings.Contains(schema, "task_id TEXT NOT NULL UNIQUE") {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, q := range []string{
		`CREATE TABLE security_findings_next(id TEXT PRIMARY KEY,task_id TEXT NOT NULL REFERENCES scan_tasks(id),data TEXT NOT NULL)`,
		`INSERT INTO security_findings_next SELECT id,task_id,data FROM security_findings`,
		`DROP TABLE security_findings`,
		`ALTER TABLE security_findings_next RENAME TO security_findings`,
	} {
		if _, err := tx.ExecContext(ctx, q); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func validDetection(d taskflow.Detection, task taskflow.Task) bool {
	if len(task.Engines) != 1 || d.Engine != task.Engines[0] || len(d.TemplateID) == 0 || len(d.TemplateID) > 200 || len(d.Title) == 0 || len(d.Title) > 500 || len(d.Description) > 4000 || len(d.MatchedPath) > 1000 || len(d.Package) > 300 || len(d.InstalledVersion) > 200 || len(d.FixedVersion) > 1000 || len(d.ArtifactID) > 200 {
		return false
	}
	switch d.Severity {
	case "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO":
	default:
		return false
	}
	targetOK := false
	for _, target := range task.Chunks[0].Targets {
		targetOK = targetOK || d.Target == target
	}
	return targetOK
}

func (s *RuntimeStore) completeEngineTask(ctx context.Context, report taskflow.Report) error {
	if len(report.Findings) > 2000 || len(report.Error) > 500 {
		return ErrInvalidTask
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	task, err := readRuntimeTask(tx.QueryRowContext(ctx, `SELECT `+taskColumns+` FROM scan_tasks WHERE id=?`, report.TaskID))
	if err != nil {
		return ErrTaskConflict
	}
	if task.Synthetic || len(task.Chunks) != 1 || task.Chunks[0].WorkerNodeID != report.WorkerID {
		return ErrTaskConflict
	}
	for _, d := range report.Findings {
		if !validDetection(d, task) {
			return ErrInvalidTask
		}
	}
	if task.Status == report.Status {
		return nil
	}
	if task.Status != "RUNNING" {
		return ErrTaskConflict
	}
	now := time.Now().UTC()
	if report.Status == "COMPLETED" && task.HardDeadline != "" {
		deadline, err := time.Parse(time.RFC3339Nano, task.HardDeadline)
		if err != nil {
			return err
		}
		if !now.Before(deadline) {
			if _, err := tx.ExecContext(ctx, "UPDATE scan_tasks SET status='PAUSED_WINDOW',worker_id='' WHERE id=?", task.ID); err != nil {
				return err
			}
			if err := tx.Commit(); err != nil {
				return err
			}
			return ErrTaskConflict
		}
	}
	if report.Status == "FAILED" && len(report.Findings) != 0 {
		return ErrInvalidTask
	}
	if report.Status == "COMPLETED" {
		var details string
		if err := tx.QueryRowContext(ctx, "SELECT details FROM scan_tasks WHERE id=?", task.ID).Scan(&details); err != nil {
			return err
		}
		var detail taskDetails
		if err := json.Unmarshal([]byte(details), &detail); err != nil {
			return err
		}
		for _, d := range report.Findings {
			identity := d.Target
			matchedPath := d.MatchedPath
			if d.Engine == "trivy" && task.InputKind == "image-archive" {
				if !strings.HasPrefix(d.ArtifactID, "sha256:") || len(d.ArtifactID) != 71 {
					return ErrInvalidTask
				}
				identity = d.ArtifactID
				if _, err := hex.DecodeString(d.ArtifactID[7:]); err != nil {
					return ErrInvalidTask
				}
				matchedPath = ""
			}
			stable, _ := json.Marshal([]string{identity, d.Engine, d.TemplateID, matchedPath, d.Package, d.InstalledVersion})
			digest := sha256.Sum256(stable)
			fingerprint := hex.EncodeToString(digest[:])
			id := "finding-" + fingerprint
			owner := detail.Owners[d.Target]
			f := taskflow.Finding{ID: id, TaskID: task.ID, Fingerprint: fingerprint, Severity: d.Severity, Title: d.Title, Engine: d.Engine, TemplateOrCVE: d.TemplateID, Target: d.Target, Status: "OPEN", FirstSeen: now, LastSeen: now, BusinessGroup: owner.Group, Owner: owner.Owner, VerifiedInRun: true, MatchedPath: d.MatchedPath, Package: d.Package, InstalledVersion: d.InstalledVersion, FixedVersion: d.FixedVersion, ArtifactID: d.ArtifactID, Description: d.Description}
			var oldData string
			if err := tx.QueryRowContext(ctx, "SELECT data FROM security_findings WHERE id=?", id).Scan(&oldData); err == nil {
				var old taskflow.Finding
				if err := json.Unmarshal([]byte(oldData), &old); err != nil {
					return err
				}
				f.FirstSeen, f.Status = old.FirstSeen, old.Status
				if f.Status == "FIXED" {
					f.Status = "REOPENED"
				}
			} else if err != sql.ErrNoRows {
				return err
			}
			data, _ := json.Marshal(f)
			if _, err := tx.ExecContext(ctx, `INSERT INTO security_findings(id,task_id,data) VALUES(?,?,?) ON CONFLICT(id) DO UPDATE SET task_id=excluded.task_id,data=excluded.data`, id, task.ID, string(data)); err != nil {
				return fmt.Errorf("save engine finding: %w", err)
			}
		}
	}
	// Missing findings never imply FIXED: completeness and repeat thresholds need a later design.
	if _, err := tx.ExecContext(ctx, `UPDATE scan_tasks SET status=?,finished_at=?,details=json_set(details,'$.error',?) WHERE id=?`, report.Status, now.Format(time.RFC3339Nano), report.Error, task.ID); err != nil {
		return err
	}
	if err := logLocal(ctx, tx, report.WorkerID, "report_engine_task", "task", task.ID, report.Status); err != nil {
		return err
	}
	return tx.Commit()
}
