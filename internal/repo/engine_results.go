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

	"net"
	"scanner-platform/internal/findings"
	"scanner-platform/internal/portprobe"
	"scanner-platform/internal/taskflow"
	"strconv"
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

func validDetection(d taskflow.Detection, task taskflow.Task, openResults []taskflow.PortProbeResult) bool {
	if !findings.ValidMetadata(d) {
		return false
	}
	if len(task.Engines) != 1 || len(d.TemplateID) == 0 || len(d.TemplateID) > 200 || len(d.Title) == 0 || len(d.Title) > 500 || len(d.Description) > 4000 || len(d.MatchedPath) > 1000 || len(d.Package) > 300 || len(d.InstalledVersion) > 200 || len(d.FixedVersion) > 1000 || len(d.ArtifactID) > 200 {
		return false
	}
	if task.Engines[0] == "auto" {
		if d.Engine != "nuclei" && d.Engine != "zap" && d.Engine != "trivy" {
			return false
		}
		address, port, target, err := canonicalTarget(d.Target)
		if err != nil || target != d.Target || address != task.Chunks[0].Targets[0] {
			return false
		}
		allowed, open := false, false
		for _, candidate := range task.VulnerabilityPorts {
			allowed = allowed || candidate == port
		}
		for _, candidate := range openResults {
			open = open || candidate.Port == port
		}
		if !allowed || !open {
			return false
		}
	} else if d.Engine != task.Engines[0] {
		return false
	}
	switch d.Severity {
	case "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO":
	default:
		return false
	}
	targetOK := false
	if task.Engines[0] == "auto" {
		targetOK = true
	} else {
		for _, target := range task.Chunks[0].Targets {
			targetOK = targetOK || d.Target == target
		}
	}
	return targetOK
}

func validPortProbeResults(results []taskflow.PortProbeResult, task taskflow.Task) bool {
	if len(task.Engines) != 1 || task.Engines[0] != "port-probe" && task.Engines[0] != "auto" || task.AssetID == "" || len(task.Chunks) != 1 || len(task.Chunks[0].Targets) != 1 || len(task.PortProbePorts) == 0 || len(task.PortProbePorts) > portprobe.MaxPorts || len(results) > len(task.PortProbePorts) {
		return false
	}
	allowed := make(map[int]bool, len(task.PortProbePorts))
	for _, port := range task.PortProbePorts {
		if port < 1 || port > 65535 || allowed[port] {
			return false
		}
		allowed[port] = true
	}
	seen := make(map[int]bool, len(results))
	for _, result := range results {
		if !allowed[result.Port] || seen[result.Port] {
			return false
		}
		seen[result.Port] = true
	}
	return true
}

func validServiceResults(results []taskflow.ServiceResult, task taskflow.Task, open []taskflow.PortProbeResult) bool {
	if task.Engines[0] != "auto" || len(results) != len(open) || len(results) > 65535 {
		return false
	}
	allowed := map[int]bool{}
	opened := map[int]bool{}
	seen := map[int]bool{}
	for _, p := range task.VulnerabilityPorts {
		allowed[p] = true
	}
	for _, p := range open {
		opened[p.Port] = true
	}
	for _, service := range results {
		if !allowed[service.Port] || !opened[service.Port] || seen[service.Port] || !validService(service, task.Chunks[0].Targets[0]) {
			return false
		}
		seen[service.Port] = true
	}
	return true
}

func validSystemScanStatus(value string) bool {
	switch value {
	case taskflow.SystemScanNotStarted, taskflow.SystemScanNotConfigured, taskflow.SystemScanPortOutOfScope, taskflow.SystemScanPortClosed,
		taskflow.SystemScanClientMissing, taskflow.SystemScanHostKeyMismatch, taskflow.SystemScanAuthFailed,
		taskflow.SystemScanPythonMissing, taskflow.SystemScanCollectionFailed, taskflow.SystemScanInvalidSnapshot,
		taskflow.SystemScanTrivyUnavailable, taskflow.SystemScanUnsupportedOS, taskflow.SystemScanTrivyFailed, taskflow.SystemScanCompleted:
		return true
	default:
		return false
	}
}

func persistAutoScanStatus(ctx context.Context, tx *sql.Tx, taskID string, report taskflow.Report) error {
	var raw string
	if err := tx.QueryRowContext(ctx, `SELECT details FROM scan_tasks WHERE id=?`, taskID).Scan(&raw); err != nil {
		return err
	}
	var detail taskDetails
	if err := json.Unmarshal([]byte(raw), &detail); err != nil {
		return err
	}
	detail.SystemStatus = report.SystemScanStatus
	detail.ApplicationStatus = report.ApplicationScanStatus
	detail.ApplicationResults = append([]taskflow.ApplicationResult(nil), report.ApplicationResults...)
	encoded, err := json.Marshal(detail)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE scan_tasks SET details=? WHERE id=?`, string(encoded), taskID); err != nil {
		return err
	}
	return nil
}

func (s *RuntimeStore) completeEngineTask(ctx context.Context, report taskflow.Report) error {
	if len(report.Findings) > 100000 || len(report.Error) > 500 {
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
	portProbeTask := len(task.Engines) == 1 && task.Engines[0] == "port-probe"
	autoTask := len(task.Engines) == 1 && task.Engines[0] == "auto"
	if !validApplicationReport(report, autoTask) {
		return ErrInvalidTask
	}
	if autoTask && !validSystemScanStatus(report.SystemScanStatus) || !autoTask && report.SystemScanStatus != "" {
		return ErrInvalidTask
	}
	if portProbeTask {
		if len(report.Findings) != 0 || len(report.ServiceResults) != 0 || !validPortProbeResults(report.PortProbeResults, task) {
			return ErrInvalidTask
		}
	} else if autoTask {
		if !validPortProbeResults(report.PortProbeResults, task) || !validServiceResults(report.ServiceResults, task, report.PortProbeResults) {
			return ErrInvalidTask
		}
	} else if len(report.PortProbeResults) != 0 || len(report.ServiceResults) != 0 {
		return ErrInvalidTask
	}
	if !validAssetProfile(report.AssetProfile) {
		return ErrInvalidTask
	}
	quarantined := map[int]bool{}
	for _, service := range report.ServiceResults {
		if service.Quarantined {
			quarantined[service.Port] = true
		}
	}
	for _, d := range report.Findings {
		_, port, _, _ := canonicalTarget(d.Target)
		if quarantined[port] {
			return ErrInvalidTask
		}
		if !validDetection(d, task, report.PortProbeResults) {
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
	if report.Status == "FAILED" && (len(report.PortProbeResults) != 0 || len(report.ServiceResults) != 0) {
		return ErrInvalidTask
	}
	if autoTask && report.Status != "COMPLETED" {
		if err := persistAutoScanStatus(ctx, tx, task.ID, report); err != nil {
			return err
		}
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
		if portProbeTask || autoTask {
			detail.ProbeResults = append([]taskflow.PortProbeResult{}, report.PortProbeResults...)
			detail.Services = append([]taskflow.ServiceResult{}, report.ServiceResults...)
			detail.SystemStatus = report.SystemScanStatus
			detail.ApplicationStatus = report.ApplicationScanStatus
			detail.ApplicationResults = append([]taskflow.ApplicationResult(nil), report.ApplicationResults...)
			detail.AssetProfile = report.AssetProfile
			encoded, err := json.Marshal(detail)
			if err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, "UPDATE scan_tasks SET details=? WHERE id=?", string(encoded), task.ID); err != nil {
				return err
			}
		}
		if err := recordInventory(ctx, tx, task, report); err != nil {
			return err
		}
		knowledge, err := listKnowledge(ctx, tx)
		if err != nil {
			return err
		}
		for _, service := range report.ServiceResults {
			if service.Quarantined || service.Excluded || service.Software == "" || service.Version == "" {
				continue
			}
			for _, k := range knowledge {
				if d, ok := findings.Match(k, service.Software, service.Version, net.JoinHostPort(task.Chunks[0].Targets[0], strconv.Itoa(service.Port))); ok {
					report.Findings = append(report.Findings, d)
				}
			}
		}
		for _, d := range report.Findings {
			d = findings.Normalize(d)
			for _, k := range knowledge {
				matched := k.ID == d.TemplateID
				for _, ids := range k.Identifiers {
					for _, id := range ids {
						matched = matched || id == d.TemplateID
					}
				}
				if matched {
					if k.Language == "zh-CN" {
						d.Title = k.Title
						d.Description = k.Description
					}
					d.Impact = k.Impact
					d.Solution = k.Solution
					d.References = k.References
					d.Identifiers = k.Identifiers
					d.ContentLanguage = k.Language
					if k.CVSSScore != nil {
						d.CVSSScore = k.CVSSScore
					}
					if k.Category != "" {
						d.VulnCategory = k.Category
					}
					d = findings.Normalize(d)
					break
				}
			}
			identity := d.Target
			matchedPath := d.MatchedPath
			if d.Engine == "trivy" && (task.InputKind == "rootfs" || autoTask) {
				// The stable input alias identifies the host; distro descriptions and
				// temporary analyzer paths must not change an OS package fingerprint.
				matchedPath = ""
			}
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
			assetID, owner, ownerErr := resolveOwner(ctx, tx, d.Target)
			if ownerErr != nil {
				return ownerErr
			}
			if assetID == "" {
				owner = detail.Owners[d.Target]
			}
			f := taskflow.Finding{AssetID: assetID, RiskType: d.RiskType, DetectMethod: d.DetectMethod, Confidence: d.Confidence, CVSSScore: d.CVSSScore, VulnCategory: d.VulnCategory, Identifiers: d.Identifiers, Impact: d.Impact, Solution: d.Solution, References: d.References, Evidence: d.Evidence, Port: d.Port, Component: d.Component, ContentLanguage: d.ContentLanguage, ID: id, TaskID: task.ID, Fingerprint: fingerprint, Severity: d.Severity, Title: d.Title, Engine: d.Engine, TemplateOrCVE: d.TemplateID, Target: d.Target, Status: "OPEN", FirstSeen: now, LastSeen: now, BusinessGroup: owner.Group, Owner: owner.Owner, VerifiedInRun: true, MatchedPath: d.MatchedPath, Package: d.Package, InstalledVersion: d.InstalledVersion, FixedVersion: d.FixedVersion, ArtifactID: d.ArtifactID, Description: d.Description}
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
			if err := observation(ctx, tx, f); err != nil {
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
	if err := logLocal(ctx, tx, report.WorkerID, "report_engine_task", "task", task.ID, func() string {
		data, _ := json.Marshal(map[string]any{"status": report.Status, "ip": task.Chunks[0].Targets, "effectivePorts": task.PortProbePorts, "excluded": task.EffectiveExclusions, "quarantined": task.QuarantinedPorts})
		return string(data)
	}()); err != nil {
		return err
	}
	return tx.Commit()
}
