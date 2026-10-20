package repo

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"scanner-platform/internal/portprobe"
	"scanner-platform/internal/taskflow"
)

// FindingRetest links a user-requested verification task to the finding that
// caused it. The relation deliberately stores no target or engine output.
type FindingRetest struct {
	ID        string    `json:"id"`
	FindingID string    `json:"findingId"`
	TaskID    string    `json:"taskId"`
	Actor     string    `json:"actor"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"createdAt"`
}

func (s *RuntimeStore) initFindingRetests(ctx context.Context) error {
	for _, q := range []string{
		`CREATE TABLE IF NOT EXISTS finding_retests(
			id TEXT PRIMARY KEY,
			finding_id TEXT NOT NULL REFERENCES security_findings(id) ON DELETE CASCADE,
			task_id TEXT NOT NULL UNIQUE REFERENCES scan_tasks(id) ON DELETE CASCADE,
			actor TEXT NOT NULL,
			created_at TEXT NOT NULL)`,
		`CREATE INDEX IF NOT EXISTS finding_retests_history ON finding_retests(finding_id,created_at,id)`,
	} {
		if _, err := s.db.ExecContext(ctx, q); err != nil {
			return err
		}
	}
	return nil
}

func exactRetestRanges(ports []int) []portprobe.Range {
	if len(ports) == 0 {
		return nil
	}
	sorted := append([]int(nil), ports...)
	sort.Ints(sorted)
	ranges := make([]portprobe.Range, 0, len(sorted))
	start, end := sorted[0], sorted[0]
	for _, port := range sorted[1:] {
		if port == end+1 {
			end = port
			continue
		}
		ranges = append(ranges, portprobe.Range{Start: start, End: end})
		start, end = port, port
	}
	return append(ranges, portprobe.Range{Start: start, End: end})
}

func containsPort(ports []int, wanted int) bool {
	for _, port := range ports {
		if port == wanted {
			return true
		}
	}
	return false
}

func frozenRetestInput(finding taskflow.Finding, detail taskDetails) (taskflow.TaskInput, error) {
	input := detail.Input
	if input.Synthetic || input.Engine == "" || input.AssetID == "" && input.Engine == "auto" {
		return taskflow.TaskInput{}, fmt.Errorf("%w: finding retest requires a completed registered scan", ErrInvalidTask)
	}
	switch input.Engine {
	case "nuclei", "zap":
		if finding.Engine != input.Engine || len(input.Targets) == 0 {
			return taskflow.TaskInput{}, fmt.Errorf("%w: finding and parent scan do not match", ErrInvalidTask)
		}
		// Retesting one finding must never repeat other targets from a batch.
		input.Targets = []string{finding.Target}
	case "auto":
		if finding.Engine != "nuclei" && finding.Engine != "trivy" || len(input.Targets) != 1 || len(detail.ProbePorts) == 0 {
			return taskflow.TaskInput{}, fmt.Errorf("%w: this finding cannot be retested from the parent scan", ErrInvalidTask)
		}
		host, port, target, err := canonicalTarget(finding.Target)
		if err != nil || target != finding.Target || host != input.Targets[0] || !containsPort(detail.ProbePorts, port) {
			return taskflow.TaskInput{}, fmt.Errorf("%w: finding is outside the frozen scan scope", ErrInvalidTask)
		}
		// Rebuild the probe plan from the parent's resolved ports. Reusing a
		// broad preset could expand the retest after policy or asset changes.
		input.Targets = []string{input.Targets[0]}
		input.PortProbe = portprobe.Config{
			Preset:        portprobe.PresetCustom,
			Ranges:        exactRetestRanges(detail.ProbePorts),
			Intensity:     input.PortProbe.Intensity,
			OpsApproved:   true,
			FullConfirmed: len(detail.ProbePorts) == portprobe.MaxPorts,
		}
	default:
		return taskflow.TaskInput{}, fmt.Errorf("%w: this engine does not support finding retest", ErrInvalidTask)
	}
	input.Synthetic = false
	return input, nil
}

func (s *RuntimeStore) CreateFindingRetest(ctx context.Context, findingID, actor string) (taskflow.Task, FindingRetest, error) {
	if actor == "" || findingID == "" {
		return taskflow.Task{}, FindingRetest{}, ErrInvalidTask
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return taskflow.Task{}, FindingRetest{}, err
	}
	defer tx.Rollback()
	var rawFinding string
	if err := tx.QueryRowContext(ctx, `SELECT data FROM security_findings WHERE id=?`, findingID).Scan(&rawFinding); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return taskflow.Task{}, FindingRetest{}, ErrTaskConflict
		}
		return taskflow.Task{}, FindingRetest{}, err
	}
	var finding taskflow.Finding
	if err := json.Unmarshal([]byte(rawFinding), &finding); err != nil {
		return taskflow.Task{}, FindingRetest{}, err
	}
	if finding.Synthetic || finding.Status == "FALSE_POSITIVE" {
		return taskflow.Task{}, FindingRetest{}, fmt.Errorf("%w: synthetic or false-positive findings cannot be retested", ErrInvalidTask)
	}
	var parentStatus, rawDetails string
	if err := tx.QueryRowContext(ctx, `SELECT status,details FROM scan_tasks WHERE id=?`, finding.TaskID).Scan(&parentStatus, &rawDetails); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return taskflow.Task{}, FindingRetest{}, ErrTaskConflict
		}
		return taskflow.Task{}, FindingRetest{}, err
	}
	if parentStatus != "COMPLETED" {
		return taskflow.Task{}, FindingRetest{}, fmt.Errorf("%w: parent scan is not complete", ErrInvalidTask)
	}
	var detail taskDetails
	if err := json.Unmarshal([]byte(rawDetails), &detail); err != nil {
		return taskflow.Task{}, FindingRetest{}, err
	}
	input, err := frozenRetestInput(finding, detail)
	if err != nil {
		return taskflow.Task{}, FindingRetest{}, err
	}
	var existingID, existingStatus string
	err = tx.QueryRowContext(ctx, `SELECT fr.id,st.status FROM finding_retests fr JOIN scan_tasks st ON st.id=fr.task_id
		WHERE fr.finding_id=? AND st.status IN ('PENDING','WAITING_WINDOW','RUNNING','PAUSED_WINDOW') LIMIT 1`, findingID).Scan(&existingID, &existingStatus)
	if err == nil {
		return taskflow.Task{}, FindingRetest{}, fmt.Errorf("%w: an active retest already exists", ErrTaskConflict)
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return taskflow.Task{}, FindingRetest{}, err
	}
	taskID := "task-" + randomLocalID()
	task, err := createLocalTaskWithRetest(ctx, tx, input, actor, taskID, time.Now().UTC(), findingID)
	if err != nil {
		return taskflow.Task{}, FindingRetest{}, err
	}
	retest := FindingRetest{ID: "retest-" + randomLocalID(), FindingID: findingID, TaskID: task.ID, Actor: actor, Status: task.Status, CreatedAt: time.Now().UTC()}
	if _, err := tx.ExecContext(ctx, `INSERT INTO finding_retests(id,finding_id,task_id,actor,created_at) VALUES(?,?,?,?,?)`, retest.ID, retest.FindingID, retest.TaskID, retest.Actor, retest.CreatedAt.Format(time.RFC3339Nano)); err != nil {
		return taskflow.Task{}, FindingRetest{}, err
	}
	audit, _ := json.Marshal(map[string]string{"retestId": retest.ID, "taskId": retest.TaskID})
	if err := logLocal(ctx, tx, actor, "retest_finding", "finding", findingID, string(audit)); err != nil {
		return taskflow.Task{}, FindingRetest{}, err
	}
	if err := tx.Commit(); err != nil {
		return taskflow.Task{}, FindingRetest{}, err
	}
	return task, retest, nil
}

func (s *RuntimeStore) ListFindingRetests(ctx context.Context, findingID string) ([]FindingRetest, error) {
	var exists int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM security_findings WHERE id=?`, findingID).Scan(&exists); err != nil {
		return nil, err
	}
	if exists != 1 {
		return nil, ErrTaskConflict
	}
	rows, err := s.db.QueryContext(ctx, `SELECT fr.id,fr.finding_id,fr.task_id,fr.actor,st.status,fr.created_at
		FROM finding_retests fr JOIN scan_tasks st ON st.id=fr.task_id WHERE fr.finding_id=? ORDER BY fr.created_at,fr.id`, findingID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []FindingRetest{}
	for rows.Next() {
		var item FindingRetest
		var created string
		if err := rows.Scan(&item.ID, &item.FindingID, &item.TaskID, &item.Actor, &item.Status, &created); err != nil {
			return nil, err
		}
		item.CreatedAt, err = time.Parse(time.RFC3339Nano, created)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}
