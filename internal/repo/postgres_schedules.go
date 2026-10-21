package repo

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"scanner-platform/internal/portprobe"
	"scanner-platform/internal/scheduler"
	"scanner-platform/internal/taskflow"
)

func (s *PostgresRuntimeStore) normalizePostgresScheduleInput(ctx context.Context, in taskflow.TaskInput) (taskflow.TaskInput, error) {
	if in.Engine != "auto" || strings.TrimSpace(in.AssetID) == "" || !in.PortProbe.OpsApproved || in.InputPath != "" || in.InputKind != "" || in.Scheme != "" || len(in.Targets) > 1 || len(in.CustomRuleIDs) > 0 {
		return taskflow.TaskInput{}, ErrInvalidTask
	}
	var address, windowsRaw string
	if err := s.db.QueryRowContext(ctx, `SELECT a.address,s.time_windows
		FROM assets a JOIN authorized_scopes s ON s.asset_id=a.id
		WHERE a.id=$1 AND a.kind='host' AND s.status='APPROVED' AND s.expires_at>CURRENT_TIMESTAMP
		ORDER BY s.expires_at DESC,s.id LIMIT 1`, in.AssetID).Scan(&address, &windowsRaw); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return taskflow.TaskInput{}, ErrInvalidTask
		}
		return taskflow.TaskInput{}, fmt.Errorf("read postgres schedule scope: %w", err)
	}
	ip, err := netip.ParseAddr(address)
	if err != nil || ip.IsUnspecified() || ip.IsMulticast() || ip.Zone() != "" {
		return taskflow.TaskInput{}, ErrInvalidTask
	}
	address = ip.Unmap().String()
	if len(in.Targets) == 1 && strings.TrimSpace(in.Targets[0]) != address {
		return taskflow.TaskInput{}, ErrInvalidTask
	}
	var approvedWindows []scheduler.Window
	if err := json.Unmarshal([]byte(windowsRaw), &approvedWindows); err != nil {
		return taskflow.TaskInput{}, fmt.Errorf("decode postgres schedule windows: %w", err)
	}
	if len(in.TimeWindows) == 0 {
		in.TimeWindows = approvedWindows
	} else {
		requested, _ := json.Marshal(in.TimeWindows)
		approved, _ := json.Marshal(approvedWindows)
		if string(requested) != string(approved) {
			return taskflow.TaskInput{}, fmt.Errorf("%w: task window must stay within approved scope", ErrInvalidTask)
		}
	}
	if err := scheduler.ValidateWindows(in.TimeWindows); err != nil {
		return taskflow.TaskInput{}, ErrInvalidTask
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
		return taskflow.TaskInput{}, err
	}
	selected, err := portprobe.SelectPorts(config)
	if err != nil || len(selected) == 0 {
		return taskflow.TaskInput{}, fmt.Errorf("%w: invalid scheduled port range", ErrInvalidTask)
	}
	excluded, err := s.postgresExcludedPorts(ctx, in.AssetID)
	if err != nil {
		return taskflow.TaskInput{}, err
	}
	effective := 0
	for _, port := range selected {
		if !excluded[port] {
			effective++
		}
	}
	if effective == 0 {
		return taskflow.TaskInput{}, fmt.Errorf("%w: all scheduled ports are excluded", ErrInvalidTask)
	}
	// Approval applies to the ports that will actually be probed. Excluded
	// ports are intentionally removed before the authorization check so a
	// quarantined port cannot make an otherwise valid schedule fail.
	effectivePorts := make([]int, 0, len(selected))
	for _, port := range selected {
		if !excluded[port] {
			effectivePorts = append(effectivePorts, port)
		}
	}
	approved, err := s.postgresApprovedVulnerabilityPorts(ctx, in.AssetID, effectivePorts)
	if err != nil {
		return taskflow.TaskInput{}, err
	}
	if approved < effective {
		return taskflow.TaskInput{}, fmt.Errorf("%w: scheduled ports must be approved before vulnerability scanning", ErrInvalidTask)
	}
	config.RegisteredPorts = nil
	in.Targets = []string{address}
	in.PortProbe = config
	return in, nil
}

func validatePostgresScheduleTime(in taskflow.Schedule, now time.Time) (time.Time, error) {
	if strings.TrimSpace(in.Name) == "" || len(in.Name) > 100 || in.IntervalMinutes < 0 || in.IntervalMinutes > 525600 {
		return time.Time{}, ErrInvalidTask
	}
	due, err := time.Parse(time.RFC3339, in.NextRun)
	if err != nil || !due.After(now) || due.After(now.Add(366*24*time.Hour)) {
		return time.Time{}, ErrInvalidTask
	}
	return due.UTC(), nil
}

func (s *PostgresRuntimeStore) SaveSchedule(ctx context.Context, in taskflow.Schedule, actor string) (taskflow.Schedule, error) {
	if strings.TrimSpace(actor) == "" {
		return in, ErrInvalidTask
	}
	now := time.Now().UTC()
	due, err := validatePostgresScheduleTime(in, now)
	if err != nil {
		return in, err
	}
	normalized, err := s.normalizePostgresScheduleInput(ctx, in.TaskInput)
	if err != nil {
		return in, err
	}
	in.ID = "schedule-" + randomLocalID()
	in.TaskInput = normalized
	in.Enabled = true
	in.CreatedBy = actor
	in.LastTaskID = ""
	in.LastError = ""
	in.NextRun = due.Format(time.RFC3339Nano)
	data, err := json.Marshal(in)
	if err != nil {
		return in, fmt.Errorf("encode postgres schedule: %w", err)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return in, fmt.Errorf("begin postgres schedule: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `INSERT INTO task_schedules(id,data,created_at,updated_at) VALUES ($1,$2,$3,$3)`, in.ID, string(data), now); err != nil {
		return in, fmt.Errorf("insert postgres schedule: %w", err)
	}
	if err := s.postgresAuditTx(ctx, tx, actor, "create_schedule", "schedule", in.ID, ""); err != nil {
		return in, err
	}
	if err := tx.Commit(); err != nil {
		return in, fmt.Errorf("commit postgres schedule: %w", err)
	}
	return in, nil
}

func (s *PostgresRuntimeStore) UpdateSchedule(ctx context.Context, id string, in taskflow.Schedule, actor string) (taskflow.Schedule, error) {
	if strings.TrimSpace(id) == "" || strings.TrimSpace(actor) == "" {
		return in, ErrInvalidTask
	}
	now := time.Now().UTC()
	due, err := validatePostgresScheduleTime(in, now)
	if err != nil {
		return in, err
	}
	normalized, err := s.normalizePostgresScheduleInput(ctx, in.TaskInput)
	if err != nil {
		return in, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return in, fmt.Errorf("begin postgres schedule update: %w", err)
	}
	defer tx.Rollback()
	var raw string
	var current taskflow.Schedule
	if err := tx.QueryRowContext(ctx, `SELECT data FROM task_schedules WHERE id=$1 FOR UPDATE`, id).Scan(&raw); errors.Is(err, sql.ErrNoRows) {
		return in, ErrTaskConflict
	} else if err != nil {
		return in, err
	}
	if err := json.Unmarshal([]byte(raw), &current); err != nil {
		return in, fmt.Errorf("decode postgres schedule: %w", err)
	}
	in.ID = id
	in.TaskInput = normalized
	in.Enabled = current.Enabled
	in.CreatedBy = current.CreatedBy
	in.LastTaskID = current.LastTaskID
	in.LastError = ""
	in.NextRun = due.Format(time.RFC3339Nano)
	data, err := json.Marshal(in)
	if err != nil {
		return in, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE task_schedules SET data=$1,updated_at=$2 WHERE id=$3`, string(data), now, id); err != nil {
		return in, err
	}
	if err := s.postgresAuditTx(ctx, tx, actor, "update_schedule", "schedule", id, ""); err != nil {
		return in, err
	}
	if err := tx.Commit(); err != nil {
		return in, err
	}
	return in, nil
}

func (s *PostgresRuntimeStore) DeleteSchedule(ctx context.Context, id, actor string) error {
	if strings.TrimSpace(id) == "" || strings.TrimSpace(actor) == "" {
		return ErrInvalidTask
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var exists bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM task_schedules WHERE id=$1)`, id).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		return ErrTaskConflict
	}
	if err := s.postgresAuditTx(ctx, tx, actor, "delete_schedule", "schedule", id, ""); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM task_schedules WHERE id=$1`, id); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *PostgresRuntimeStore) ListSchedules(ctx context.Context) ([]taskflow.Schedule, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT data FROM task_schedules ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("list postgres schedules: %w", err)
	}
	defer rows.Close()
	items := make([]taskflow.Schedule, 0)
	for rows.Next() {
		var raw string
		var item taskflow.Schedule
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(raw), &item); err != nil {
			return nil, fmt.Errorf("decode postgres schedule: %w", err)
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *PostgresRuntimeStore) ListScheduleRuns(ctx context.Context, scheduleID string, limit, offset int) ([]taskflow.ScheduleRun, int, error) {
	if strings.TrimSpace(scheduleID) == "" {
		return nil, 0, ErrInvalidTask
	}
	if limit <= 0 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}
	var total int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM schedule_runs WHERE schedule_id=$1`, scheduleID).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count postgres schedule runs: %w", err)
	}
	rows, err := s.db.QueryContext(ctx, `SELECT r.id,r.schedule_id,r.task_id,r.triggered_at,
		CASE WHEN r.error<>'' OR r.task_id='' THEN 'FAILED'
		WHEN t.id IS NULL THEN 'DELETED' ELSE t.status END,r.error
		FROM schedule_runs r LEFT JOIN scan_tasks t ON t.id=r.task_id
		WHERE r.schedule_id=$1 ORDER BY r.triggered_at DESC,r.id DESC LIMIT $2 OFFSET $3`, scheduleID, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("list postgres schedule runs: %w", err)
	}
	defer rows.Close()
	items := make([]taskflow.ScheduleRun, 0, limit)
	for rows.Next() {
		var item taskflow.ScheduleRun
		var triggered time.Time
		if err := rows.Scan(&item.ID, &item.ScheduleID, &item.TaskID, &triggered, &item.Status, &item.Error); err != nil {
			return nil, 0, err
		}
		item.TriggeredAt = triggered.UTC().Format(time.RFC3339Nano)
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	return items, total, nil
}

func (s *PostgresRuntimeStore) ToggleSchedule(ctx context.Context, id, actor string, enabled bool) error {
	if strings.TrimSpace(id) == "" || strings.TrimSpace(actor) == "" {
		return ErrInvalidTask
	}
	now := time.Now().UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var raw string
	var item taskflow.Schedule
	if err := tx.QueryRowContext(ctx, `SELECT data FROM task_schedules WHERE id=$1 FOR UPDATE`, id).Scan(&raw); errors.Is(err, sql.ErrNoRows) {
		return ErrTaskConflict
	} else if err != nil {
		return err
	}
	if err := json.Unmarshal([]byte(raw), &item); err != nil {
		return err
	}
	item.Enabled = enabled
	item.LastError = ""
	if enabled {
		due, err := time.Parse(time.RFC3339Nano, item.NextRun)
		if err != nil {
			return ErrInvalidTask
		}
		if !due.After(now) {
			item.NextRun = now.Add(time.Second).Format(time.RFC3339Nano)
		}
	}
	data, err := json.Marshal(item)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE task_schedules SET data=$1,updated_at=$2 WHERE id=$3`, string(data), now, id); err != nil {
		return err
	}
	if err := s.postgresAuditTx(ctx, tx, actor, "toggle_schedule", "schedule", id, strconv.FormatBool(enabled)); err != nil {
		return err
	}
	return tx.Commit()
}

func insertPostgresScheduleRun(ctx context.Context, tx *sql.Tx, scheduleID, taskID string, triggeredAt time.Time, runError string) error {
	if strings.TrimSpace(scheduleID) == "" || len(taskID) > 128 || len(runError) > 512 {
		return ErrInvalidTask
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO schedule_runs(id,schedule_id,task_id,triggered_at,error) VALUES ($1,$2,$3,$4,$5)`, "schedule-run-"+randomLocalID(), scheduleID, taskID, triggeredAt.UTC(), runError)
	return err
}

func (s *PostgresRuntimeStore) tickPostgresSchedules(ctx context.Context, now time.Time) error {
	items, err := s.ListSchedules(ctx)
	if err != nil {
		return err
	}
	for _, snapshot := range items {
		due, err := time.Parse(time.RFC3339Nano, snapshot.NextRun)
		if err != nil {
			return fmt.Errorf("parse postgres schedule next run: %w", err)
		}
		if !snapshot.Enabled || due.After(now) {
			continue
		}
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		var raw string
		if err := tx.QueryRowContext(ctx, `SELECT data FROM task_schedules WHERE id=$1 FOR UPDATE`, snapshot.ID).Scan(&raw); errors.Is(err, sql.ErrNoRows) {
			tx.Rollback()
			continue
		} else if err != nil {
			tx.Rollback()
			return err
		}
		var item taskflow.Schedule
		if err := json.Unmarshal([]byte(raw), &item); err != nil {
			tx.Rollback()
			return err
		}
		latestDue, err := time.Parse(time.RFC3339Nano, item.NextRun)
		if err != nil {
			tx.Rollback()
			return fmt.Errorf("parse postgres schedule next run: %w", err)
		}
		if !item.Enabled || !latestDue.Equal(due) || latestDue.After(now) {
			tx.Rollback()
			continue
		}
		// Keep the row lock while creating the task. This serializes concurrent
		// Tick calls for a schedule and prevents two workers from consuming the
		// same due timestamp. CreateLocalTask uses another pool connection and
		// never touches task_schedules, so it does not contend with this lock.
		task, createErr := s.CreateLocalTask(ctx, item.TaskInput, item.CreatedBy)
		if createErr != nil {
			if !errors.Is(createErr, ErrInvalidTask) {
				tx.Rollback()
				return createErr
			}
			item.Enabled = false
			item.LastError = truncateScheduleError(createErr.Error())
			if err := insertPostgresScheduleRun(ctx, tx, item.ID, "", now, item.LastError); err != nil {
				tx.Rollback()
				return err
			}
		} else {
			item.LastTaskID = task.ID
			item.LastError = ""
			if item.IntervalMinutes == 0 {
				item.Enabled = false
			} else {
				item.NextRun = now.Add(time.Duration(item.IntervalMinutes) * time.Minute).UTC().Format(time.RFC3339Nano)
			}
			if err := insertPostgresScheduleRun(ctx, tx, item.ID, task.ID, now, ""); err != nil {
				tx.Rollback()
				return err
			}
		}
		data, err := json.Marshal(item)
		if err != nil {
			tx.Rollback()
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE task_schedules SET data=$1,updated_at=$2 WHERE id=$3`, string(data), now, item.ID); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

func truncateScheduleError(value string) string {
	if len(value) > 512 {
		return value[:512]
	}
	return value
}
