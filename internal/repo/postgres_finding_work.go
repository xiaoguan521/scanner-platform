package repo

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"scanner-platform/internal/taskflow"
)

func postgresFindingWorkUser(ctx context.Context, tx *sql.Tx, id string) (FindingAssignee, error) {
	var user FindingAssignee
	err := tx.QueryRowContext(ctx, `SELECT id,username FROM users WHERE id=$1
		AND is_active=TRUE AND role IN ('admin','security_engineer') FOR SHARE`, id).Scan(&user.ID, &user.Name)
	if errors.Is(err, sql.ErrNoRows) {
		return user, ErrInvalidTask
	}
	if err != nil {
		return user, fmt.Errorf("read postgres finding worker: %w", err)
	}
	return user, nil
}

func validPostgresWorkID(id string, max int) bool {
	return id != "" && id == strings.TrimSpace(id) && len(id) <= max &&
		utf8.ValidString(id) && !strings.ContainsFunc(id, unicode.IsControl)
}

func (s *PostgresRuntimeStore) ListFindingAssignees(ctx context.Context) ([]FindingAssignee, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,username FROM users WHERE is_active=TRUE
		AND role IN ('admin','security_engineer') ORDER BY username,id`)
	if err != nil {
		return nil, fmt.Errorf("list postgres finding assignees: %w", err)
	}
	defer rows.Close()
	items := make([]FindingAssignee, 0)
	for rows.Next() {
		var item FindingAssignee
		if err := rows.Scan(&item.ID, &item.Name); err != nil {
			return nil, fmt.Errorf("scan postgres finding assignee: %w", err)
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *PostgresRuntimeStore) readFindingWorkTx(ctx context.Context, tx *sql.Tx, id string) (taskflow.Finding, error) {
	if !validPostgresWorkID(id, 256) {
		return taskflow.Finding{}, ErrInvalidTask
	}
	finding, err := s.finding.readFindingTx(ctx, tx, id)
	if errors.Is(err, ErrPostgresFindingMissing) {
		return taskflow.Finding{}, ErrTaskNotFound
	}
	return finding, err
}

func (s *PostgresRuntimeStore) AssignFinding(ctx context.Context, id, assigneeID, actor string) (taskflow.Finding, error) {
	if !validPostgresWorkID(actor, 128) || len(assigneeID) > 128 ||
		!utf8.ValidString(assigneeID) || strings.ContainsFunc(assigneeID, unicode.IsControl) {
		return taskflow.Finding{}, ErrInvalidTask
	}
	if assigneeID != "" && !validPostgresWorkID(assigneeID, 128) {
		return taskflow.Finding{}, ErrInvalidTask
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return taskflow.Finding{}, fmt.Errorf("begin postgres finding assignment: %w", err)
	}
	defer tx.Rollback()
	if _, err := postgresFindingWorkUser(ctx, tx, actor); err != nil {
		return taskflow.Finding{}, err
	}
	var assignee FindingAssignee
	if assigneeID != "" {
		assignee, err = postgresFindingWorkUser(ctx, tx, assigneeID)
		if err != nil {
			return taskflow.Finding{}, err
		}
	}
	finding, err := s.readFindingWorkTx(ctx, tx, id)
	if err != nil {
		return taskflow.Finding{}, err
	}
	if finding.AssigneeID == assignee.ID && finding.AssigneeName == assignee.Name {
		return taskflow.Finding{}, ErrInvalidTask
	}
	previous := finding.AssigneeID
	finding.AssigneeID, finding.AssigneeName = assignee.ID, assignee.Name
	now := time.Now().UTC()
	if err := s.finding.updateFindingLifecycleTx(ctx, tx, finding, now); err != nil {
		return taskflow.Finding{}, err
	}
	if err := s.postgresAssignmentEventTx(ctx, tx, id, previous, assignee.ID, actor, now); err != nil {
		return taskflow.Finding{}, err
	}
	if err := tx.Commit(); err != nil {
		return taskflow.Finding{}, fmt.Errorf("commit postgres finding assignment: %w", err)
	}
	return finding, nil
}

func (s *PostgresRuntimeStore) postgresAssignmentEventTx(ctx context.Context, tx *sql.Tx, findingID, from, to, actor string, now time.Time) error {
	eventID := "assignment-" + randomLocalID()
	if _, err := tx.ExecContext(ctx, `INSERT INTO finding_assignment_events
		(id,finding_id,from_assignee,to_assignee,actor,created_at)
		VALUES ($1,$2,$3,$4,$5,$6)`, eventID, findingID, from, to, actor, now); err != nil {
		return fmt.Errorf("insert postgres finding assignment event: %w", err)
	}
	detail, _ := json.Marshal(map[string]string{"eventId": eventID, "fromAssigneeId": from, "toAssigneeId": to})
	return s.postgresAuditTx(ctx, tx, actor, "finding_assignee_changed", "finding", findingID, string(detail))
}

func (s *PostgresRuntimeStore) BatchAssignFindings(ctx context.Context, input FindingBatchAssignment, actor string) ([]taskflow.Finding, error) {
	if !validPostgresWorkID(actor, 128) || len(input.Items) < 1 || len(input.Items) > 100 ||
		len(input.AssigneeID) > 128 || !utf8.ValidString(input.AssigneeID) ||
		strings.ContainsFunc(input.AssigneeID, unicode.IsControl) ||
		input.AssigneeID != "" && !validPostgresWorkID(input.AssigneeID, 128) {
		return nil, ErrInvalidTask
	}
	items := append([]FindingBatchAssignmentItem(nil), input.Items...)
	sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	for i, item := range items {
		if !validPostgresWorkID(item.ID, 256) || len(item.ExpectedAssigneeID) > 128 ||
			!utf8.ValidString(item.ExpectedAssigneeID) || strings.ContainsFunc(item.ExpectedAssigneeID, unicode.IsControl) ||
			i > 0 && items[i-1].ID == item.ID {
			return nil, ErrInvalidTask
		}
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin postgres finding batch assignment: %w", err)
	}
	defer tx.Rollback()
	if _, err := postgresFindingWorkUser(ctx, tx, actor); err != nil {
		return nil, err
	}
	var assignee FindingAssignee
	if input.AssigneeID != "" {
		assignee, err = postgresFindingWorkUser(ctx, tx, input.AssigneeID)
		if err != nil {
			return nil, err
		}
	}
	current := make([]taskflow.Finding, len(items))
	for i, item := range items {
		current[i], err = s.readFindingWorkTx(ctx, tx, item.ID)
		if errors.Is(err, ErrTaskNotFound) {
			return nil, ErrTaskConflict
		}
		if err != nil {
			return nil, err
		}
		if current[i].AssigneeID != item.ExpectedAssigneeID ||
			current[i].AssigneeID == assignee.ID && current[i].AssigneeName == assignee.Name {
			return nil, ErrTaskConflict
		}
	}
	updated := make(map[string]taskflow.Finding, len(items))
	now := time.Now().UTC()
	for i, item := range items {
		finding := current[i]
		previous := finding.AssigneeID
		finding.AssigneeID, finding.AssigneeName = assignee.ID, assignee.Name
		if err := s.finding.updateFindingLifecycleTx(ctx, tx, finding, now); err != nil {
			return nil, err
		}
		if err := s.postgresAssignmentEventTx(ctx, tx, item.ID, previous, assignee.ID, actor, now); err != nil {
			return nil, err
		}
		updated[item.ID] = finding
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit postgres finding batch assignment: %w", err)
	}
	result := make([]taskflow.Finding, 0, len(input.Items))
	for _, item := range input.Items {
		result = append(result, updated[item.ID])
	}
	return result, nil
}

func (s *PostgresRuntimeStore) AddFindingNote(ctx context.Context, id, body, actor string) (FindingNote, error) {
	if !validPostgresWorkID(actor, 128) || !validFindingNote(body) || strings.TrimSpace(body) == "" {
		return FindingNote{}, ErrInvalidTask
	}
	body = strings.TrimSpace(body)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return FindingNote{}, fmt.Errorf("begin postgres finding note: %w", err)
	}
	defer tx.Rollback()
	user, err := postgresFindingWorkUser(ctx, tx, actor)
	if err != nil {
		return FindingNote{}, err
	}
	if _, err := s.readFindingWorkTx(ctx, tx, id); err != nil {
		return FindingNote{}, err
	}
	note := FindingNote{ID: "note-" + randomLocalID(), FindingID: id, Actor: user.ID, ActorName: user.Name, Body: body, CreatedAt: time.Now().UTC()}
	if _, err := tx.ExecContext(ctx, `INSERT INTO finding_notes
		(id,finding_id,actor,actor_name,body,created_at)
		VALUES ($1,$2,$3,$4,$5,$6)`, note.ID, id, note.Actor, note.ActorName, note.Body, note.CreatedAt); err != nil {
		return FindingNote{}, fmt.Errorf("insert postgres finding note: %w", err)
	}
	detail, _ := json.Marshal(map[string]any{"noteId": note.ID, "bytes": len(body)})
	if err := s.postgresAuditTx(ctx, tx, actor, "finding_note_added", "finding", id, string(detail)); err != nil {
		return FindingNote{}, err
	}
	if err := tx.Commit(); err != nil {
		return FindingNote{}, fmt.Errorf("commit postgres finding note: %w", err)
	}
	return note, nil
}

func (s *PostgresRuntimeStore) findingWorkExists(ctx context.Context, id string) error {
	if !validPostgresWorkID(id, 256) {
		return ErrInvalidTask
	}
	var exists bool
	if err := s.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM security_findings WHERE id=$1)`, id).Scan(&exists); err != nil {
		return fmt.Errorf("check postgres finding: %w", err)
	}
	if !exists {
		return ErrTaskNotFound
	}
	return nil
}

func (s *PostgresRuntimeStore) ListFindingNotes(ctx context.Context, id string) ([]FindingNote, error) {
	if err := s.findingWorkExists(ctx, id); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id,finding_id,actor,actor_name,body,created_at
		FROM finding_notes WHERE finding_id=$1 ORDER BY created_at,id`, id)
	if err != nil {
		return nil, fmt.Errorf("list postgres finding notes: %w", err)
	}
	defer rows.Close()
	items := make([]FindingNote, 0)
	for rows.Next() {
		var item FindingNote
		if err := rows.Scan(&item.ID, &item.FindingID, &item.Actor, &item.ActorName, &item.Body, &item.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan postgres finding note: %w", err)
		}
		item.CreatedAt = item.CreatedAt.UTC()
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *PostgresRuntimeStore) ListFindingAssignmentEvents(ctx context.Context, id string) ([]FindingAssignmentEvent, error) {
	if err := s.findingWorkExists(ctx, id); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id,finding_id,from_assignee,to_assignee,actor,created_at
		FROM finding_assignment_events WHERE finding_id=$1 ORDER BY created_at,id`, id)
	if err != nil {
		return nil, fmt.Errorf("list postgres finding assignments: %w", err)
	}
	defer rows.Close()
	items := make([]FindingAssignmentEvent, 0)
	for rows.Next() {
		var item FindingAssignmentEvent
		if err := rows.Scan(&item.ID, &item.FindingID, &item.FromAssigneeID, &item.ToAssigneeID, &item.Actor, &item.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan postgres finding assignment: %w", err)
		}
		item.CreatedAt = item.CreatedAt.UTC()
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *PostgresRuntimeStore) BatchFindingDisposition(ctx context.Context, input FindingBatchDisposition, actor string) ([]taskflow.Finding, error) {
	now := time.Now().UTC()
	if !validPostgresWorkID(actor, 128) || len(input.Items) < 1 || len(input.Items) > 100 {
		return nil, ErrInvalidTask
	}
	reason, until, err := validateFindingDisposition(FindingDisposition{
		Status: input.Status, Reason: input.Reason, AcceptedUntil: input.AcceptedUntil,
	}, now)
	if err != nil {
		return nil, err
	}
	items := append([]FindingBatchItem(nil), input.Items...)
	sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	for i, item := range items {
		if !validPostgresWorkID(item.ID, 256) || !validPostgresFindingStatus(item.ExpectedStatus) ||
			i > 0 && items[i-1].ID == item.ID {
			return nil, ErrInvalidTask
		}
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin postgres finding batch disposition: %w", err)
	}
	defer tx.Rollback()
	current := make([]taskflow.Finding, len(items))
	for i, item := range items {
		current[i], err = s.readFindingWorkTx(ctx, tx, item.ID)
		if errors.Is(err, ErrTaskNotFound) {
			return nil, ErrTaskConflict
		}
		if err != nil {
			return nil, err
		}
		if current[i].Status != item.ExpectedStatus {
			return nil, ErrTaskConflict
		}
		if err := validateFindingTransition(current[i].Status, input.Status); err != nil {
			return nil, err
		}
	}
	updated := make(map[string]taskflow.Finding, len(items))
	for i, item := range items {
		finding := current[i]
		from := finding.Status
		finding.Status, finding.AcceptedReason, finding.AcceptedUntil = input.Status, reason, until
		finding.ResolvedAt = nil
		if err := s.finding.updateFindingLifecycleTx(ctx, tx, finding, now); err != nil {
			return nil, err
		}
		if err := recordPostgresFindingEventTx(ctx, tx, item.ID, from, input.Status, actor, reason, now); err != nil {
			return nil, err
		}
		updated[item.ID] = finding
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit postgres finding batch disposition: %w", err)
	}
	result := make([]taskflow.Finding, 0, len(input.Items))
	for _, item := range input.Items {
		result = append(result, updated[item.ID])
	}
	return result, nil
}
