package repo

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"scanner-platform/internal/taskflow"
)

// FindingAssignee deliberately exposes no account credentials or administrative fields.
type FindingAssignee struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type FindingNote struct {
	ID        string    `json:"id"`
	FindingID string    `json:"findingId"`
	Actor     string    `json:"actor"`
	ActorName string    `json:"actorName"`
	Body      string    `json:"body"`
	CreatedAt time.Time `json:"createdAt"`
}

type FindingAssignmentEvent struct {
	ID             string    `json:"id"`
	FindingID      string    `json:"findingId"`
	FromAssigneeID string    `json:"fromAssigneeId,omitempty"`
	ToAssigneeID   string    `json:"toAssigneeId,omitempty"`
	Actor          string    `json:"actor"`
	CreatedAt      time.Time `json:"createdAt"`
}

type FindingBatchAssignmentItem struct {
	ID                 string `json:"id"`
	ExpectedAssigneeID string `json:"expectedAssigneeId"`
}

type FindingBatchAssignment struct {
	Items      []FindingBatchAssignmentItem `json:"items"`
	AssigneeID string                       `json:"assigneeId"`
}

func (s *RuntimeStore) initFindingWork(ctx context.Context) error {
	for _, query := range []string{
		`CREATE TABLE IF NOT EXISTS finding_notes(id TEXT PRIMARY KEY,finding_id TEXT NOT NULL REFERENCES security_findings(id) ON DELETE CASCADE,actor TEXT NOT NULL,actor_name TEXT NOT NULL,body TEXT NOT NULL,created_at TEXT NOT NULL)`,
		`CREATE INDEX IF NOT EXISTS finding_notes_history ON finding_notes(finding_id,created_at,id)`,
		`CREATE TABLE IF NOT EXISTS finding_assignment_events(id TEXT PRIMARY KEY,finding_id TEXT NOT NULL REFERENCES security_findings(id) ON DELETE CASCADE,from_assignee TEXT NOT NULL,to_assignee TEXT NOT NULL,actor TEXT NOT NULL,created_at TEXT NOT NULL)`,
	} {
		if _, err := s.db.ExecContext(ctx, query); err != nil {
			return err
		}
	}
	return nil
}

func (s *RuntimeStore) ListFindingAssignees(ctx context.Context) ([]FindingAssignee, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,username FROM users WHERE is_active=1 AND role IN ('admin','security_engineer') ORDER BY username,id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []FindingAssignee{}
	for rows.Next() {
		var item FindingAssignee
		if err := rows.Scan(&item.ID, &item.Name); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

// Resolve users inside the same transaction as the write, so a disabled user
// cannot slip through a preflight check. Local databases without accounts fail closed.
func findingWorkUser(ctx context.Context, tx *sql.Tx, id string) (FindingAssignee, error) {
	var item FindingAssignee
	err := tx.QueryRowContext(ctx, `SELECT id,username FROM users WHERE id=? AND is_active=1 AND role IN ('admin','security_engineer')`, id).Scan(&item.ID, &item.Name)
	if errors.Is(err, sql.ErrNoRows) {
		return item, ErrInvalidTask
	}
	return item, err
}
func findingWorkRecord(ctx context.Context, tx *sql.Tx, id string) (taskflow.Finding, string, error) {
	var f taskflow.Finding
	var raw string
	if err := tx.QueryRowContext(ctx, `SELECT data FROM security_findings WHERE id=?`, id).Scan(&raw); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return f, raw, ErrTaskNotFound
		}
		return f, raw, err
	}
	err := json.Unmarshal([]byte(raw), &f)
	return f, raw, err
}

func (s *RuntimeStore) AssignFinding(ctx context.Context, id, assigneeID, actor string) (taskflow.Finding, error) {
	var f taskflow.Finding
	if actor == "" || len(assigneeID) > 128 || strings.ContainsFunc(assigneeID, unicode.IsControl) {
		return f, ErrInvalidTask
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return f, err
	}
	defer tx.Rollback()
	if _, err := findingWorkUser(ctx, tx, actor); err != nil {
		return f, err
	}
	var assignee FindingAssignee
	if assigneeID != "" {
		assignee, err = findingWorkUser(ctx, tx, assigneeID)
		if err != nil {
			return f, err
		}
	}
	f, raw, err := findingWorkRecord(ctx, tx, id)
	if err != nil {
		return f, err
	}
	if f.AssigneeID == assignee.ID && f.AssigneeName == assignee.Name {
		return f, ErrInvalidTask
	}
	previous := f.AssigneeID
	f.AssigneeID, f.AssigneeName = assignee.ID, assignee.Name
	data, err := json.Marshal(f)
	if err != nil {
		return f, err
	}
	result, err := tx.ExecContext(ctx, `UPDATE security_findings SET data=? WHERE id=? AND data=?`, string(data), id, raw)
	if err != nil {
		return f, err
	}
	if n, _ := result.RowsAffected(); n != 1 {
		return f, ErrTaskConflict
	}
	eventID := "assignment-" + randomLocalID()
	if _, err = tx.ExecContext(ctx, `INSERT INTO finding_assignment_events(id,finding_id,from_assignee,to_assignee,actor,created_at) VALUES(?,?,?,?,?,?)`, eventID, id, previous, assignee.ID, actor, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		return f, err
	}
	detail, _ := json.Marshal(map[string]string{"eventId": eventID, "fromAssigneeId": previous, "toAssigneeId": assignee.ID})
	if err := logLocal(ctx, tx, actor, "finding_assignee_changed", "finding", id, string(detail)); err != nil {
		return f, err
	}
	return f, tx.Commit()
}

func validFindingNote(body string) bool {
	return utf8.ValidString(body) && len(body) >= 1 && len(body) <= 2000 && !strings.ContainsFunc(body, func(r rune) bool { return unicode.IsControl(r) || r == '\u2028' || r == '\u2029' })
}
func (s *RuntimeStore) AddFindingNote(ctx context.Context, id, body, actor string) (FindingNote, error) {
	var note FindingNote
	// Validate before trimming: forbidden control characters cannot disappear at the boundary.
	if !validFindingNote(body) || strings.TrimSpace(body) == "" || actor == "" {
		return note, ErrInvalidTask
	}
	body = strings.TrimSpace(body)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return note, err
	}
	defer tx.Rollback()
	user, err := findingWorkUser(ctx, tx, actor)
	if err != nil {
		return note, err
	}
	if _, _, err := findingWorkRecord(ctx, tx, id); err != nil {
		return note, err
	}
	note = FindingNote{ID: "note-" + randomLocalID(), FindingID: id, Actor: user.ID, ActorName: user.Name, Body: body, CreatedAt: time.Now().UTC()}
	if _, err := tx.ExecContext(ctx, `INSERT INTO finding_notes(id,finding_id,actor,actor_name,body,created_at) VALUES(?,?,?,?,?,?)`, note.ID, id, note.Actor, note.ActorName, note.Body, note.CreatedAt.Format(time.RFC3339Nano)); err != nil {
		return note, err
	}
	detail, _ := json.Marshal(map[string]any{"noteId": note.ID, "bytes": len(body)})
	if err := logLocal(ctx, tx, actor, "finding_note_added", "finding", id, string(detail)); err != nil {
		return note, err
	}
	return note, tx.Commit()
}
func (s *RuntimeStore) ListFindingNotes(ctx context.Context, id string) ([]FindingNote, error) {
	var exists int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM security_findings WHERE id=?`, id).Scan(&exists); err != nil {
		return nil, err
	}
	if exists == 0 {
		return nil, ErrTaskNotFound
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id,finding_id,actor,actor_name,body,created_at FROM finding_notes WHERE finding_id=? ORDER BY created_at,id`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []FindingNote{}
	for rows.Next() {
		var item FindingNote
		var timestamp string
		if err := rows.Scan(&item.ID, &item.FindingID, &item.Actor, &item.ActorName, &item.Body, &timestamp); err != nil {
			return nil, err
		}
		item.CreatedAt, err = time.Parse(time.RFC3339Nano, timestamp)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *RuntimeStore) ListFindingAssignmentEvents(ctx context.Context, id string) ([]FindingAssignmentEvent, error) {
	var exists int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM security_findings WHERE id=?`, id).Scan(&exists); err != nil {
		return nil, err
	}
	if exists == 0 {
		return nil, ErrTaskNotFound
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id,finding_id,from_assignee,to_assignee,actor,created_at
FROM finding_assignment_events WHERE finding_id=? ORDER BY created_at,id`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []FindingAssignmentEvent{}
	for rows.Next() {
		var item FindingAssignmentEvent
		var timestamp string
		if err := rows.Scan(&item.ID, &item.FindingID, &item.FromAssigneeID, &item.ToAssigneeID, &item.Actor, &timestamp); err != nil {
			return nil, err
		}
		item.CreatedAt, err = time.Parse(time.RFC3339Nano, timestamp)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

// BatchAssignFindings updates only the explicitly selected findings. The
// expected assignee snapshot makes stale UI selections fail closed, while the
// single transaction prevents a partial assignment batch.
func (s *RuntimeStore) BatchAssignFindings(ctx context.Context, in FindingBatchAssignment, actor string) ([]taskflow.Finding, error) {
	if actor == "" || len(in.Items) == 0 || len(in.Items) > 100 || len(in.AssigneeID) > 128 || strings.ContainsFunc(in.AssigneeID, unicode.IsControl) {
		return nil, ErrInvalidTask
	}
	items := append([]FindingBatchAssignmentItem(nil), in.Items...)
	seen := make(map[string]bool, len(items))
	for _, item := range items {
		if strings.TrimSpace(item.ID) == "" || len(item.ID) > 256 || seen[item.ID] || len(item.ExpectedAssigneeID) > 128 || strings.ContainsFunc(item.ExpectedAssigneeID, unicode.IsControl) {
			return nil, ErrInvalidTask
		}
		seen[item.ID] = true
	}
	sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if _, err := findingWorkUser(ctx, tx, actor); err != nil {
		return nil, err
	}
	var assignee FindingAssignee
	if in.AssigneeID != "" {
		assignee, err = findingWorkUser(ctx, tx, in.AssigneeID)
		if err != nil {
			return nil, err
		}
	}
	updated := make(map[string]taskflow.Finding, len(items))
	for _, item := range items {
		finding, raw, err := findingWorkRecord(ctx, tx, item.ID)
		if err != nil {
			return nil, err
		}
		if finding.AssigneeID != item.ExpectedAssigneeID || (finding.AssigneeID == assignee.ID && finding.AssigneeName == assignee.Name) {
			return nil, ErrTaskConflict
		}
		previous := finding.AssigneeID
		finding.AssigneeID, finding.AssigneeName = assignee.ID, assignee.Name
		data, err := json.Marshal(finding)
		if err != nil {
			return nil, err
		}
		result, err := tx.ExecContext(ctx, `UPDATE security_findings SET data=? WHERE id=? AND data=?`, string(data), item.ID, raw)
		if err != nil {
			return nil, err
		}
		if n, _ := result.RowsAffected(); n != 1 {
			return nil, ErrTaskConflict
		}
		eventID := "assignment-" + randomLocalID()
		createdAt := time.Now().UTC().Format(time.RFC3339Nano)
		if _, err := tx.ExecContext(ctx, `INSERT INTO finding_assignment_events(id,finding_id,from_assignee,to_assignee,actor,created_at) VALUES(?,?,?,?,?,?)`, eventID, item.ID, previous, assignee.ID, actor, createdAt); err != nil {
			return nil, err
		}
		detail, _ := json.Marshal(map[string]string{"eventId": eventID, "fromAssigneeId": previous, "toAssigneeId": assignee.ID})
		if err := logLocal(ctx, tx, actor, "finding_assignee_changed", "finding", item.ID, string(detail)); err != nil {
			return nil, err
		}
		updated[item.ID] = finding
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	result := make([]taskflow.Finding, 0, len(items))
	for _, item := range in.Items {
		result = append(result, updated[item.ID])
	}
	return result, nil
}
