package repo

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"scanner-platform/internal/taskflow"
)

// FindingDisposition is UI input. Engine reports cannot set these fields.
type FindingDisposition struct {
	Status        string `json:"status"`
	Reason        string `json:"reason,omitempty"`
	AcceptedUntil string `json:"acceptedUntil,omitempty"`
}

type FindingEvent struct {
	ID         string    `json:"id"`
	FindingID  string    `json:"findingId"`
	FromStatus string    `json:"fromStatus"`
	ToStatus   string    `json:"toStatus"`
	Actor      string    `json:"actor"`
	Reason     string    `json:"reason,omitempty"`
	CreatedAt  time.Time `json:"createdAt"`
}

func (s *RuntimeStore) initFindingEvents(ctx context.Context) error {
	for _, q := range []string{
		`CREATE TABLE IF NOT EXISTS finding_events(id TEXT PRIMARY KEY,finding_id TEXT NOT NULL REFERENCES security_findings(id) ON DELETE CASCADE,from_status TEXT NOT NULL,to_status TEXT NOT NULL,actor TEXT NOT NULL,reason TEXT NOT NULL DEFAULT '',created_at TEXT NOT NULL)`,
		`CREATE INDEX IF NOT EXISTS finding_events_history ON finding_events(finding_id,created_at,id)`,
	} {
		if _, err := s.db.ExecContext(ctx, q); err != nil {
			return err
		}
	}
	return nil
}

func recordFindingEvent(ctx context.Context, tx *sql.Tx, findingID, from, to, actor, reason string, now time.Time) error {
	id := "event-" + randomLocalID()
	if _, err := tx.ExecContext(ctx, `INSERT INTO finding_events(id,finding_id,from_status,to_status,actor,reason,created_at) VALUES(?,?,?,?,?,?,?)`, id, findingID, from, to, actor, reason, now.UTC().Format(time.RFC3339Nano)); err != nil {
		return err
	}
	// Reasons can contain sensitive business context; audit records only link to the event.
	detail, _ := json.Marshal(map[string]string{"eventId": id, "fromStatus": from, "toStatus": to})
	return logLocal(ctx, tx, actor, "finding_status_changed", "finding", findingID, string(detail))
}

func (s *RuntimeStore) UpdateFinding(ctx context.Context, id, status, actor string) (taskflow.Finding, error) {
	return s.UpdateFindingDisposition(ctx, id, FindingDisposition{Status: status}, actor)
}

func (s *RuntimeStore) UpdateFindingDisposition(ctx context.Context, id string, in FindingDisposition, actor string) (taskflow.Finding, error) {
	now := time.Now().UTC()
	if strings.TrimSpace(actor) == "" {
		return taskflow.Finding{}, ErrInvalidTask
	}
	reason := strings.TrimSpace(in.Reason)
	var until *time.Time
	if in.Status == "ACCEPTED_RISK" {
		parsed, err := time.Parse(time.RFC3339, in.AcceptedUntil)
		if err != nil || !parsed.After(now) || parsed.After(now.Add(365*24*time.Hour)) || !utf8.ValidString(reason) || len(reason) < 1 || len(reason) > 500 || strings.ContainsFunc(reason, unicode.IsControl) {
			return taskflow.Finding{}, ErrInvalidTask
		}
		parsed = parsed.UTC()
		until = &parsed
	} else if in.Reason != "" || in.AcceptedUntil != "" {
		return taskflow.Finding{}, ErrInvalidTask
	}
	if in.Status != "OPEN" && in.Status != "IN_PROGRESS" && in.Status != "FALSE_POSITIVE" && in.Status != "ACCEPTED_RISK" {
		return taskflow.Finding{}, ErrInvalidTask
	}
	if err := s.ExpireAcceptedRisks(ctx, now); err != nil {
		return taskflow.Finding{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return taskflow.Finding{}, err
	}
	defer tx.Rollback()
	var raw string
	var f taskflow.Finding
	if err := tx.QueryRowContext(ctx, `SELECT data FROM security_findings WHERE id=?`, id).Scan(&raw); err != nil {
		return f, ErrTaskConflict
	}
	if err := json.Unmarshal([]byte(raw), &f); err != nil {
		return f, err
	}
	from := f.Status
	if from == in.Status || from == "FIXED" || from == "ACCEPTED_RISK" && in.Status != "OPEN" || in.Status == "ACCEPTED_RISK" && from != "OPEN" && from != "REOPENED" && from != "IN_PROGRESS" {
		return f, ErrInvalidTask
	}
	f.Status = in.Status
	f.AcceptedReason = reason
	f.AcceptedUntil = until
	encoded, err := json.Marshal(f)
	if err != nil {
		return f, err
	}
	result, err := tx.ExecContext(ctx, `UPDATE security_findings SET data=? WHERE id=? AND data=?`, string(encoded), id, raw)
	if err != nil {
		return f, err
	}
	if n, _ := result.RowsAffected(); n != 1 {
		return f, ErrTaskConflict
	}
	if err := recordFindingEvent(ctx, tx, id, from, in.Status, actor, reason, now); err != nil {
		return f, err
	}
	return f, tx.Commit()
}

// ExpireAcceptedRisks also repairs legacy indefinite acceptance. Conditional
// updates make concurrent list/tick/manual requests create exactly one event.
func (s *RuntimeStore) ExpireAcceptedRisks(ctx context.Context, now time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT id,data FROM security_findings WHERE json_extract(data,'$.status')='ACCEPTED_RISK'`)
	if err != nil {
		return err
	}
	type entry struct{ id, raw string }
	items := []entry{}
	for rows.Next() {
		var item entry
		if err := rows.Scan(&item.id, &item.raw); err != nil {
			rows.Close()
			return err
		}
		items = append(items, item)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, item := range items {
		f, err := findingForExpiry(item.raw)
		if err != nil {
			return err
		}
		if f.AcceptedUntil != nil && f.AcceptedUntil.After(now) {
			continue
		}
		f.Status = "OPEN"
		f.AcceptedReason = ""
		f.AcceptedUntil = nil
		data, err := json.Marshal(f)
		if err != nil {
			return err
		}
		result, err := tx.ExecContext(ctx, `UPDATE security_findings SET data=? WHERE id=? AND data=?`, string(data), item.id, item.raw)
		if err != nil {
			return err
		}
		if n, _ := result.RowsAffected(); n == 1 {
			if err := recordFindingEvent(ctx, tx, item.id, "ACCEPTED_RISK", "OPEN", "system", "接受风险已到期或缺少有效期限", now); err != nil {
				return err
			}
		}
	}
	return tx.Commit()
}

// findingForExpiry tolerates a malformed legacy acceptedUntil field. Such a
// record is treated as an acceptance without a valid expiry and is reopened;
// malformed unrelated finding data still fails closed instead of being
// rewritten.
func findingForExpiry(raw string) (taskflow.Finding, error) {
	var finding taskflow.Finding
	if err := json.Unmarshal([]byte(raw), &finding); err == nil {
		return finding, nil
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &object); err != nil {
		return finding, err
	}
	if _, ok := object["acceptedUntil"]; !ok {
		if err := json.Unmarshal([]byte(raw), &finding); err != nil {
			return finding, err
		}
		return finding, nil
	}
	delete(object, "acceptedUntil")
	normalized, err := json.Marshal(object)
	if err != nil {
		return finding, err
	}
	if err := json.Unmarshal(normalized, &finding); err != nil {
		return finding, err
	}
	return finding, nil
}

func (s *RuntimeStore) ListFindingEvents(ctx context.Context, id string) ([]FindingEvent, error) {
	if err := s.ExpireAcceptedRisks(ctx, time.Now().UTC()); err != nil {
		return nil, err
	}
	var exists int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM security_findings WHERE id=?`, id).Scan(&exists); err != nil {
		return nil, err
	}
	if exists != 1 {
		return nil, ErrTaskConflict
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id,finding_id,from_status,to_status,actor,reason,created_at FROM finding_events WHERE finding_id=? ORDER BY created_at,id`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []FindingEvent{}
	for rows.Next() {
		var e FindingEvent
		var timestamp string
		if err := rows.Scan(&e.ID, &e.FindingID, &e.FromStatus, &e.ToStatus, &e.Actor, &e.Reason, &timestamp); err != nil {
			return nil, err
		}
		e.CreatedAt, err = time.Parse(time.RFC3339Nano, timestamp)
		if err != nil {
			return nil, err
		}
		items = append(items, e)
	}
	return items, rows.Err()
}
