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
	reason, until, err := validateFindingDisposition(in, now)
	if err != nil {
		return taskflow.Finding{}, err
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
	if err := validateFindingTransition(from, in.Status); err != nil {
		return f, err
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

// Validation is shared by single and atomic batch operations.
func validateFindingDisposition(in FindingDisposition, now time.Time) (string, *time.Time, error) {
	reason := strings.TrimSpace(in.Reason)
	var until *time.Time
	if in.Status == "ACCEPTED_RISK" {
		parsed, err := time.Parse(time.RFC3339, in.AcceptedUntil)
		if err != nil || !parsed.After(now) || parsed.After(now.Add(365*24*time.Hour)) || !utf8.ValidString(reason) || len(reason) < 1 || len(reason) > 500 || strings.ContainsFunc(reason, unicode.IsControl) {
			return "", nil, ErrInvalidTask
		}
		parsed = parsed.UTC()
		until = &parsed
	} else if in.Reason != "" || in.AcceptedUntil != "" {
		return "", nil, ErrInvalidTask
	}
	if in.Status != "OPEN" && in.Status != "IN_PROGRESS" && in.Status != "FALSE_POSITIVE" && in.Status != "ACCEPTED_RISK" {
		return "", nil, ErrInvalidTask
	}
	return reason, until, nil
}

func validateFindingTransition(from, to string) error {
	if from != "OPEN" && from != "REOPENED" && from != "IN_PROGRESS" && from != "FALSE_POSITIVE" && from != "ACCEPTED_RISK" {
		return ErrInvalidTask
	}
	if from == to || from == "ACCEPTED_RISK" && to != "OPEN" || to == "ACCEPTED_RISK" && from != "OPEN" && from != "REOPENED" && from != "IN_PROGRESS" {
		return ErrInvalidTask
	}
	return nil
}

type FindingBatchItem struct {
	ID             string `json:"id"`
	ExpectedStatus string `json:"expectedStatus"`
}
type FindingBatchDisposition struct {
	Items         []FindingBatchItem `json:"items"`
	Status        string             `json:"status"`
	Reason        string             `json:"reason,omitempty"`
	AcceptedUntil string             `json:"acceptedUntil,omitempty"`
}

// BatchFindingDisposition changes only explicit IDs. Preflight, CAS, history and
// audits share one transaction; any failure leaves the entire batch untouched.
func (s *RuntimeStore) BatchFindingDisposition(ctx context.Context, in FindingBatchDisposition, actor string) ([]taskflow.Finding, error) {
	now := time.Now().UTC()
	if strings.TrimSpace(actor) == "" || len(in.Items) < 1 || len(in.Items) > 100 {
		return nil, ErrInvalidTask
	}
	reason, until, err := validateFindingDisposition(FindingDisposition{Status: in.Status, Reason: in.Reason, AcceptedUntil: in.AcceptedUntil}, now)
	if err != nil {
		return nil, err
	}
	items := append([]FindingBatchItem(nil), in.Items...)
	sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	for i, item := range items {
		if strings.TrimSpace(item.ID) == "" || item.ID != strings.TrimSpace(item.ID) || len(item.ID) > 256 || !utf8.ValidString(item.ID) || strings.ContainsFunc(item.ID, unicode.IsControl) || i > 0 && items[i-1].ID == item.ID {
			return nil, ErrInvalidTask
		}
		if item.ExpectedStatus != "OPEN" && item.ExpectedStatus != "REOPENED" && item.ExpectedStatus != "IN_PROGRESS" && item.ExpectedStatus != "FIXED" && item.ExpectedStatus != "FALSE_POSITIVE" && item.ExpectedStatus != "ACCEPTED_RISK" {
			return nil, ErrInvalidTask
		}
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	type entry struct {
		raw     string
		finding taskflow.Finding
	}
	entries := make([]entry, len(items))
	for i, item := range items {
		if err := tx.QueryRowContext(ctx, `SELECT data FROM security_findings WHERE id=?`, item.ID).Scan(&entries[i].raw); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return nil, ErrTaskConflict
			}
			return nil, err
		}
		if err := json.Unmarshal([]byte(entries[i].raw), &entries[i].finding); err != nil {
			return nil, err
		}
		f := entries[i].finding
		if f.Status != item.ExpectedStatus {
			return nil, ErrTaskConflict
		}
		if err := validateFindingTransition(f.Status, in.Status); err != nil {
			return nil, err
		}
	}
	updated := make([]taskflow.Finding, 0, len(items))
	for i, item := range items {
		f := entries[i].finding
		from := f.Status
		f.Status = in.Status
		f.AcceptedReason = reason
		f.AcceptedUntil = until
		encoded, err := json.Marshal(f)
		if err != nil {
			return nil, err
		}
		result, err := tx.ExecContext(ctx, `UPDATE security_findings SET data=? WHERE id=? AND data=?`, string(encoded), item.ID, entries[i].raw)
		if err != nil {
			return nil, err
		}
		n, err := result.RowsAffected()
		if err != nil {
			return nil, err
		}
		if n != 1 {
			return nil, ErrTaskConflict
		}
		if err := recordFindingEvent(ctx, tx, item.ID, from, in.Status, actor, reason, now); err != nil {
			return nil, err
		}
		updated = append(updated, f)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit finding batch: %w", err)
	}
	return updated, nil
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
