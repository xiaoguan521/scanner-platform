package repo

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"scanner-platform/internal/findings"
	"scanner-platform/internal/taskflow"
)

var (
	ErrPostgresFindingInvalid = errors.New("invalid postgres finding")
	ErrPostgresFindingMissing = errors.New("postgres finding is missing")
)

// PostgresFindingStore keeps lifecycle columns authoritative while retaining a
// bounded portable JSON projection for the existing Server API. It is owned by
// sec-server; Worker only submits normalized reports through the node API.
type PostgresFindingStore struct {
	db  *sql.DB
	now func() time.Time
}

func NewPostgresFindingStore(db *sql.DB) (*PostgresFindingStore, error) {
	if db == nil {
		return nil, ErrPostgresDSNRequired
	}
	return &PostgresFindingStore{db: db, now: time.Now}, nil
}

func (s *PostgresFindingStore) currentTime() time.Time {
	if s.now != nil {
		return s.now().UTC()
	}
	return time.Now().UTC()
}

// SaveFinding records one normalized detection. The caller must provide the
// Server-computed stable fingerprint; this method never hashes request/response
// evidence or other dynamic material.
func (s *PostgresFindingStore) SaveFinding(ctx context.Context, input taskflow.Finding) (taskflow.Finding, error) {
	if s == nil || s.db == nil {
		return taskflow.Finding{}, ErrPostgresFindingInvalid
	}
	now := s.currentTime()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return taskflow.Finding{}, fmt.Errorf("begin postgres finding: %w", err)
	}
	defer tx.Rollback()
	finding, err := s.SaveFindingTx(ctx, tx, input, now)
	if err != nil {
		return taskflow.Finding{}, err
	}
	if err := tx.Commit(); err != nil {
		return taskflow.Finding{}, fmt.Errorf("commit postgres finding: %w", err)
	}
	return finding, nil
}

// SaveFindingTx is the transaction form used by Server task completion. It
// keeps a finding observation and the terminal task state in one commit.
func (s *PostgresFindingStore) SaveFindingTx(ctx context.Context, tx *sql.Tx, input taskflow.Finding, now time.Time) (taskflow.Finding, error) {
	if s == nil || tx == nil {
		return taskflow.Finding{}, ErrPostgresFindingInvalid
	}
	finding, err := normalizePostgresFinding(input, now)
	if err != nil {
		return taskflow.Finding{}, err
	}

	var existingID, lifecycle string
	var firstSeen sql.NullTime
	var raw sql.NullString
	err = tx.QueryRowContext(ctx, `SELECT sf.id,sf.lifecycle_status,sf.first_seen_at,
		fp.data FROM security_findings sf
		LEFT JOIN finding_projections fp ON fp.finding_id=sf.id
		WHERE sf.asset_id=$1 AND sf.fingerprint_hash=$2
		FOR UPDATE OF sf`, finding.AssetID, finding.Fingerprint).Scan(
		&existingID, &lifecycle, &firstSeen, &raw)
	if errors.Is(err, sql.ErrNoRows) {
		finding.Status = "OPEN"
		finding.FirstSeen = now
		finding.LastSeen = now
		if err := s.insertFindingTx(ctx, tx, finding, now); err != nil {
			return taskflow.Finding{}, err
		}
	} else if err != nil {
		return taskflow.Finding{}, fmt.Errorf("read postgres finding identity: %w", err)
	} else {
		if !raw.Valid || raw.String == "" {
			return taskflow.Finding{}, ErrPostgresFindingMissing
		}
		var previous taskflow.Finding
		if err := json.Unmarshal([]byte(raw.String), &previous); err != nil {
			return taskflow.Finding{}, fmt.Errorf("decode postgres finding projection: %w", err)
		}
		finding.ID = existingID
		finding.Status = lifecycle
		if firstSeen.Valid {
			finding.FirstSeen = firstSeen.Time.UTC()
		} else if !previous.FirstSeen.IsZero() {
			finding.FirstSeen = previous.FirstSeen
		}
		finding.LastSeen = now
		finding.ConsecutiveMisses = 0
		finding.VerifiedInRun = true
		finding.AcceptedReason = previous.AcceptedReason
		finding.AcceptedUntil = previous.AcceptedUntil
		finding.AssigneeID = previous.AssigneeID
		finding.AssigneeName = previous.AssigneeName
		finding.ResolvedAt = nil
		if lifecycle == "FIXED" {
			finding.Status = "REOPENED"
			if err := recordPostgresFindingEventTx(ctx, tx, finding.ID, "FIXED", "REOPENED", "system", "扫描再次检出", now); err != nil {
				return taskflow.Finding{}, err
			}
		}
		if err := s.updateFindingTx(ctx, tx, finding, now); err != nil {
			return taskflow.Finding{}, err
		}
	}
	return finding, nil
}

func normalizePostgresFinding(input taskflow.Finding, now time.Time) (taskflow.Finding, error) {
	if strings.TrimSpace(input.ID) == "" || len(input.ID) > 256 ||
		strings.ContainsAny(input.ID, "\x00\r\n") || strings.TrimSpace(input.TaskID) == "" ||
		len(input.TaskID) > 128 || strings.TrimSpace(input.AssetID) == "" ||
		len(input.AssetID) > 128 || strings.TrimSpace(input.Fingerprint) == "" ||
		len(input.Fingerprint) != sha256.Size*2 {
		return taskflow.Finding{}, ErrPostgresFindingInvalid
	}
	if _, err := hex.DecodeString(input.Fingerprint); err != nil {
		return taskflow.Finding{}, ErrPostgresFindingInvalid
	}
	if input.Status != "" && !validPostgresFindingStatus(input.Status) ||
		input.Severity != "CRITICAL" && input.Severity != "HIGH" && input.Severity != "MEDIUM" && input.Severity != "LOW" && input.Severity != "INFO" {
		return taskflow.Finding{}, ErrPostgresFindingInvalid
	}
	if input.FirstSeen.IsZero() {
		input.FirstSeen = now
	}
	if input.LastSeen.IsZero() {
		input.LastSeen = now
	}
	if input.LastSeen.Before(input.FirstSeen) || input.Title == "" || len(input.Title) > 500 || input.Engine == "" || input.TemplateOrCVE == "" || input.Target == "" {
		return taskflow.Finding{}, ErrPostgresFindingInvalid
	}
	input = findings.Upgrade(input)
	encoded, err := json.Marshal(input)
	if err != nil || len(encoded) > 1<<20 {
		return taskflow.Finding{}, ErrPostgresFindingInvalid
	}
	return input, nil
}

func validPostgresFindingStatus(value string) bool {
	switch value {
	case "OPEN", "REOPENED", "IN_PROGRESS", "FIXED", "FALSE_POSITIVE", "ACCEPTED_RISK":
		return true
	default:
		return false
	}
}

func findingProjectionJSON(finding taskflow.Finding) (string, error) {
	data, err := json.Marshal(finding)
	if err != nil || len(data) > 1<<20 {
		return "", ErrPostgresFindingInvalid
	}
	return string(data), nil
}

func findingEvidenceJSON(finding taskflow.Finding) (string, error) {
	data, err := json.Marshal(map[string]any{"evidence": finding.Evidence})
	if err != nil {
		return "", ErrPostgresFindingInvalid
	}
	return string(data), nil
}

func (s *PostgresFindingStore) insertFindingTx(ctx context.Context, tx *sql.Tx, finding taskflow.Finding, now time.Time) error {
	projection, err := findingProjectionJSON(finding)
	if err != nil {
		return err
	}
	evidence, err := findingEvidenceJSON(finding)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO security_findings
		(id,asset_id,fingerprint_hash,engine_name,rule_id,severity,title,location,
		evidence_json,lifecycle_status,accepted_until,first_seen_task_id,last_seen_task_id,
		first_seen_at,last_seen_at,resolved_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$12,$13,$13,$14)`,
		finding.ID, finding.AssetID, finding.Fingerprint, finding.Engine,
		finding.TemplateOrCVE, finding.Severity, finding.Title, finding.Target,
		evidence, finding.Status, finding.AcceptedUntil, finding.TaskID,
		finding.FirstSeen, finding.ResolvedAt); err != nil {
		return fmt.Errorf("insert postgres finding: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO finding_projections
		(finding_id,task_id,data,updated_at) VALUES ($1,$2,$3,$4)`, finding.ID,
		finding.TaskID, projection, now); err != nil {
		return fmt.Errorf("insert postgres finding projection: %w", err)
	}
	return s.saveObservationTx(ctx, tx, finding)
}

func (s *PostgresFindingStore) updateFindingTx(ctx context.Context, tx *sql.Tx, finding taskflow.Finding, now time.Time) error {
	projection, err := findingProjectionJSON(finding)
	if err != nil {
		return err
	}
	evidence, err := findingEvidenceJSON(finding)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE security_findings SET engine_name=$1,
		rule_id=$2,severity=$3,title=$4,location=$5,evidence_json=$6,
		lifecycle_status=$7,accepted_until=$8,last_seen_task_id=$9,last_seen_at=$10,
		resolved_at=$11 WHERE id=$12`, finding.Engine, finding.TemplateOrCVE,
		finding.Severity, finding.Title, finding.Target, evidence, finding.Status,
		finding.AcceptedUntil, finding.TaskID, finding.LastSeen, finding.ResolvedAt,
		finding.ID); err != nil {
		return fmt.Errorf("update postgres finding: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE finding_projections
		SET task_id=$1,data=$2,updated_at=$3 WHERE finding_id=$4`, finding.TaskID,
		projection, now, finding.ID); err != nil {
		return fmt.Errorf("update postgres finding projection: %w", err)
	}
	return s.saveObservationTx(ctx, tx, finding)
}

// updateFindingLifecycleTx changes only the current normalized lifecycle and
// API projection. It deliberately does not write task_finding_observations:
// manual disposition and missing-finding convergence are not observations in
// a scan task.
func (s *PostgresFindingStore) updateFindingLifecycleTx(ctx context.Context, tx *sql.Tx, finding taskflow.Finding, now time.Time) error {
	projection, err := findingProjectionJSON(finding)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE security_findings SET lifecycle_status=$1,
		accepted_until=$2,resolved_at=$3 WHERE id=$4`, finding.Status,
		finding.AcceptedUntil, finding.ResolvedAt, finding.ID); err != nil {
		return fmt.Errorf("update postgres finding lifecycle: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE finding_projections
		SET data=$1,updated_at=$2 WHERE finding_id=$3`, projection, now, finding.ID); err != nil {
		return fmt.Errorf("update postgres finding lifecycle projection: %w", err)
	}
	return nil
}

func (s *PostgresFindingStore) saveObservationTx(ctx context.Context, tx *sql.Tx, finding taskflow.Finding) error {
	projection, err := findingProjectionJSON(finding)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO task_finding_observations
		(task_id,finding_id,data) VALUES ($1,$2,$3)
		ON CONFLICT(task_id,finding_id) DO UPDATE SET data=EXCLUDED.data`,
		finding.TaskID, finding.ID, projection); err != nil {
		return fmt.Errorf("save postgres finding observation: %w", err)
	}
	return nil
}

// Get returns the portable finding projection with normalized lifecycle fields
// overlaid so malformed/stale JSON cannot change status or timestamps.
func (s *PostgresFindingStore) Get(ctx context.Context, id string) (taskflow.Finding, error) {
	if s == nil || s.db == nil || strings.TrimSpace(id) == "" || len(id) > 256 {
		return taskflow.Finding{}, ErrPostgresFindingInvalid
	}
	var f taskflow.Finding
	var raw, status, assetID, fingerprint, taskID string
	var accepted, firstSeen, lastSeen, resolved sql.NullTime
	err := s.db.QueryRowContext(ctx, `SELECT sf.asset_id,sf.fingerprint_hash,sf.lifecycle_status,
		sf.accepted_until,sf.first_seen_at,sf.last_seen_at,sf.resolved_at,
		fp.task_id,fp.data FROM security_findings sf
		JOIN finding_projections fp ON fp.finding_id=sf.id WHERE sf.id=$1`, id).Scan(
		&assetID, &fingerprint, &status, &accepted, &firstSeen, &lastSeen,
		&resolved, &taskID, &raw)
	if errors.Is(err, sql.ErrNoRows) {
		return taskflow.Finding{}, ErrPostgresFindingMissing
	}
	if err != nil {
		return taskflow.Finding{}, fmt.Errorf("read postgres finding: %w", err)
	}
	if err := json.Unmarshal([]byte(raw), &f); err != nil {
		return taskflow.Finding{}, fmt.Errorf("decode postgres finding: %w", err)
	}
	f.ID, f.AssetID, f.Fingerprint, f.Status, f.TaskID = id, assetID, fingerprint, status, taskID
	if accepted.Valid {
		value := accepted.Time.UTC()
		f.AcceptedUntil = &value
	} else {
		f.AcceptedUntil = nil
	}
	if firstSeen.Valid {
		f.FirstSeen = firstSeen.Time.UTC()
	}
	if lastSeen.Valid {
		f.LastSeen = lastSeen.Time.UTC()
	}
	if resolved.Valid {
		value := resolved.Time.UTC()
		f.ResolvedAt = &value
	} else {
		f.ResolvedAt = nil
	}
	return findings.Upgrade(f), nil
}

// ListTaskFindings returns immutable observations for one completed task.
func (s *PostgresFindingStore) ListTaskFindings(ctx context.Context, taskID string) ([]taskflow.Finding, error) {
	if s == nil || s.db == nil || strings.TrimSpace(taskID) == "" || len(taskID) > 128 {
		return nil, ErrPostgresFindingInvalid
	}
	rows, err := s.db.QueryContext(ctx, `SELECT data FROM task_finding_observations
		WHERE task_id=$1 ORDER BY finding_id`, taskID)
	if err != nil {
		return nil, fmt.Errorf("list postgres task findings: %w", err)
	}
	defer rows.Close()
	items := make([]taskflow.Finding, 0)
	for rows.Next() {
		var raw string
		var finding taskflow.Finding
		if err := rows.Scan(&raw); err != nil {
			return nil, fmt.Errorf("scan postgres task finding: %w", err)
		}
		if err := json.Unmarshal([]byte(raw), &finding); err != nil {
			return nil, fmt.Errorf("decode postgres task finding: %w", err)
		}
		items = append(items, findings.Upgrade(finding))
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate postgres task findings: %w", err)
	}
	return items, nil
}

// ListPage implements the bounded Server-side finding list contract with
// fixed SQL fragments and PostgreSQL placeholders; user input only becomes a
// bound value.
func (s *PostgresFindingStore) ListPage(ctx context.Context, in FindingListQuery) (FindingListPage, error) {
	if s == nil || s.db == nil {
		return FindingListPage{}, ErrPostgresFindingInvalid
	}
	query, err := NormalizeFindingListQuery(in)
	if err != nil {
		return FindingListPage{}, err
	}
	where, args := postgresFindingWhere(query)
	from := ` FROM security_findings sf JOIN finding_projections fp ON fp.finding_id=sf.id
		JOIN assets a ON a.id=sf.asset_id WHERE ` + where
	var total int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*)`+from, args...).Scan(&total); err != nil {
		return FindingListPage{}, fmt.Errorf("count postgres findings: %w", err)
	}
	counts, err := s.postgresFindingCounts(ctx, from, args)
	if err != nil {
		return FindingListPage{}, err
	}
	sortExpr, direction := postgresFindingSort(query.Sort)
	selectSQL := `SELECT fp.data,sf.asset_id,sf.fingerprint_hash,sf.lifecycle_status,
		sf.accepted_until,sf.first_seen_at,sf.last_seen_at,sf.resolved_at,fp.task_id` + from +
		` ORDER BY ` + sortExpr + ` ` + direction + `,sf.id ASC`
	queryArgs := append([]any(nil), args...)
	pageSize := query.PageSize
	if pageSize > 0 {
		selectSQL += fmt.Sprintf(" LIMIT $%d OFFSET $%d", len(queryArgs)+1, len(queryArgs)+2)
		queryArgs = append(queryArgs, pageSize, (query.Page-1)*pageSize)
	}
	rows, err := s.db.QueryContext(ctx, selectSQL, queryArgs...)
	if err != nil {
		return FindingListPage{}, fmt.Errorf("list postgres findings: %w", err)
	}
	defer rows.Close()
	items := make([]taskflow.Finding, 0)
	for rows.Next() {
		var raw, assetID, fingerprint, status, taskID string
		var accepted, firstSeen, lastSeen, resolved sql.NullTime
		if err := rows.Scan(&raw, &assetID, &fingerprint, &status, &accepted,
			&firstSeen, &lastSeen, &resolved, &taskID); err != nil {
			return FindingListPage{}, fmt.Errorf("scan postgres findings: %w", err)
		}
		finding, err := hydratePostgresFinding(raw, assetID, fingerprint, status, taskID, accepted, firstSeen, lastSeen, resolved)
		if err != nil {
			return FindingListPage{}, err
		}
		items = append(items, finding)
	}
	if err := rows.Err(); err != nil {
		return FindingListPage{}, fmt.Errorf("iterate postgres findings: %w", err)
	}
	if pageSize == 0 {
		pageSize = len(items)
		if pageSize == 0 {
			pageSize = DefaultFindingPageSize
		}
	}
	return FindingListPage{Items: items, Total: total, Page: query.Page, PageSize: pageSize, Counts: counts}, nil
}

func hydratePostgresFinding(raw, assetID, fingerprint, status, taskID string, accepted, firstSeen, lastSeen, resolved sql.NullTime) (taskflow.Finding, error) {
	var finding taskflow.Finding
	if err := json.Unmarshal([]byte(raw), &finding); err != nil {
		return taskflow.Finding{}, fmt.Errorf("decode postgres finding projection: %w", err)
	}
	finding.AssetID, finding.Fingerprint, finding.Status, finding.TaskID = assetID, fingerprint, status, taskID
	if accepted.Valid {
		value := accepted.Time.UTC()
		finding.AcceptedUntil = &value
	} else {
		finding.AcceptedUntil = nil
	}
	if firstSeen.Valid {
		finding.FirstSeen = firstSeen.Time.UTC()
	}
	if lastSeen.Valid {
		finding.LastSeen = lastSeen.Time.UTC()
	}
	if resolved.Valid {
		value := resolved.Time.UTC()
		finding.ResolvedAt = &value
	} else {
		finding.ResolvedAt = nil
	}
	return findings.Upgrade(finding), nil
}

func postgresFindingWhere(query FindingListQuery) (string, []any) {
	clauses := []string{"TRUE"}
	args := make([]any, 0, 10)
	add := func(fragment string, values ...any) {
		positions := make([]any, len(values))
		for index := range values {
			positions[index] = len(args) + index + 1
		}
		args = append(args, values...)
		clauses = append(clauses, fmt.Sprintf(fragment, positions...))
	}
	if query.Search != "" {
		pattern := "%" + escapeFindingLike(query.Search) + "%"
		add(`(sf.location ILIKE $%d ESCAPE '\' OR sf.title ILIKE $%d ESCAPE '\' OR sf.rule_id ILIKE $%d ESCAPE '\' OR (fp.data::jsonb ->> 'package') ILIKE $%d ESCAPE '\')`, pattern, pattern, pattern, pattern)
	}
	if query.Severity != "" {
		add(`sf.severity=$%d`, query.Severity)
	}
	if query.Status != "" {
		add(`sf.lifecycle_status=$%d`, query.Status)
	}
	if query.Method != "" {
		add(`COALESCE(fp.data::jsonb ->> 'detectMethod','unknown')=$%d`, query.Method)
	}
	if query.Confidence != "" {
		add(`COALESCE(fp.data::jsonb ->> 'confidence','unknown')=$%d`, query.Confidence)
	}
	if query.Risk != "" {
		add(`COALESCE(fp.data::jsonb ->> 'riskType',CASE WHEN sf.engine_name IN ('trivy','knowledge') THEN 'system' ELSE 'web' END)=$%d`, query.Risk)
	}
	if query.OnlyVerified {
		clauses = append(clauses, `(fp.data::jsonb ->> 'verifiedInRun')='true'`)
	}
	if query.BusinessGroup != "" {
		add(`a.business_group=$%d`, query.BusinessGroup)
	}
	if query.AssetID != "" {
		add(`sf.asset_id=$%d`, query.AssetID)
	}
	if query.CVE != "" {
		add(`COALESCE(fp.data::jsonb ->> 'templateOrCve','')=$%d`, query.CVE)
	}
	if query.Package != "" {
		add(`COALESCE(fp.data::jsonb ->> 'package','')=$%d`, query.Package)
	}
	if query.Engine != "" {
		add(`sf.engine_name=$%d`, query.Engine)
	}
	if query.FixableOnly {
		clauses = append(clauses, `COALESCE(fp.data::jsonb ->> 'fixedVersion','')<>''`)
	}
	if query.TaskID != "" {
		add(`fp.task_id=$%d`, query.TaskID)
	}
	return strings.Join(clauses, " AND "), args
}

func postgresFindingSort(sortValue string) (string, string) {
	direction := "ASC"
	if strings.HasPrefix(sortValue, "-") || sortValue == "" {
		direction = "DESC"
	}
	switch strings.TrimPrefix(strings.TrimPrefix(sortValue, "+"), "-") {
	case "first_seen":
		return "sf.first_seen_at", direction
	case "severity":
		return `CASE sf.severity WHEN 'CRITICAL' THEN 5 WHEN 'HIGH' THEN 4 WHEN 'MEDIUM' THEN 3 WHEN 'LOW' THEN 2 ELSE 1 END`, direction
	case "status":
		return "sf.lifecycle_status", direction
	case "target":
		return "sf.location", direction
	case "title":
		return "sf.title", direction
	default:
		return "sf.last_seen_at", direction
	}
}

func (s *PostgresFindingStore) postgresFindingCounts(ctx context.Context, from string, args []any) (FindingListCounts, error) {
	var counts FindingListCounts
	err := s.db.QueryRowContext(ctx, `SELECT
		COUNT(*) FILTER (WHERE COALESCE(fp.data::jsonb ->> 'riskType',CASE WHEN sf.engine_name IN ('trivy','knowledge') THEN 'system' ELSE 'web' END) IN ('system','web')),
		COUNT(*) FILTER (WHERE COALESCE(fp.data::jsonb ->> 'riskType','')='login_entry'),
		COUNT(*) FILTER (WHERE COALESCE(fp.data::jsonb ->> 'riskType','unknown') NOT IN ('system','web','weak_credential','login_entry')),
		COUNT(*) FILTER (WHERE COALESCE(fp.data::jsonb ->> 'detectMethod','')='version'),
		COUNT(*) FILTER (WHERE COALESCE(fp.data::jsonb ->> 'riskType',CASE WHEN sf.engine_name IN ('trivy','knowledge') THEN 'system' ELSE 'web' END) IN ('system','web') AND COALESCE(fp.data::jsonb ->> 'detectMethod','') IN ('principle','configuration'))`+from, args...).Scan(
		&counts.Vulnerabilities, &counts.LoginEntries, &counts.Unknown, &counts.Version, &counts.Verified)
	if err != nil {
		return FindingListCounts{}, fmt.Errorf("count postgres finding categories: %w", err)
	}
	return counts, nil
}

// UpdateFindingDisposition applies the same state machine as the SQLite
// implementation, but writes normalized lifecycle fields and a projection in
// one PostgreSQL transaction.
func (s *PostgresFindingStore) UpdateFindingDisposition(ctx context.Context, id string, input FindingDisposition, actor string) (taskflow.Finding, error) {
	if s == nil || s.db == nil || strings.TrimSpace(actor) == "" {
		return taskflow.Finding{}, ErrPostgresFindingInvalid
	}
	now := s.currentTime()
	reason, until, err := validateFindingDisposition(input, now)
	if err != nil {
		return taskflow.Finding{}, err
	}
	if err := s.ExpireAcceptedRisks(ctx, now); err != nil {
		return taskflow.Finding{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return taskflow.Finding{}, fmt.Errorf("begin postgres finding disposition: %w", err)
	}
	defer tx.Rollback()
	finding, err := s.readFindingTx(ctx, tx, id)
	if err != nil {
		return taskflow.Finding{}, err
	}
	from := finding.Status
	if err := validateFindingTransition(from, input.Status); err != nil {
		return taskflow.Finding{}, err
	}
	finding.Status, finding.AcceptedReason, finding.AcceptedUntil = input.Status, reason, until
	if input.Status != "FIXED" {
		finding.ResolvedAt = nil
	}
	if err := s.updateFindingLifecycleTx(ctx, tx, finding, now); err != nil {
		return taskflow.Finding{}, err
	}
	if err := recordPostgresFindingEventTx(ctx, tx, id, from, input.Status, actor, reason, now); err != nil {
		return taskflow.Finding{}, err
	}
	if err := tx.Commit(); err != nil {
		return taskflow.Finding{}, fmt.Errorf("commit postgres finding disposition: %w", err)
	}
	return finding, nil
}

func (s *PostgresFindingStore) readFindingTx(ctx context.Context, tx *sql.Tx, id string) (taskflow.Finding, error) {
	var raw, assetID, fingerprint, status, taskID string
	var accepted, firstSeen, lastSeen, resolved sql.NullTime
	err := tx.QueryRowContext(ctx, `SELECT sf.asset_id,sf.fingerprint_hash,sf.lifecycle_status,
		sf.accepted_until,sf.first_seen_at,sf.last_seen_at,sf.resolved_at,fp.task_id,fp.data
		FROM security_findings sf JOIN finding_projections fp ON fp.finding_id=sf.id
		WHERE sf.id=$1 FOR UPDATE OF sf`, id).Scan(&assetID, &fingerprint, &status,
		&accepted, &firstSeen, &lastSeen, &resolved, &taskID, &raw)
	if errors.Is(err, sql.ErrNoRows) {
		return taskflow.Finding{}, ErrPostgresFindingMissing
	}
	if err != nil {
		return taskflow.Finding{}, fmt.Errorf("read postgres finding for update: %w", err)
	}
	return hydratePostgresFinding(raw, assetID, fingerprint, status, taskID, accepted, firstSeen, lastSeen, resolved)
}

func (s *PostgresFindingStore) ExpireAcceptedRisks(ctx context.Context, now time.Time) error {
	if s == nil || s.db == nil {
		return ErrPostgresFindingInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin postgres finding expiry: %w", err)
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT sf.id,fp.data FROM security_findings sf
		JOIN finding_projections fp ON fp.finding_id=sf.id
		WHERE sf.lifecycle_status='ACCEPTED_RISK' AND (sf.accepted_until IS NULL OR sf.accepted_until <= $1)
		FOR UPDATE OF sf`, now)
	if err != nil {
		return fmt.Errorf("list expired postgres findings: %w", err)
	}
	type expiredFinding struct {
		id         string
		projection string
	}
	expired := make([]expiredFinding, 0)
	for rows.Next() {
		var id, raw string
		if err := rows.Scan(&id, &raw); err != nil {
			return err
		}
		var f taskflow.Finding
		if err := json.Unmarshal([]byte(raw), &f); err != nil {
			return err
		}
		f.Status, f.AcceptedReason, f.AcceptedUntil = "OPEN", "", nil
		projection, err := findingProjectionJSON(f)
		if err != nil {
			return err
		}
		expired = append(expired, expiredFinding{id: id, projection: projection})
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, item := range expired {
		if _, err := tx.ExecContext(ctx, `UPDATE security_findings SET lifecycle_status='OPEN',accepted_until=NULL,resolved_at=NULL WHERE id=$1`, item.id); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE finding_projections SET data=$1,updated_at=$2 WHERE finding_id=$3`, item.projection, now, item.id); err != nil {
			return err
		}
		if err := recordPostgresFindingEventTx(ctx, tx, item.id, "ACCEPTED_RISK", "OPEN", "system", "接受风险已到期或缺少有效期限", now); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit postgres finding expiry: %w", err)
	}
	return nil
}

func recordPostgresFindingEventTx(ctx context.Context, tx *sql.Tx, findingID, from, to, actor, reason string, now time.Time) error {
	id := "event-" + randomLocalID()
	if _, err := tx.ExecContext(ctx, `INSERT INTO finding_events
		(id,finding_id,from_status,to_status,actor,reason,created_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7)`, id, findingID, from, to, actor, reason, now); err != nil {
		return fmt.Errorf("insert postgres finding event: %w", err)
	}
	detail, _ := json.Marshal(map[string]string{"eventId": id, "fromStatus": from, "toStatus": to})
	if _, err := tx.ExecContext(ctx, `INSERT INTO audit_logs
		(id,actor,action,object_type,object_id,detail,created_at)
		VALUES ($1,$2,'finding_status_changed','finding',$3,$4,$5)`, "audit-"+randomLocalID(), actor, findingID, string(detail), now); err != nil {
		return fmt.Errorf("audit postgres finding event: %w", err)
	}
	return nil
}

func (s *PostgresFindingStore) ListEvents(ctx context.Context, id string) ([]FindingEvent, error) {
	if s == nil || s.db == nil || strings.TrimSpace(id) == "" {
		return nil, ErrPostgresFindingInvalid
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id,finding_id,COALESCE(from_status,''),to_status,
		COALESCE(actor,''),COALESCE(reason,''),created_at FROM finding_events
		WHERE finding_id=$1 ORDER BY created_at,id`, id)
	if err != nil {
		return nil, fmt.Errorf("list postgres finding events: %w", err)
	}
	defer rows.Close()
	items := make([]FindingEvent, 0)
	for rows.Next() {
		var item FindingEvent
		if err := rows.Scan(&item.ID, &item.FindingID, &item.FromStatus, &item.ToStatus,
			&item.Actor, &item.Reason, &item.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan postgres finding event: %w", err)
		}
		item.CreatedAt = item.CreatedAt.UTC()
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate postgres finding events: %w", err)
	}
	return items, nil
}

// stablePostgresFindingFingerprint is kept for report adapters that receive a
// normalized detection before constructing a taskflow.Finding. It excludes
// evidence, timestamps and response content by design.
func stablePostgresFindingFingerprint(identity, engine, ruleID, matchedPath, packageName, installedVersion string) string {
	data, _ := json.Marshal([]string{identity, engine, ruleID, matchedPath, packageName, installedVersion})
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}
