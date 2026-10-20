package assets

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	MaxImportBytes = 1 << 20
	MaxImportRows  = 1000
	ImportTTL      = 15 * time.Minute
	ImportTemplate = "kind,address,businessGroup,owner,name\nhost,192.0.2.10,示例业务组,示例负责人,示例主机\nimage_repo,registry.example.com/team/image,示例业务组,示例负责人,示例镜像\n"
)

var (
	ErrImportFormat      = errors.New("invalid asset CSV format")
	ErrImportLimit       = errors.New("asset CSV limit exceeded")
	ErrImportUnavailable = errors.New("asset import unavailable or expired")
	ErrImportConflict    = errors.New("asset import conflict")
)

// ImportRow exposes only fields supported by this import version. Ports cannot be imported.
type ImportRow struct {
	Row           int    `json:"row"`
	Kind          string `json:"kind"`
	Address       string `json:"address"`
	BusinessGroup string `json:"businessGroup"`
	Owner         string `json:"owner"`
	Name          string `json:"name,omitempty"`
	Reason        string `json:"reason,omitempty"`
}
type ImportPreview struct {
	PreviewID string      `json:"previewId,omitempty"`
	ExpiresAt string      `json:"expiresAt,omitempty"`
	Total     int         `json:"total"`
	Valid     int         `json:"valid"`
	Invalid   int         `json:"invalid"`
	Rows      []ImportRow `json:"rows"`
}
type ImportResult struct {
	Imported int `json:"imported"`
}
type ImportRepository interface {
	PreviewImport(context.Context, string, []byte) (ImportPreview, error)
	ConfirmImport(context.Context, string, string) (ImportResult, error)
}

func importInput(row ImportRow) Input {
	return Input{Kind: row.Kind, Address: row.Address, BusinessGroup: row.BusinessGroup, Owner: row.Owner, Name: row.Name}
}

// parseImportCSV performs no I/O beyond reading the supplied bytes and never resolves targets.
func parseImportCSV(data []byte) (ImportPreview, error) {
	out := ImportPreview{Rows: []ImportRow{}}
	if len(data) > MaxImportBytes {
		return out, ErrImportLimit
	}
	if !utf8.Valid(data) {
		return out, ErrImportFormat
	}
	r := csv.NewReader(bytes.NewReader(data))
	header, err := r.Read()
	if err != nil || (len(header) != 4 && len(header) != 5) {
		return out, ErrImportFormat
	}
	expected := []string{"kind", "address", "businessGroup", "owner", "name"}
	for i, value := range header {
		if value != expected[i] {
			return out, ErrImportFormat
		}
	}
	r.FieldsPerRecord = -1
	seen := map[string]bool{}
	for {
		record, err := r.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return ImportPreview{}, ErrImportFormat
		}
		if len(out.Rows) >= MaxImportRows {
			return ImportPreview{}, ErrImportLimit
		}
		line, _ := r.FieldPos(0)
		row := ImportRow{Row: line}
		if len(record) != len(header) {
			row.Reason = "字段数与表头不一致"
		} else {
			row.Kind = record[0]
			row.Address = record[1]
			row.BusinessGroup = record[2]
			row.Owner = record[3]
			if len(record) == 5 {
				row.Name = record[4]
			}
			validText := true
			for _, text := range record {
				validText = validText && !strings.ContainsFunc(text, unicode.IsControl)
			}
			normalized, normalizeErr := normalize(importInput(row))
			if !validText || normalizeErr != nil {
				row.Reason = "类型、数字 IP/镜像地址、业务组、负责人或名称无效"
			} else {
				row.Address = normalized.Address
				row.BusinessGroup = normalized.BusinessGroup
				row.Owner = normalized.Owner
				row.Name = strings.TrimSpace(normalized.Name)
				key := row.Kind + "\x00" + row.Address
				if seen[key] {
					row.Reason = "文件内资产重复"
				}
				seen[key] = true
			}
		}
		out.Rows = append(out.Rows, row)
	}
	if len(out.Rows) == 0 {
		return out, ErrImportFormat
	}
	out.Total = len(out.Rows)
	return out, nil
}
func (s *Store) PreviewImport(ctx context.Context, actor string, data []byte) (ImportPreview, error) {
	if strings.TrimSpace(actor) == "" {
		return ImportPreview{}, ErrInvalid
	}
	preview, err := parseImportCSV(data)
	if err != nil {
		return ImportPreview{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ImportPreview{}, fmt.Errorf("begin import preview: %w", err)
	}
	defer tx.Rollback()
	for i := range preview.Rows {
		row := &preview.Rows[i]
		if row.Reason == "" {
			var count int
			if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM assets WHERE kind=? AND address=?", row.Kind, row.Address).Scan(&count); err != nil {
				return ImportPreview{}, fmt.Errorf("check import duplicate: %w", err)
			}
			if count != 0 {
				row.Reason = "资产已存在"
			}
		}
		if row.Reason == "" {
			preview.Valid++
		} else {
			preview.Invalid++
		}
	}
	// Replacing a user's current preview invalidates its previous confirmation.
	now := time.Now().UTC()
	if _, err := tx.ExecContext(ctx, "DELETE FROM asset_import_previews WHERE actor=? OR expires_at<=?", actor, now.Unix()); err != nil {
		return ImportPreview{}, fmt.Errorf("clear import previews: %w", err)
	}
	if preview.Invalid == 0 {
		preview.PreviewID, err = newID()
		if err != nil {
			return ImportPreview{}, err
		}
		expires := now.Add(ImportTTL)
		preview.ExpiresAt = expires.Format(time.RFC3339)
		data, err := json.Marshal(preview.Rows)
		if err != nil {
			return ImportPreview{}, fmt.Errorf("encode import rows: %w", err)
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO asset_import_previews(id,actor,rows_json,expires_at,state) VALUES(?,?,?,?,'PENDING')", preview.PreviewID, actor, string(data), expires.Unix()); err != nil {
			return ImportPreview{}, fmt.Errorf("stage import preview: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return ImportPreview{}, fmt.Errorf("commit import preview: %w", err)
	}
	return preview, nil
}
func (s *Store) ConfirmImport(ctx context.Context, actor, id string) (ImportResult, error) {
	if strings.TrimSpace(actor) == "" || strings.TrimSpace(id) == "" || len(id) > 128 {
		return ImportResult{}, ErrImportUnavailable
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ImportResult{}, fmt.Errorf("begin import confirmation: %w", err)
	}
	defer tx.Rollback()
	// Claim with a write before reading so concurrent connections cannot both consume a preview.
	claim, err := tx.ExecContext(ctx, "UPDATE asset_import_previews SET state='CONFIRMED' WHERE id=? AND actor=? AND state='PENDING' AND expires_at>?", id, actor, time.Now().UTC().Unix())
	if err != nil {
		return ImportResult{}, fmt.Errorf("claim import preview: %w", err)
	}
	count, err := claim.RowsAffected()
	if err != nil {
		return ImportResult{}, fmt.Errorf("count import claim: %w", err)
	}
	if count != 1 {
		return ImportResult{}, ErrImportUnavailable
	}
	var encoded string
	if err := tx.QueryRowContext(ctx, "SELECT rows_json FROM asset_import_previews WHERE id=?", id).Scan(&encoded); err != nil {
		return ImportResult{}, fmt.Errorf("read import preview: %w", err)
	}
	var rows []ImportRow
	if len(encoded) > MaxImportBytes*8 || json.Unmarshal([]byte(encoded), &rows) != nil || len(rows) == 0 || len(rows) > MaxImportRows {
		return ImportResult{}, ErrImportUnavailable
	}
	created := time.Now().UTC().Format(time.RFC3339Nano)
	for _, row := range rows {
		in, err := normalize(importInput(row))
		if err != nil || row.Reason != "" {
			return ImportResult{}, ErrImportUnavailable
		}
		assetID, err := newID()
		if err != nil {
			return ImportResult{}, err
		}
		resolved := ""
		if in.Kind == "host" {
			resolved = in.Address
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO assets(id,kind,address,resolved_ip,business_group,owner,created_at) VALUES(?,?,?,?,?,?,?)`, assetID, in.Kind, in.Address, resolved, in.BusinessGroup, in.Owner, created); err != nil {
			if strings.Contains(err.Error(), "UNIQUE") {
				return ImportResult{}, ErrImportConflict
			}
			return ImportResult{}, fmt.Errorf("insert imported asset: %w", err)
		}
		if err := saveProfile(ctx, tx, assetID, in); err != nil {
			return ImportResult{}, fmt.Errorf("insert imported profile: %w", err)
		}
	}
	// Audit only the count, never CSV contents, filenames, target addresses or names.
	auditID, err := newID()
	if err != nil {
		return ImportResult{}, err
	}
	detail := fmt.Sprintf(`{"imported":%d}`, len(rows))
	if _, err := tx.ExecContext(ctx, `INSERT INTO audit_logs(id,actor,action,object_type,object_id,detail,created_at) VALUES(?,?,'import_assets','asset_import','',?,?)`, auditID, actor, detail, created); err != nil {
		return ImportResult{}, fmt.Errorf("audit asset import: %w", err)
	}
	if _, err := tx.ExecContext(ctx, "UPDATE asset_import_previews SET rows_json='[]' WHERE id=?", id); err != nil {
		return ImportResult{}, fmt.Errorf("clear confirmed import: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return ImportResult{}, fmt.Errorf("commit asset import: %w", err)
	}
	return ImportResult{Imported: len(rows)}, nil
}
