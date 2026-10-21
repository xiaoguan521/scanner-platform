package repo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"scanner-platform/internal/findings"
	"scanner-platform/internal/taskflow"
)

// FindingListQuery is the bounded Server-side findings list contract.
type FindingListQuery struct {
	Page          int
	PageSize      int
	Search        string
	Severity      string
	Status        string
	Method        string
	Confidence    string
	Risk          string
	OnlyVerified  bool
	BusinessGroup string
	AssetID       string
	Sort          string
}

type FindingListCounts struct {
	Vulnerabilities int `json:"vulnerabilities"`
	LoginEntries    int `json:"loginEntries"`
	Unknown         int `json:"unknown"`
	Version         int `json:"version"`
	Verified        int `json:"verified"`
}

type FindingListPage struct {
	Items    []taskflow.Finding `json:"items"`
	Total    int                `json:"total"`
	Page     int                `json:"page"`
	PageSize int                `json:"pageSize"`
	Counts   FindingListCounts  `json:"counts"`
}

const (
	DefaultFindingPageSize = 20
	MaxFindingPageSize     = 100
	MaxFindingPage         = 1_000_000
)

var ErrInvalidFindingListQuery = errors.New("invalid finding list query")

func NormalizeFindingListQuery(in FindingListQuery) (FindingListQuery, error) {
	if in.Page < 0 || in.PageSize < 0 || in.Page > MaxFindingPage || len(in.Search) > 160 || len(in.BusinessGroup) > 160 || len(in.AssetID) > 160 || strings.ContainsRune(in.Search, 0) || strings.ContainsRune(in.BusinessGroup, 0) || strings.ContainsRune(in.AssetID, 0) {
		return FindingListQuery{}, ErrInvalidFindingListQuery
	}
	if in.Page == 0 {
		in.Page = 1
	}
	if in.PageSize > MaxFindingPageSize {
		return FindingListQuery{}, ErrInvalidFindingListQuery
	}
	if in.Severity != "" && !oneOf(in.Severity, "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO") {
		return FindingListQuery{}, ErrInvalidFindingListQuery
	}
	if in.Status != "" && !oneOf(in.Status, "OPEN", "REOPENED", "IN_PROGRESS", "FIXED", "FALSE_POSITIVE", "ACCEPTED_RISK") {
		return FindingListQuery{}, ErrInvalidFindingListQuery
	}
	if in.Method != "" && !oneOf(in.Method, "principle", "version", "configuration", "unknown") {
		return FindingListQuery{}, ErrInvalidFindingListQuery
	}
	if in.Confidence != "" && !oneOf(in.Confidence, "high", "medium", "low", "unknown") {
		return FindingListQuery{}, ErrInvalidFindingListQuery
	}
	if in.Risk != "" && !oneOf(in.Risk, "system", "web", "weak_credential", "login_entry", "unknown") {
		return FindingListQuery{}, ErrInvalidFindingListQuery
	}
	if strings.HasPrefix(in.Sort, "+") {
		in.Sort = strings.TrimPrefix(in.Sort, "+")
	}
	sortKey := strings.TrimPrefix(in.Sort, "-")
	if !oneOf(sortKey, "", "last_seen", "first_seen", "severity", "status", "target", "title") {
		return FindingListQuery{}, ErrInvalidFindingListQuery
	}
	if in.PageSize > 0 && in.Page-1 > int(^uint(0)>>1)/in.PageSize {
		return FindingListQuery{}, ErrInvalidFindingListQuery
	}
	return in, nil
}

func oneOf(value string, allowed ...string) bool {
	for _, candidate := range allowed {
		if value == candidate {
			return true
		}
	}
	return false
}

func (s *RuntimeStore) ListRuntimeFindingsPage(ctx context.Context, in FindingListQuery) (FindingListPage, error) {
	if err := s.ExpireAcceptedRisks(ctx, time.Now().UTC()); err != nil {
		return FindingListPage{}, err
	}
	query, err := NormalizeFindingListQuery(in)
	if err != nil {
		return FindingListPage{}, err
	}
	items, total, err := s.listFindingRows(ctx, query)
	if err != nil {
		return FindingListPage{}, err
	}
	counts, err := s.findingListCounts(ctx, query)
	if err != nil {
		return FindingListPage{}, err
	}
	pageSize := query.PageSize
	if pageSize == 0 {
		pageSize = len(items)
		if pageSize == 0 {
			pageSize = DefaultFindingPageSize
		}
	}
	return FindingListPage{Items: items, Total: total, Page: query.Page, PageSize: pageSize, Counts: counts}, nil
}

func (s *RuntimeStore) listFindingRows(ctx context.Context, query FindingListQuery) ([]taskflow.Finding, int, error) {
	where, args := findingListWhere(query)
	var total int
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM security_findings WHERE "+where, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count findings: %w", err)
	}
	sortColumn := findingLastSeenExpr
	sortKey := strings.TrimPrefix(query.Sort, "-")
	switch sortKey {
	case "first_seen":
		sortColumn = findingFirstSeenExpr
	case "severity":
		sortColumn = findingSeverityOrderExpr
	case "status":
		sortColumn = findingStatusExpr
	case "target":
		sortColumn = "COALESCE(json_extract(data,'$.target'),'')"
	case "title":
		sortColumn = "COALESCE(json_extract(data,'$.title'),'')"
	}
	direction := "ASC"
	if strings.HasPrefix(query.Sort, "-") || query.Sort == "" {
		direction = "DESC"
	}
	queryArgs := append([]any(nil), args...)
	sqlQuery := "SELECT data FROM security_findings WHERE " + where + " ORDER BY " + sortColumn + " " + direction + ",rowid DESC"
	if query.PageSize > 0 {
		sqlQuery += " LIMIT ? OFFSET ?"
		queryArgs = append(queryArgs, query.PageSize, (query.Page-1)*query.PageSize)
	}
	rows, err := s.db.QueryContext(ctx, sqlQuery, queryArgs...)
	if err != nil {
		return nil, 0, fmt.Errorf("list findings: %w", err)
	}
	defer rows.Close()
	items := make([]taskflow.Finding, 0)
	for rows.Next() {
		var data string
		var item taskflow.Finding
		if err := rows.Scan(&data); err != nil {
			return nil, 0, fmt.Errorf("read finding: %w", err)
		}
		if err := json.Unmarshal([]byte(data), &item); err != nil {
			return nil, 0, fmt.Errorf("decode finding: %w", err)
		}
		items = append(items, findings.Upgrade(item))
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	return items, total, nil
}

const (
	findingRiskExpr          = `CASE WHEN COALESCE(json_extract(data,'$.riskType'),'')<>'' THEN json_extract(data,'$.riskType') WHEN json_extract(data,'$.engine') IN ('trivy','knowledge') THEN 'system' ELSE 'web' END`
	findingMethodExpr        = `CASE WHEN COALESCE(json_extract(data,'$.detectMethod'),'')<>'' THEN json_extract(data,'$.detectMethod') WHEN json_extract(data,'$.engine') IN ('trivy','knowledge') THEN 'version' WHEN json_extract(data,'$.engine') IN ('nuclei','zap') THEN 'configuration' ELSE 'unknown' END`
	findingConfidenceExpr    = `CASE WHEN COALESCE(json_extract(data,'$.confidence'),'')<>'' THEN json_extract(data,'$.confidence') WHEN ` + findingMethodExpr + `='version' THEN 'medium' WHEN ` + findingMethodExpr + ` IN ('principle','configuration') THEN 'high' ELSE 'unknown' END`
	findingSeverityExpr      = `COALESCE(json_extract(data,'$.severity'),'')`
	findingSeverityOrderExpr = `CASE json_extract(data,'$.severity') WHEN 'CRITICAL' THEN 5 WHEN 'HIGH' THEN 4 WHEN 'MEDIUM' THEN 3 WHEN 'LOW' THEN 2 WHEN 'INFO' THEN 1 ELSE 0 END`
	findingStatusExpr        = `COALESCE(json_extract(data,'$.status'),'')`
	findingLastSeenExpr      = `COALESCE(json_extract(data,'$.lastSeen'),'')`
	findingFirstSeenExpr     = `COALESCE(json_extract(data,'$.firstSeen'),'')`
)

func findingListWhere(query FindingListQuery) (string, []any) {
	where := []string{"1=1"}
	args := make([]any, 0, 12)
	if query.Severity != "" {
		where = append(where, findingSeverityExpr+"=?")
		args = append(args, query.Severity)
	}
	if query.Status != "" {
		where = append(where, findingStatusExpr+"=?")
		args = append(args, query.Status)
	}
	if query.Method != "" {
		where = append(where, findingMethodExpr+"=?")
		args = append(args, query.Method)
	}
	if query.Confidence != "" {
		where = append(where, findingConfidenceExpr+"=?")
		args = append(args, query.Confidence)
	}
	if query.Risk != "" {
		where = append(where, findingRiskExpr+"=?")
		args = append(args, query.Risk)
	}
	if query.OnlyVerified {
		where = append(where, findingRiskExpr+" IN ('system','web') AND "+findingMethodExpr+" IN ('principle','configuration')")
	}
	if query.BusinessGroup != "" {
		where = append(where, "COALESCE(json_extract(data,'$.businessGroup'),'')=?")
		args = append(args, query.BusinessGroup)
	}
	if query.AssetID != "" {
		where = append(where, "COALESCE(json_extract(data,'$.assetId'),'')=?")
		args = append(args, query.AssetID)
	}
	if query.Search != "" {
		pattern := "%" + escapeFindingLike(query.Search) + "%"
		where = append(where, `(COALESCE(json_extract(data,'$.target'),'') LIKE ? ESCAPE '\' OR COALESCE(json_extract(data,'$.package'),'') LIKE ? ESCAPE '\' OR COALESCE(json_extract(data,'$.templateOrCve'),'') LIKE ? ESCAPE '\' OR COALESCE(json_extract(data,'$.title'),'') LIKE ? ESCAPE '\')`)
		args = append(args, pattern, pattern, pattern, pattern)
	}
	return strings.Join(where, " AND "), args
}

func escapeFindingLike(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, `%`, `\%`)
	return strings.ReplaceAll(value, `_`, `\_`)
}

func (s *RuntimeStore) findingListCounts(ctx context.Context, query FindingListQuery) (FindingListCounts, error) {
	where, args := findingListWhere(query)
	queryText := `SELECT
	COALESCE(SUM(CASE WHEN ` + findingRiskExpr + ` IN ('system','web') THEN 1 ELSE 0 END),0),
	COALESCE(SUM(CASE WHEN ` + findingRiskExpr + `='login_entry' THEN 1 ELSE 0 END),0),
	COALESCE(SUM(CASE WHEN ` + findingRiskExpr + ` NOT IN ('system','web','weak_credential','login_entry') THEN 1 ELSE 0 END),0),
	COALESCE(SUM(CASE WHEN ` + findingRiskExpr + ` IN ('system','web') AND ` + findingMethodExpr + `='version' THEN 1 ELSE 0 END),0),
	COALESCE(SUM(CASE WHEN ` + findingRiskExpr + ` IN ('system','web') AND ` + findingMethodExpr + ` IN ('principle','configuration') THEN 1 ELSE 0 END),0)
	FROM security_findings WHERE ` + where
	var counts FindingListCounts
	if err := s.db.QueryRowContext(ctx, queryText, args...).Scan(&counts.Vulnerabilities, &counts.LoginEntries, &counts.Unknown, &counts.Version, &counts.Verified); err != nil {
		return FindingListCounts{}, fmt.Errorf("count finding categories: %w", err)
	}
	return counts, nil
}
