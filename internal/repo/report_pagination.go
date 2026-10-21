package repo

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"scanner-platform/internal/reporting"
)

// ReportListQuery is the bounded Server-side report history contract.
type ReportListQuery struct {
	Page     int
	PageSize int
	Search   string
	Status   string
	Format   string
	Sort     string
}

type ReportListPage struct {
	Items    []reporting.Job `json:"items"`
	Total    int             `json:"total"`
	Page     int             `json:"page"`
	PageSize int             `json:"pageSize"`
}

const (
	DefaultReportPageSize = 20
	MaxReportPageSize     = 100
	MaxReportPage         = 1_000_000
)

var ErrInvalidReportListQuery = errors.New("invalid report list query")

func NormalizeReportListQuery(in ReportListQuery) (ReportListQuery, error) {
	if in.Page < 0 || in.PageSize < 0 || in.Page > MaxReportPage || len(in.Search) > 160 || strings.ContainsRune(in.Search, 0) {
		return ReportListQuery{}, ErrInvalidReportListQuery
	}
	if in.Page == 0 {
		in.Page = 1
	}
	if in.PageSize > MaxReportPageSize {
		return ReportListQuery{}, ErrInvalidReportListQuery
	}
	if in.Status != "" && !oneOf(in.Status, "QUEUED", "GENERATING", "READY", "FAILED") {
		return ReportListQuery{}, ErrInvalidReportListQuery
	}
	if in.Format != "" && !oneOf(in.Format, "html", "xlsx", "docx", "csv", "json", "pdf") {
		return ReportListQuery{}, ErrInvalidReportListQuery
	}
	if strings.HasPrefix(in.Sort, "+") {
		in.Sort = strings.TrimPrefix(in.Sort, "+")
	}
	sortKey := strings.TrimPrefix(in.Sort, "-")
	if !oneOf(sortKey, "", "created_at", "name", "status", "format") {
		return ReportListQuery{}, ErrInvalidReportListQuery
	}
	if in.PageSize > 0 && in.Page-1 > int(^uint(0)>>1)/in.PageSize {
		return ReportListQuery{}, ErrInvalidReportListQuery
	}
	return in, nil
}

func (s *RuntimeStore) ListReportsPage(ctx context.Context, in ReportListQuery) (ReportListPage, error) {
	query, err := NormalizeReportListQuery(in)
	if err != nil {
		return ReportListPage{}, err
	}
	where, args := reportListWhere(query)
	var total int
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM report_jobs WHERE "+where, args...).Scan(&total); err != nil {
		return ReportListPage{}, fmt.Errorf("count reports: %w", err)
	}

	sortColumn := "created_at"
	switch strings.TrimPrefix(query.Sort, "-") {
	case "name":
		sortColumn = "COALESCE(json_extract(data,'$.name'),'')"
	case "status":
		sortColumn = "status"
	case "format":
		sortColumn = "COALESCE(json_extract(data,'$.format'),'')"
	}
	direction := "ASC"
	if strings.HasPrefix(query.Sort, "-") || query.Sort == "" {
		direction = "DESC"
	}
	queryArgs := append([]any(nil), args...)
	sqlQuery := "SELECT data,status,file_path FROM report_jobs WHERE " + where + " ORDER BY " + sortColumn + " " + direction + ",id"
	if query.PageSize > 0 {
		sqlQuery += " LIMIT ? OFFSET ?"
		queryArgs = append(queryArgs, query.PageSize, (query.Page-1)*query.PageSize)
	}
	rows, err := s.db.QueryContext(ctx, sqlQuery, queryArgs...)
	if err != nil {
		return ReportListPage{}, fmt.Errorf("list reports: %w", err)
	}
	defer rows.Close()
	items := make([]reporting.Job, 0)
	for rows.Next() {
		job, err := readReport(rows)
		if err != nil {
			return ReportListPage{}, fmt.Errorf("read report: %w", err)
		}
		items = append(items, job)
	}
	if err := rows.Err(); err != nil {
		return ReportListPage{}, fmt.Errorf("iterate reports: %w", err)
	}
	pageSize := query.PageSize
	if pageSize == 0 {
		pageSize = len(items)
		if pageSize == 0 {
			pageSize = DefaultReportPageSize
		}
	}
	return ReportListPage{Items: items, Total: total, Page: query.Page, PageSize: pageSize}, nil
}

func reportListWhere(query ReportListQuery) (string, []any) {
	where := []string{"1=1"}
	args := make([]any, 0, 4)
	if query.Status != "" {
		where = append(where, "status=?")
		args = append(args, query.Status)
	}
	if query.Format != "" {
		where = append(where, "COALESCE(json_extract(data,'$.format'),'')=?")
		args = append(args, query.Format)
	}
	if query.Search != "" {
		pattern := "%" + escapeFindingLike(query.Search) + "%"
		where = append(where, `(id LIKE ? ESCAPE '\' OR COALESCE(json_extract(data,'$.name'),'') LIKE ? ESCAPE '\' OR COALESCE(json_extract(data,'$.createdBy'),'') LIKE ? ESCAPE '\' OR COALESCE(json_extract(data,'$.snapshotId'),'') LIKE ? ESCAPE '\')`)
		args = append(args, pattern, pattern, pattern, pattern)
	}
	return strings.Join(where, " AND "), args
}
