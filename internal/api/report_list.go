package api

import (
	"net/http"
	"strconv"

	"scanner-platform/internal/repo"
)

func parseReportListQuery(r *http.Request) (repo.ReportListQuery, bool, bool) {
	values := r.URL.Query()
	if len(values) == 0 {
		return repo.ReportListQuery{}, false, true
	}
	for key := range values {
		switch key {
		case "page", "page_size", "q", "status", "format", "sort":
		default:
			return repo.ReportListQuery{}, true, false
		}
	}
	single := func(key string) (string, bool) {
		items, ok := values[key]
		if !ok {
			return "", true
		}
		if len(items) != 1 {
			return "", false
		}
		return items[0], true
	}
	pageText, pageOK := single("page")
	pageSizeText, pageSizeOK := single("page_size")
	search, searchOK := single("q")
	status, statusOK := single("status")
	format, formatOK := single("format")
	sort, sortOK := single("sort")
	if !pageOK || !pageSizeOK || !searchOK || !statusOK || !formatOK || !sortOK {
		return repo.ReportListQuery{}, true, false
	}
	normalizeAll := func(value string) string {
		if value == "ALL" || value == "all" {
			return ""
		}
		return value
	}
	query := repo.ReportListQuery{Page: 1, Search: search, Status: normalizeAll(status), Format: normalizeAll(format), Sort: sort}
	if pageText != "" {
		page, err := strconv.Atoi(pageText)
		if err != nil || page < 1 {
			return repo.ReportListQuery{}, true, false
		}
		query.Page = page
	}
	if pageSizeText != "" {
		pageSize, err := strconv.Atoi(pageSizeText)
		if err != nil || pageSize < 1 {
			return repo.ReportListQuery{}, true, false
		}
		query.PageSize = pageSize
	} else {
		query.PageSize = repo.DefaultReportPageSize
	}
	if _, err := repo.NormalizeReportListQuery(query); err != nil {
		return repo.ReportListQuery{}, true, false
	}
	return query, true, true
}
