package api

import (
	"net/http"
	"strconv"
	"strings"

	"scanner-platform/internal/approvals"
)

type approvalListQuery struct {
	page     int
	pageSize int
}

func approvalListValue(values map[string][]string, key string) (string, bool) {
	items, present := values[key]
	if !present {
		return "", true
	}
	if len(items) != 1 {
		return "", false
	}
	return items[0], true
}

func parseApprovalPage(values map[string][]string) (approvalListQuery, bool) {
	pageText, ok := approvalListValue(values, "page")
	if !ok {
		return approvalListQuery{}, false
	}
	pageSizeText, ok := approvalListValue(values, "page_size")
	if !ok {
		return approvalListQuery{}, false
	}
	page, pageSize := 0, 0
	var err error
	if pageText != "" {
		page, err = strconv.Atoi(pageText)
		if err != nil || page < 1 || page > 100000 {
			return approvalListQuery{}, false
		}
	}
	if pageSizeText != "" {
		pageSize, err = strconv.Atoi(pageSizeText)
		if err != nil || pageSize < 1 || pageSize > 100 {
			return approvalListQuery{}, false
		}
	}
	return approvalListQuery{page: page, pageSize: pageSize}, true
}

func parseScopeListQuery(r *http.Request) (approvals.ScopeListQuery, bool, bool) {
	values := r.URL.Query()
	paged := false
	for key := range values {
		switch key {
		case "page", "page_size", "expiry", "q":
			paged = true
		default:
			return approvals.ScopeListQuery{}, false, false
		}
	}
	if !paged {
		return approvals.ScopeListQuery{}, false, true
	}
	page, ok := parseApprovalPage(values)
	if !ok {
		return approvals.ScopeListQuery{}, true, false
	}
	expiry, ok := approvalListValue(values, "expiry")
	if !ok {
		return approvals.ScopeListQuery{}, true, false
	}
	expiry = strings.ToLower(strings.TrimSpace(expiry))
	if expiry != "" && expiry != "all" && expiry != "expiring" && expiry != "expired" {
		return approvals.ScopeListQuery{}, true, false
	}
	search, ok := approvalListValue(values, "q")
	if !ok || len(strings.TrimSpace(search)) > 160 {
		return approvals.ScopeListQuery{}, true, false
	}
	return approvals.ScopeListQuery{Page: page.page, PageSize: page.pageSize, Expiry: expiry, Search: search}, true, true
}

func parsePortRequestListQuery(r *http.Request) (approvals.PortRequestListQuery, bool, bool) {
	values := r.URL.Query()
	paged := false
	for key := range values {
		switch key {
		case "page", "page_size", "status", "q":
			paged = true
		default:
			return approvals.PortRequestListQuery{}, false, false
		}
	}
	if !paged {
		return approvals.PortRequestListQuery{}, false, true
	}
	page, ok := parseApprovalPage(values)
	if !ok {
		return approvals.PortRequestListQuery{}, true, false
	}
	status, ok := approvalListValue(values, "status")
	if !ok {
		return approvals.PortRequestListQuery{}, true, false
	}
	status = strings.ToUpper(strings.TrimSpace(status))
	if status != "" && status != "ALL" && status != "PENDING" && status != "APPROVED" && status != "REJECTED" {
		return approvals.PortRequestListQuery{}, true, false
	}
	search, ok := approvalListValue(values, "q")
	if !ok || len(search) > 160 || strings.IndexByte(search, 0) >= 0 {
		return approvals.PortRequestListQuery{}, true, false
	}
	return approvals.PortRequestListQuery{Page: page.page, PageSize: page.pageSize, Status: status, Search: strings.TrimSpace(search)}, true, true
}
