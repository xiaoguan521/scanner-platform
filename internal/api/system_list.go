package api

import (
	"net/http"
	"strconv"

	"scanner-platform/internal/repo"
)

func parseNodeListQuery(r *http.Request) (repo.NodeListQuery, bool, bool) {
	values := r.URL.Query()
	if len(values) == 0 {
		return repo.NodeListQuery{}, false, true
	}
	for key := range values {
		switch key {
		case "page", "page_size", "q", "sort":
		default:
			return repo.NodeListQuery{}, true, false
		}
	}
	pageText, pageSizeText, search, sort, ok := singleSystemListValues(values)
	if !ok {
		return repo.NodeListQuery{}, true, false
	}
	query := repo.NodeListQuery{Page: 1, Search: search, Sort: sort, PageSize: repo.DefaultSystemListPageSize}
	if pageText != "" {
		page, err := strconv.Atoi(pageText)
		if err != nil || page < 1 {
			return repo.NodeListQuery{}, true, false
		}
		query.Page = page
	}
	if pageSizeText != "" {
		pageSize, err := strconv.Atoi(pageSizeText)
		if err != nil || pageSize < 1 {
			return repo.NodeListQuery{}, true, false
		}
		query.PageSize = pageSize
	}
	if _, err := repo.NormalizeNodeListQuery(query); err != nil {
		return repo.NodeListQuery{}, true, false
	}
	return query, true, true
}

func parseRuleListQuery(r *http.Request) (repo.RuleListQuery, bool, bool) {
	values := r.URL.Query()
	if len(values) == 0 {
		return repo.RuleListQuery{}, false, true
	}
	for key := range values {
		switch key {
		case "page", "page_size", "q", "sort":
		default:
			return repo.RuleListQuery{}, true, false
		}
	}
	pageText, pageSizeText, search, sort, ok := singleSystemListValues(values)
	if !ok {
		return repo.RuleListQuery{}, true, false
	}
	query := repo.RuleListQuery{Page: 1, Search: search, Sort: sort, PageSize: repo.DefaultSystemListPageSize}
	if pageText != "" {
		page, err := strconv.Atoi(pageText)
		if err != nil || page < 1 {
			return repo.RuleListQuery{}, true, false
		}
		query.Page = page
	}
	if pageSizeText != "" {
		pageSize, err := strconv.Atoi(pageSizeText)
		if err != nil || pageSize < 1 {
			return repo.RuleListQuery{}, true, false
		}
		query.PageSize = pageSize
	}
	if _, err := repo.NormalizeRuleListQuery(query); err != nil {
		return repo.RuleListQuery{}, true, false
	}
	return query, true, true
}

func parseRuleJobListQuery(r *http.Request) (repo.RuleJobListQuery, bool, bool) {
	values := r.URL.Query()
	if len(values) == 0 {
		return repo.RuleJobListQuery{}, false, true
	}
	for key := range values {
		switch key {
		case "page", "page_size", "q", "status", "kind", "sort":
		default:
			return repo.RuleJobListQuery{}, true, false
		}
	}
	pageText, pageSizeText, search, status, kind, sort, ok := singleRuleJobListValues(values)
	if !ok {
		return repo.RuleJobListQuery{}, true, false
	}
	query := repo.RuleJobListQuery{Page: 1, PageSize: repo.DefaultSystemListPageSize, Search: search, Status: normalizeListAll(status), Kind: normalizeListAll(kind), Sort: sort}
	if pageText != "" {
		page, err := strconv.Atoi(pageText)
		if err != nil || page < 1 {
			return repo.RuleJobListQuery{}, true, false
		}
		query.Page = page
	}
	if pageSizeText != "" {
		pageSize, err := strconv.Atoi(pageSizeText)
		if err != nil || pageSize < 1 {
			return repo.RuleJobListQuery{}, true, false
		}
		query.PageSize = pageSize
	}
	if _, err := repo.NormalizeRuleJobListQuery(query); err != nil {
		return repo.RuleJobListQuery{}, true, false
	}
	return query, true, true
}

func parseCustomRuleListQuery(r *http.Request) (repo.CustomRuleListQuery, bool, bool) {
	values := r.URL.Query()
	if len(values) == 0 {
		return repo.CustomRuleListQuery{}, false, true
	}
	for key := range values {
		switch key {
		case "page", "page_size", "q", "severity", "enabled", "sort":
		default:
			return repo.CustomRuleListQuery{}, true, false
		}
	}
	pageText, pageSizeText, search, severity, enabled, sort, ok := singleCustomRuleListValues(values)
	if !ok {
		return repo.CustomRuleListQuery{}, true, false
	}
	if enabled == "ALL" || enabled == "all" {
		enabled = ""
	}
	query := repo.CustomRuleListQuery{Page: 1, PageSize: repo.DefaultSystemListPageSize, Search: search, Severity: normalizeListAll(severity), Enabled: enabled, Sort: sort}
	if pageText != "" {
		page, err := strconv.Atoi(pageText)
		if err != nil || page < 1 {
			return repo.CustomRuleListQuery{}, true, false
		}
		query.Page = page
	}
	if pageSizeText != "" {
		pageSize, err := strconv.Atoi(pageSizeText)
		if err != nil || pageSize < 1 {
			return repo.CustomRuleListQuery{}, true, false
		}
		query.PageSize = pageSize
	}
	if _, err := repo.NormalizeCustomRuleListQuery(query); err != nil {
		return repo.CustomRuleListQuery{}, true, false
	}
	return query, true, true
}

func singleSystemListValues(values map[string][]string) (page, pageSize, search, sort string, ok bool) {
	single := func(key string) (string, bool) {
		items, exists := values[key]
		if !exists {
			return "", true
		}
		if len(items) != 1 {
			return "", false
		}
		return items[0], true
	}
	var pageOK, pageSizeOK, searchOK, sortOK bool
	page, pageOK = single("page")
	pageSize, pageSizeOK = single("page_size")
	search, searchOK = single("q")
	sort, sortOK = single("sort")
	return page, pageSize, search, sort, pageOK && pageSizeOK && searchOK && sortOK
}

func normalizeListAll(value string) string {
	if value == "ALL" || value == "all" {
		return ""
	}
	return value
}

func singleRuleJobListValues(values map[string][]string) (page, pageSize, search, status, kind, sort string, ok bool) {
	single := func(key string) (string, bool) {
		items, exists := values[key]
		if !exists {
			return "", true
		}
		if len(items) != 1 {
			return "", false
		}
		return items[0], true
	}
	var pageOK, pageSizeOK, searchOK, statusOK, kindOK, sortOK bool
	page, pageOK = single("page")
	pageSize, pageSizeOK = single("page_size")
	search, searchOK = single("q")
	status, statusOK = single("status")
	kind, kindOK = single("kind")
	sort, sortOK = single("sort")
	return page, pageSize, search, status, kind, sort, pageOK && pageSizeOK && searchOK && statusOK && kindOK && sortOK
}

func singleCustomRuleListValues(values map[string][]string) (page, pageSize, search, severity, enabled, sort string, ok bool) {
	single := func(key string) (string, bool) {
		items, exists := values[key]
		if !exists {
			return "", true
		}
		if len(items) != 1 {
			return "", false
		}
		return items[0], true
	}
	var pageOK, pageSizeOK, searchOK, severityOK, enabledOK, sortOK bool
	page, pageOK = single("page")
	pageSize, pageSizeOK = single("page_size")
	search, searchOK = single("q")
	severity, severityOK = single("severity")
	enabled, enabledOK = single("enabled")
	sort, sortOK = single("sort")
	return page, pageSize, search, severity, enabled, sort, pageOK && pageSizeOK && searchOK && severityOK && enabledOK && sortOK
}
