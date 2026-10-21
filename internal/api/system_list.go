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
