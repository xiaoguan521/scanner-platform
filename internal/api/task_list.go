package api

import (
	"net/http"
	"strconv"

	"scanner-platform/internal/repo"
)

func parseTaskListQuery(r *http.Request) (repo.TaskListQuery, bool, bool) {
	values := r.URL.Query()
	if len(values) == 0 {
		return repo.TaskListQuery{}, false, true
	}
	for key := range values {
		switch key {
		case "page", "page_size", "q", "status", "engine", "archived", "sort":
		default:
			return repo.TaskListQuery{}, true, false
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
	engine, engineOK := single("engine")
	archived, archivedOK := single("archived")
	sort, sortOK := single("sort")
	if !pageOK || !pageSizeOK || !searchOK || !statusOK || !engineOK || !archivedOK || !sortOK {
		return repo.TaskListQuery{}, true, false
	}
	query := repo.TaskListQuery{Page: 1, Search: search, Sort: sort, Archived: archived}
	if query.Archived == "" {
		query.Archived = "all"
	}
	if status == "all" {
		status = ""
	}
	query.Status = status
	if engine == "all" {
		engine = ""
	}
	query.Engine = engine
	if pageText != "" {
		page, err := strconv.Atoi(pageText)
		if err != nil || page < 1 {
			return repo.TaskListQuery{}, true, false
		}
		query.Page = page
	}
	if pageSizeText != "" {
		pageSize, err := strconv.Atoi(pageSizeText)
		if err != nil || pageSize < 1 {
			return repo.TaskListQuery{}, true, false
		}
		query.PageSize = pageSize
	} else {
		query.PageSize = repo.DefaultTaskPageSize
	}
	if _, err := repo.NormalizeTaskListQuery(query); err != nil {
		return repo.TaskListQuery{}, true, false
	}
	return query, true, true
}
