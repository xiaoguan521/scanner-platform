package api

import (
	"net/http"
	"strconv"
	"strings"

	"scanner-platform/internal/repo"
)

func parseKnowledgeListQuery(r *http.Request) (repo.KnowledgeListQuery, bool, bool) {
	values := r.URL.Query()
	paged := false
	for key := range values {
		switch key {
		case "page", "page_size", "q":
			paged = true
		default:
			return repo.KnowledgeListQuery{}, false, false
		}
	}
	if !paged {
		return repo.KnowledgeListQuery{}, false, true
	}
	single := func(key string) (string, bool) {
		items, present := values[key]
		if !present {
			return "", true
		}
		if len(items) != 1 {
			return "", false
		}
		return items[0], true
	}
	pageText, ok := single("page")
	if !ok {
		return repo.KnowledgeListQuery{}, true, false
	}
	pageSizeText, ok := single("page_size")
	if !ok {
		return repo.KnowledgeListQuery{}, true, false
	}
	search, ok := single("q")
	if !ok || len(search) > 160 || strings.IndexByte(search, 0) >= 0 {
		return repo.KnowledgeListQuery{}, true, false
	}
	query := repo.KnowledgeListQuery{Search: strings.TrimSpace(search)}
	var err error
	if pageText != "" {
		query.Page, err = strconv.Atoi(pageText)
		if err != nil || query.Page < 1 || query.Page > 100000 {
			return repo.KnowledgeListQuery{}, true, false
		}
	}
	if pageSizeText != "" {
		query.PageSize, err = strconv.Atoi(pageSizeText)
		if err != nil || query.PageSize < 1 || query.PageSize > 100 {
			return repo.KnowledgeListQuery{}, true, false
		}
	}
	return query, true, true
}

func parseNotificationListQuery(r *http.Request) (repo.NotificationListQuery, bool, bool) {
	values := r.URL.Query()
	paged := false
	for key := range values {
		switch key {
		case "page", "page_size":
			paged = true
		case "unread":
		default:
			return repo.NotificationListQuery{}, false, false
		}
	}
	single := func(key string) (string, bool, bool) {
		items, present := values[key]
		if !present {
			return "", false, true
		}
		if len(items) != 1 {
			return "", true, false
		}
		return items[0], true, true
	}
	unreadText, unreadPresent, ok := single("unread")
	if !ok {
		return repo.NotificationListQuery{}, paged, false
	}
	unreadOnly := false
	if unreadPresent {
		parsed, err := strconv.ParseBool(unreadText)
		if err != nil {
			return repo.NotificationListQuery{}, paged, false
		}
		unreadOnly = parsed
	}
	if !paged {
		return repo.NotificationListQuery{UnreadOnly: unreadOnly}, false, true
	}
	pageText, _, ok := single("page")
	if !ok {
		return repo.NotificationListQuery{}, true, false
	}
	pageSizeText, _, ok := single("page_size")
	if !ok {
		return repo.NotificationListQuery{}, true, false
	}
	query := repo.NotificationListQuery{UnreadOnly: unreadOnly}
	var err error
	if pageText != "" {
		query.Page, err = strconv.Atoi(pageText)
		if err != nil || query.Page < 1 || query.Page > 100000 {
			return repo.NotificationListQuery{}, true, false
		}
	}
	if pageSizeText != "" {
		query.PageSize, err = strconv.Atoi(pageSizeText)
		if err != nil || query.PageSize < 1 || query.PageSize > 100 {
			return repo.NotificationListQuery{}, true, false
		}
	}
	return query, true, true
}
