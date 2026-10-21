package api

import (
	"context"
	"net/http"
	"strconv"

	"scanner-platform/internal/assets"
)

type assetPageReader interface {
	ListPage(context.Context, assets.ListQuery) (assets.ListPage, error)
}

func parseAssetListQuery(r *http.Request) (assets.ListQuery, bool, bool) {
	values := r.URL.Query()
	if len(values) == 0 {
		return assets.ListQuery{}, false, true
	}
	for key := range values {
		switch key {
		case "page", "page_size", "q", "sort":
		default:
			return assets.ListQuery{}, true, false
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
	sort, sortOK := single("sort")
	if !pageOK || !pageSizeOK || !searchOK || !sortOK {
		return assets.ListQuery{}, true, false
	}
	query := assets.ListQuery{Page: 1, Search: search, Sort: sort}
	if pageText != "" {
		page, err := strconv.Atoi(pageText)
		if err != nil || page < 1 {
			return assets.ListQuery{}, true, false
		}
		query.Page = page
	}
	if pageSizeText != "" {
		pageSize, err := strconv.Atoi(pageSizeText)
		if err != nil || pageSize < 1 {
			return assets.ListQuery{}, true, false
		}
		query.PageSize = pageSize
	}
	if _, err := assets.NormalizeListQuery(query); err != nil {
		return assets.ListQuery{}, true, false
	}
	return query, true, true
}
