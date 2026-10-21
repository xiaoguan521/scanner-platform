package api

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"scanner-platform/internal/account"
	"scanner-platform/internal/assets"
)

// registerAssetManagementHandlers exposes safe summaries for the asset
// registry. It is intentionally optional so older Repository implementations
// fail closed with 501 rather than silently returning incomplete data.
func registerAssetManagementHandlers(mux *http.ServeMux, accounts account.Repository, store assets.Repository) {
	groups, groupsAvailable := store.(assets.BusinessGroupRepository)
	groupPages, groupPagesAvailable := store.(assets.BusinessGroupPageRepository)
	history, historyAvailable := store.(assets.ImportHistoryRepository)
	historyPages, historyPagesAvailable := store.(assets.ImportHistoryPageRepository)

	mux.HandleFunc("GET /api/v1/business-groups", auth(accounts, false, func(w http.ResponseWriter, r *http.Request, _ account.User) {
		if !groupsAvailable {
			bad(w, http.StatusNotImplemented, "business_group_unavailable")
			return
		}
		query, paged, ok := parseAssetManagementListQuery(r)
		if !ok {
			bad(w, http.StatusBadRequest, "invalid_business_group_list_query")
			return
		}
		if paged {
			if !groupPagesAvailable {
				bad(w, http.StatusNotImplemented, "business_group_unavailable")
				return
			}
			page, err := groupPages.ListBusinessGroupsPage(r.Context(), assets.BusinessGroupListQuery{Page: query.page, PageSize: query.pageSize, Search: query.search})
			if err != nil {
				if errors.Is(err, assets.ErrInvalid) {
					bad(w, http.StatusBadRequest, "invalid_business_group_list_query")
				} else {
					bad(w, http.StatusInternalServerError, "db_error")
				}
				return
			}
			respond(w, http.StatusOK, PageListResponse[assets.BusinessGroup]{Items: page.Items, Total: page.Total, Page: page.Page, PageSize: page.PageSize})
			return
		}
		items, err := groups.ListBusinessGroups(r.Context())
		if err != nil {
			bad(w, http.StatusInternalServerError, "db_error")
			return
		}
		respond(w, http.StatusOK, ListResponse[assets.BusinessGroup]{Items: items, Total: len(items)})
	}))

	mux.HandleFunc("POST /api/v1/business-groups", auth(accounts, false, func(w http.ResponseWriter, r *http.Request, u account.User) {
		if u.Role != "admin" && u.Role != "security_engineer" {
			bad(w, http.StatusForbidden, "forbidden")
			return
		}
		if !groupsAvailable {
			bad(w, http.StatusNotImplemented, "business_group_unavailable")
			return
		}
		if !mutationGuard(w, r) {
			return
		}
		var body struct {
			Name string `json:"name"`
		}
		if !readJSON(w, r, &body) {
			return
		}
		item, err := groups.CreateBusinessGroup(r.Context(), u.ID, strings.TrimSpace(body.Name))
		if err != nil {
			switch {
			case errors.Is(err, assets.ErrBusinessGroupInvalid):
				bad(w, http.StatusBadRequest, "invalid_business_group")
			case errors.Is(err, assets.ErrBusinessGroupExists):
				bad(w, http.StatusConflict, "business_group_exists")
			default:
				bad(w, http.StatusInternalServerError, "db_error")
			}
			return
		}
		respond(w, http.StatusCreated, item)
	}))

	mux.HandleFunc("GET /api/v1/assets/import-history", auth(accounts, false, func(w http.ResponseWriter, r *http.Request, _ account.User) {
		if !historyAvailable {
			bad(w, http.StatusNotImplemented, "asset_import_history_unavailable")
			return
		}
		query, paged, ok := parseAssetManagementListQuery(r)
		if !ok {
			bad(w, http.StatusBadRequest, "invalid_asset_import_history_list_query")
			return
		}
		if paged {
			if !historyPagesAvailable {
				bad(w, http.StatusNotImplemented, "asset_import_history_unavailable")
				return
			}
			page, err := historyPages.ListImportHistoryPage(r.Context(), assets.ImportHistoryListQuery{Page: query.page, PageSize: query.pageSize, Search: query.search})
			if err != nil {
				if errors.Is(err, assets.ErrInvalid) {
					bad(w, http.StatusBadRequest, "invalid_asset_import_history_list_query")
				} else {
					bad(w, http.StatusInternalServerError, "db_error")
				}
				return
			}
			respond(w, http.StatusOK, PageListResponse[assets.ImportHistory]{Items: page.Items, Total: page.Total, Page: page.Page, PageSize: page.PageSize})
			return
		}
		items, err := history.ListImportHistory(r.Context())
		if err != nil {
			bad(w, http.StatusInternalServerError, "db_error")
			return
		}
		respond(w, http.StatusOK, ListResponse[assets.ImportHistory]{Items: items, Total: len(items)})
	}))
}

type assetManagementListQuery struct {
	page     int
	pageSize int
	search   string
}

func parseAssetManagementListQuery(r *http.Request) (assetManagementListQuery, bool, bool) {
	values := r.URL.Query()
	paged := false
	for key := range values {
		switch key {
		case "page", "page_size", "q":
			paged = true
		default:
			return assetManagementListQuery{}, false, false
		}
	}
	if !paged {
		return assetManagementListQuery{}, false, true
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
		return assetManagementListQuery{}, true, false
	}
	pageSizeText, ok := single("page_size")
	if !ok {
		return assetManagementListQuery{}, true, false
	}
	search, ok := single("q")
	if !ok || len(search) > 160 || strings.IndexByte(search, 0) >= 0 {
		return assetManagementListQuery{}, true, false
	}
	page, pageSize := 0, 0
	var err error
	if pageText != "" {
		page, err = strconv.Atoi(pageText)
		if err != nil || page < 1 || page > 100000 {
			return assetManagementListQuery{}, true, false
		}
	}
	if pageSizeText != "" {
		pageSize, err = strconv.Atoi(pageSizeText)
		if err != nil || pageSize < 1 || pageSize > 100 {
			return assetManagementListQuery{}, true, false
		}
	}
	return assetManagementListQuery{page: page, pageSize: pageSize, search: strings.TrimSpace(search)}, true, true
}
