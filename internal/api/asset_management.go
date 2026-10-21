package api

import (
	"errors"
	"net/http"
	"strings"

	"scanner-platform/internal/account"
	"scanner-platform/internal/assets"
)

// registerAssetManagementHandlers exposes safe summaries for the asset
// registry. It is intentionally optional so older Repository implementations
// fail closed with 501 rather than silently returning incomplete data.
func registerAssetManagementHandlers(mux *http.ServeMux, accounts account.Repository, store assets.Repository) {
	groups, groupsAvailable := store.(assets.BusinessGroupRepository)
	history, historyAvailable := store.(assets.ImportHistoryRepository)

	mux.HandleFunc("GET /api/v1/business-groups", auth(accounts, false, func(w http.ResponseWriter, r *http.Request, _ account.User) {
		if !groupsAvailable {
			bad(w, http.StatusNotImplemented, "business_group_unavailable")
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
		items, err := history.ListImportHistory(r.Context())
		if err != nil {
			bad(w, http.StatusInternalServerError, "db_error")
			return
		}
		respond(w, http.StatusOK, ListResponse[assets.ImportHistory]{Items: items, Total: len(items)})
	}))
}
