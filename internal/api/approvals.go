package api

import (
	"errors"
	"net/http"

	"scanner-platform/internal/account"
	"scanner-platform/internal/approvals"
)

// These endpoints store administrative approval records only. They do not
// grant a Worker any scan lease, firewall exception, or rule activation.
func registerApprovalHandlers(mux *http.ServeMux, users account.Repository, repo approvals.Repository) {
	mayRequest := func(u account.User) bool { return u.Role == "admin" || u.Role == "security_engineer" }
	mayReview := func(u account.User) bool { return u.Role == "admin" || u.Role == "ops_approver" }
	handleError := func(w http.ResponseWriter, err error) {
		switch {
		case errors.Is(err, approvals.ErrInvalid):
			bad(w, 400, "invalid_approval")
		case errors.Is(err, approvals.ErrForbidden):
			bad(w, 403, "forbidden")
		case errors.Is(err, approvals.ErrMissing):
			bad(w, 404, "not_found")
		case errors.Is(err, approvals.ErrConflict):
			bad(w, 409, "approval_conflict")
		default:
			bad(w, 500, "db_error")
		}
	}
	mux.HandleFunc("GET /api/v1/scopes", auth(users, false, func(w http.ResponseWriter, r *http.Request, _ account.User) {
		query, paged, ok := parseScopeListQuery(r)
		if !ok {
			bad(w, http.StatusBadRequest, "invalid_scope_list_query")
			return
		}
		if paged {
			pageRepo, available := repo.(approvals.ScopePageRepository)
			if !available {
				bad(w, http.StatusNotImplemented, "scope_pagination_unavailable")
				return
			}
			page, err := pageRepo.ListScopesPage(r.Context(), query)
			if err != nil {
				if errors.Is(err, approvals.ErrInvalid) {
					bad(w, http.StatusBadRequest, "invalid_scope_list_query")
				} else {
					bad(w, http.StatusInternalServerError, "db_error")
				}
				return
			}
			respond(w, http.StatusOK, ScopePageResponse{Items: page.Items, Total: page.Total, Page: page.Page, PageSize: page.PageSize, ExpiringCount: page.ExpiringCount, ExpiredCount: page.ExpiredCount})
			return
		}
		items, err := repo.ListScopes(r.Context())
		if err != nil {
			handleError(w, err)
			return
		}
		respond(w, 200, ListResponse[approvals.Scope]{Items: items, Total: len(items)})
	}))
	mux.HandleFunc("POST /api/v1/scopes", auth(users, false, func(w http.ResponseWriter, r *http.Request, u account.User) {
		if !mayRequest(u) {
			bad(w, 403, "forbidden")
			return
		}
		if !mutationGuard(w, r) {
			return
		}
		var in approvals.ScopeInput
		if !readJSON(w, r, &in) {
			return
		}
		item, err := repo.RequestScope(r.Context(), u.ID, in)
		if err != nil {
			handleError(w, err)
			return
		}
		respond(w, 201, item)
	}))
	mux.HandleFunc("PUT /api/v1/scopes/{id}", auth(users, false, func(w http.ResponseWriter, r *http.Request, u account.User) {
		if !mayRequest(u) {
			bad(w, 403, "forbidden")
			return
		}
		if !mutationGuard(w, r) {
			return
		}
		var in approvals.ScopeInput
		if !readJSON(w, r, &in) {
			return
		}
		item, err := repo.UpdateScope(r.Context(), u.ID, r.PathValue("id"), in)
		if err != nil {
			handleError(w, err)
			return
		}
		respond(w, 200, item)
	}))
	mux.HandleFunc("DELETE /api/v1/scopes/{id}", auth(users, false, func(w http.ResponseWriter, r *http.Request, u account.User) {
		if !mayRequest(u) {
			bad(w, 403, "forbidden")
			return
		}
		if !mutationGuard(w, r) {
			return
		}
		if err := repo.DeleteScope(r.Context(), u.ID, r.PathValue("id")); err != nil {
			handleError(w, err)
			return
		}
		respond(w, 200, map[string]string{"status": "DELETED"})
	}))
	mux.HandleFunc("POST /api/v1/scopes/{id}/revoke", auth(users, false, func(w http.ResponseWriter, r *http.Request, u account.User) {
		if !mayRequest(u) && !mayReview(u) {
			bad(w, 403, "forbidden")
			return
		}
		if !mutationGuard(w, r) {
			return
		}
		item, err := repo.RevokeScope(r.Context(), u.ID, r.PathValue("id"))
		if err != nil {
			handleError(w, err)
			return
		}
		respond(w, 200, item)
	}))
	mux.HandleFunc("POST /api/v1/scopes/{id}/review", auth(users, false, func(w http.ResponseWriter, r *http.Request, u account.User) {
		if !mayReview(u) {
			bad(w, 403, "forbidden")
			return
		}
		if !mutationGuard(w, r) {
			return
		}
		var decision approvals.Decision
		if !readJSON(w, r, &decision) {
			return
		}
		item, err := repo.ReviewScope(r.Context(), u.ID, r.PathValue("id"), decision)
		if err != nil {
			handleError(w, err)
			return
		}
		respond(w, 200, item)
	}))
	mux.HandleFunc("GET /api/v1/port-requests", auth(users, false, func(w http.ResponseWriter, r *http.Request, _ account.User) {
		query, paged, ok := parsePortRequestListQuery(r)
		if !ok {
			bad(w, http.StatusBadRequest, "invalid_port_request_list_query")
			return
		}
		if paged {
			pageRepo, available := repo.(approvals.PortRequestPageRepository)
			if !available {
				bad(w, http.StatusNotImplemented, "port_request_pagination_unavailable")
				return
			}
			page, err := pageRepo.ListPortRequestsPage(r.Context(), query)
			if err != nil {
				if errors.Is(err, approvals.ErrInvalid) {
					bad(w, http.StatusBadRequest, "invalid_port_request_list_query")
				} else {
					bad(w, http.StatusInternalServerError, "db_error")
				}
				return
			}
			respond(w, http.StatusOK, PageListResponse[approvals.PortRequest]{Items: page.Items, Total: page.Total, Page: page.Page, PageSize: page.PageSize})
			return
		}
		items, err := repo.ListPortRequests(r.Context())
		if err != nil {
			handleError(w, err)
			return
		}
		respond(w, 200, ListResponse[approvals.PortRequest]{Items: items, Total: len(items)})
	}))
	mux.HandleFunc("POST /api/v1/port-requests/{assetId}/{port}/review", auth(users, false, func(w http.ResponseWriter, r *http.Request, u account.User) {
		if !mayReview(u) {
			bad(w, 403, "forbidden")
			return
		}
		if !mutationGuard(w, r) {
			return
		}
		port, err := parsePort(r.PathValue("port"))
		if err != nil {
			bad(w, 400, "invalid_port")
			return
		}
		var decision approvals.Decision
		if !readJSON(w, r, &decision) {
			return
		}
		item, err := repo.ReviewPort(r.Context(), u.ID, r.PathValue("assetId"), port, decision)
		if err != nil {
			handleError(w, err)
			return
		}
		respond(w, 200, item)
	}))
}
