package api

import (
	"net/http"
	"scanner-platform/internal/account"
	"scanner-platform/internal/repo"
)

func registerFindingWorkHandlers(mux *http.ServeMux, store *repo.RuntimeStore, ui func(bool, http.HandlerFunc) http.HandlerFunc, actor func(*http.Request) string, accounts ...account.Repository) {
	guarded := func(write bool, handler http.HandlerFunc) http.HandlerFunc {
		return ui(write, func(w http.ResponseWriter, r *http.Request) {
			if len(accounts) == 0 {
				bad(w, http.StatusServiceUnavailable, "authentication_required")
				return
			}
			handler(w, r)
		})
	}
	mux.HandleFunc("GET /api/v1/findings/assignees", guarded(false, func(w http.ResponseWriter, r *http.Request) {
		user, err := accounts[0].Session(r.Context(), sessionToken(r))
		if err != nil {
			bad(w, http.StatusUnauthorized, "authentication_required")
			return
		}
		if user.Role != "admin" && user.Role != "security_engineer" {
			bad(w, http.StatusForbidden, "forbidden")
			return
		}
		items, err := store.ListFindingAssignees(r.Context())
		if !runtimeStoreError(w, err) {
			runtimeJSON(w, 200, ListResponse[repo.FindingAssignee]{Items: items, Total: len(items)})
		}
	}))
	mux.HandleFunc("PUT /api/v1/findings/{id}/assignee", guarded(true, func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			AssigneeID *string `json:"assigneeId"`
		}
		if !runtimeDecode(w, r, &body) {
			return
		}
		if body.AssigneeID == nil {
			bad(w, 400, "assignee_id_required")
			return
		}
		item, err := store.AssignFinding(r.Context(), r.PathValue("id"), *body.AssigneeID, actor(r))
		if !runtimeStoreError(w, err) {
			runtimeJSON(w, 200, item)
		}
	}))
	mux.HandleFunc("GET /api/v1/findings/{id}/assignments", guarded(false, func(w http.ResponseWriter, r *http.Request) {
		items, err := store.ListFindingAssignmentEvents(r.Context(), r.PathValue("id"))
		if !runtimeStoreError(w, err) {
			runtimeJSON(w, 200, ListResponse[repo.FindingAssignmentEvent]{Items: items, Total: len(items)})
		}
	}))
	mux.HandleFunc("POST /api/v1/findings/batch-assignment", guarded(true, func(w http.ResponseWriter, r *http.Request) {
		var body repo.FindingBatchAssignment
		if !runtimeDecode(w, r, &body) {
			return
		}
		items, err := store.BatchAssignFindings(r.Context(), body, actor(r))
		if !runtimeStoreError(w, err) {
			runtimeJSON(w, http.StatusOK, map[string]any{"updated": len(items), "items": items})
		}
	}))
	mux.HandleFunc("GET /api/v1/findings/{id}/notes", guarded(false, func(w http.ResponseWriter, r *http.Request) {
		items, err := store.ListFindingNotes(r.Context(), r.PathValue("id"))
		if !runtimeStoreError(w, err) {
			runtimeJSON(w, 200, ListResponse[repo.FindingNote]{Items: items, Total: len(items)})
		}
	}))
	mux.HandleFunc("POST /api/v1/findings/{id}/notes", guarded(true, func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Body string `json:"body"`
		}
		if !runtimeDecode(w, r, &body) {
			return
		}
		item, err := store.AddFindingNote(r.Context(), r.PathValue("id"), body.Body, actor(r))
		if !runtimeStoreError(w, err) {
			runtimeJSON(w, 201, item)
		}
	}))
}
