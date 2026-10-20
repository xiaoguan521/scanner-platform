package api

import (
	"net/http"

	"scanner-platform/internal/repo"
)

func registerFindingRetestHandlers(mux *http.ServeMux, store *repo.RuntimeStore, ui func(bool, http.HandlerFunc) http.HandlerFunc, actor func(*http.Request) string) {
	mux.HandleFunc("POST /api/v1/findings/{id}/retest", ui(true, func(w http.ResponseWriter, r *http.Request) {
		var body struct{}
		if !runtimeDecode(w, r, &body) {
			return
		}
		task, retest, err := store.CreateFindingRetest(r.Context(), r.PathValue("id"), actor(r))
		if !runtimeStoreError(w, err) {
			runtimeJSON(w, http.StatusCreated, map[string]any{"task": task, "retest": retest})
		}
	}))
	mux.HandleFunc("GET /api/v1/findings/{id}/retests", ui(false, func(w http.ResponseWriter, r *http.Request) {
		items, err := store.ListFindingRetests(r.Context(), r.PathValue("id"))
		if !runtimeStoreError(w, err) {
			runtimeJSON(w, http.StatusOK, ListResponse[repo.FindingRetest]{Items: items, Total: len(items)})
		}
	}))
}
