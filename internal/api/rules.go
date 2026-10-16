package api

import (
	"io"
	"net/http"
	"scanner-platform/internal/repo"
	"scanner-platform/internal/rules"
)

func registerRuleHandlers(mux *http.ServeMux, store *repo.RuntimeStore, ui func(bool, http.HandlerFunc) http.HandlerFunc, actor func(*http.Request) string) {
	mux.HandleFunc("GET /api/v1/rules", ui(false, func(w http.ResponseWriter, r *http.Request) {
		items, err := store.ListRules(r.Context())
		if !runtimeStoreError(w, err) {
			runtimeJSON(w, 200, ListResponse[rules.Bundle]{Items: items, Total: len(items)})
		}
	}))
	mux.HandleFunc("GET /api/v1/rule-jobs", ui(false, func(w http.ResponseWriter, r *http.Request) {
		items, err := store.ListRuleJobs(r.Context())
		if !runtimeStoreError(w, err) {
			runtimeJSON(w, 200, ListResponse[rules.Job]{Items: items, Total: len(items)})
		}
	}))
	mux.HandleFunc("POST /api/v1/rules/import", ui(true, func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, rules.MaxArchive+(1<<20))
		if err := r.ParseMultipartForm(1 << 20); err != nil {
			bad(w, 400, "invalid_or_oversized_zip")
			return
		}
		defer r.MultipartForm.RemoveAll()
		file, _, err := r.FormFile("bundle")
		if err != nil {
			bad(w, 400, "bundle_required")
			return
		}
		defer file.Close()
		data, err := io.ReadAll(io.LimitReader(file, rules.MaxArchive+1))
		if err != nil || len(data) > rules.MaxArchive {
			bad(w, 400, "oversized_zip")
			return
		}
		job, err := store.QueueRuleJob(r.Context(), rules.Job{Kind: "IMPORT", Bundle: data}, actor(r))
		if !runtimeStoreError(w, err) {
			runtimeJSON(w, 202, job)
		}
	}))
	mux.HandleFunc("POST /api/v1/rules/fetch", ui(true, func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			URL            string `json:"url"`
			ExpectedSHA256 string `json:"expectedSha256"`
		}
		if !runtimeDecode(w, r, &body) {
			return
		}
		job, err := store.QueueRuleJob(r.Context(), rules.Job{Kind: "FETCH", URL: body.URL, ExpectedSHA256: body.ExpectedSHA256}, actor(r))
		if !runtimeStoreError(w, err) {
			runtimeJSON(w, 202, job)
		}
	}))
	mux.HandleFunc("POST /api/v1/rules/{version}/activate", ui(true, func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Rollback bool `json:"rollback"`
		}
		if !runtimeDecode(w, r, &body) {
			return
		}
		job, err := store.QueueRuleJob(r.Context(), rules.Job{Kind: "ACTIVATE", Version: r.PathValue("version"), Rollback: body.Rollback}, actor(r))
		if !runtimeStoreError(w, err) {
			runtimeJSON(w, 202, job)
		}
	}))
	mux.HandleFunc("POST /api/v1/updater/claim", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			NodeID string `json:"nodeId"`
		}
		if !runtimeDecode(w, r, &body) {
			return
		}
		if !runtimeWorkerID.MatchString(body.NodeID) {
			bad(w, 400, "invalid_node")
			return
		}
		if runtimeStoreError(w, store.TouchNode(r.Context(), body.NodeID, "updater", "")) {
			return
		}
		job, err := store.ClaimRuleJob(r.Context(), body.NodeID)
		if runtimeStoreError(w, err) {
			return
		}
		if job == nil {
			w.WriteHeader(204)
			return
		}
		if runtimeStoreError(w, store.TouchNode(r.Context(), body.NodeID, "updater", job.ID)) {
			return
		}
		runtimeJSON(w, 200, job)
	})
	mux.HandleFunc("POST /api/v1/updater/report", func(w http.ResponseWriter, r *http.Request) {
		var body rules.Report
		if !runtimeDecodeLimit(w, r, &body, 2<<20) {
			return
		}
		if !runtimeWorkerID.MatchString(body.NodeID) {
			bad(w, 400, "invalid_node")
			return
		}
		if !runtimeStoreError(w, store.ReportRuleJob(r.Context(), body)) {
			runtimeJSON(w, 200, map[string]string{"state": "recorded"})
		}
	})
	mux.HandleFunc("POST /api/v1/updater/state", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			NodeID  string         `json:"nodeId"`
			Bundles []rules.Bundle `json:"bundles"`
		}
		if !runtimeDecodeLimit(w, r, &body, 2<<20) {
			return
		}
		if !runtimeWorkerID.MatchString(body.NodeID) {
			bad(w, 400, "invalid_node")
			return
		}
		if !runtimeStoreError(w, store.SyncRules(r.Context(), body.Bundles)) {
			runtimeJSON(w, 200, map[string]string{"state": "synced"})
		}
	})
}
