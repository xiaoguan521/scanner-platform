package api

import (
	"errors"
	"io"
	"net/http"
	"scanner-platform/internal/repo"
	"scanner-platform/internal/rules"
)

func registerRuleHandlers(mux *http.ServeMux, store repo.RuntimeBackend, ui func(bool, http.HandlerFunc) http.HandlerFunc, actor func(*http.Request) string) {
	mux.HandleFunc("GET /api/v1/custom-rules", ui(false, func(w http.ResponseWriter, r *http.Request) {
		if query, paged, ok := parseCustomRuleListQuery(r); paged {
			if !ok {
				bad(w, http.StatusBadRequest, "invalid_custom_rule_list_query")
				return
			}
			page, err := store.ListCustomRulesPage(r.Context(), query)
			if errors.Is(err, repo.ErrInvalidCustomRuleListQuery) {
				bad(w, http.StatusBadRequest, "invalid_custom_rule_list_query")
				return
			}
			if !runtimeStoreError(w, err) {
				runtimeJSON(w, http.StatusOK, PageListResponse[rules.CustomRule]{Items: page.Items, Total: page.Total, Page: page.Page, PageSize: page.PageSize})
			}
			return
		}
		items, err := store.ListCustomRules(r.Context())
		if !runtimeStoreError(w, err) {
			runtimeJSON(w, 200, ListResponse[rules.CustomRule]{Items: items, Total: len(items)})
		}
	}))
	writeCustomRule := func(w http.ResponseWriter, r *http.Request, create bool) {
		var body rules.CustomRule
		if !runtimeDecode(w, r, &body) {
			return
		}
		if !create {
			id := r.PathValue("id")
			if body.ID != "" && body.ID != id {
				bad(w, 400, "custom_rule_id_mismatch")
				return
			}
			body.ID = id
		}
		item, err := store.SaveCustomRule(r.Context(), actor(r), body, create)
		if errors.Is(err, repo.ErrInvalidCustomRule) {
			bad(w, 400, "invalid_custom_rule")
			return
		}
		if errors.Is(err, repo.ErrCustomRuleConflict) {
			bad(w, http.StatusConflict, "custom_rule_conflict")
			return
		}
		if !runtimeStoreError(w, err) {
			code := http.StatusOK
			if create {
				code = http.StatusCreated
			}
			runtimeJSON(w, code, item)
		}
	}
	mux.HandleFunc("POST /api/v1/custom-rules", ui(true, func(w http.ResponseWriter, r *http.Request) { writeCustomRule(w, r, true) }))
	mux.HandleFunc("PUT /api/v1/custom-rules/{id}", ui(true, func(w http.ResponseWriter, r *http.Request) { writeCustomRule(w, r, false) }))
	mux.HandleFunc("DELETE /api/v1/custom-rules/{id}", ui(true, func(w http.ResponseWriter, r *http.Request) {
		if err := store.DeleteCustomRule(r.Context(), r.PathValue("id"), actor(r)); errors.Is(err, repo.ErrCustomRuleConflict) {
			bad(w, http.StatusConflict, "custom_rule_conflict")
		} else if !runtimeStoreError(w, err) {
			runtimeJSON(w, 200, map[string]string{"status": "DELETED"})
		}
	}))
	mux.HandleFunc("GET /api/v1/rules", ui(false, func(w http.ResponseWriter, r *http.Request) {
		if query, paged, ok := parseRuleListQuery(r); paged {
			if !ok {
				bad(w, http.StatusBadRequest, "invalid_rule_list_query")
				return
			}
			page, err := store.ListRulesPage(r.Context(), query)
			if errors.Is(err, repo.ErrInvalidRuleListQuery) {
				bad(w, http.StatusBadRequest, "invalid_rule_list_query")
				return
			}
			if !runtimeStoreError(w, err) {
				runtimeJSON(w, http.StatusOK, PageListResponse[rules.Bundle]{Items: page.Items, Total: page.Total, Page: page.Page, PageSize: page.PageSize})
			}
			return
		}
		items, err := store.ListRules(r.Context())
		if !runtimeStoreError(w, err) {
			runtimeJSON(w, 200, ListResponse[rules.Bundle]{Items: items, Total: len(items)})
		}
	}))
	mux.HandleFunc("GET /api/v1/rule-jobs", ui(false, func(w http.ResponseWriter, r *http.Request) {
		if query, paged, ok := parseRuleJobListQuery(r); paged {
			if !ok {
				bad(w, http.StatusBadRequest, "invalid_rule_job_list_query")
				return
			}
			page, err := store.ListRuleJobsPage(r.Context(), query)
			if errors.Is(err, repo.ErrInvalidRuleJobListQuery) {
				bad(w, http.StatusBadRequest, "invalid_rule_job_list_query")
				return
			}
			if !runtimeStoreError(w, err) {
				runtimeJSON(w, http.StatusOK, PageListResponse[rules.Job]{Items: page.Items, Total: page.Total, Page: page.Page, PageSize: page.PageSize})
			}
			return
		}
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
		if nodeID := AuthenticatedNodeID(r); nodeID != "" && body.NodeID != nodeID {
			bad(w, http.StatusUnauthorized, "node_identity_mismatch")
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
		if nodeID := AuthenticatedNodeID(r); nodeID != "" && body.NodeID != nodeID {
			bad(w, http.StatusUnauthorized, "node_identity_mismatch")
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
		if nodeID := AuthenticatedNodeID(r); nodeID != "" && body.NodeID != nodeID {
			bad(w, http.StatusUnauthorized, "node_identity_mismatch")
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
