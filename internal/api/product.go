package api

import (
	"errors"
	"net/http"
	"scanner-platform/internal/findings"
	"scanner-platform/internal/repo"
	"scanner-platform/internal/scanplans"
	"scanner-platform/internal/taskflow"
)

func registerProductHandlers(mux *http.ServeMux, store *repo.RuntimeStore, ui func(bool, http.HandlerFunc) http.HandlerFunc, admin func(http.HandlerFunc) http.HandlerFunc, adminRead func(http.HandlerFunc) http.HandlerFunc, actor func(*http.Request) string) {
	registerDashboardHandlers(mux, store, ui)
	registerTaskDetailHandlers(mux, store, ui)
	mux.HandleFunc("GET /api/v1/audit-logs", adminRead(func(w http.ResponseWriter, r *http.Request) {
		query, err := parseAuditLogQuery(r)
		if err != nil {
			bad(w, http.StatusBadRequest, "invalid_audit_filter")
			return
		}
		items, total, err := store.ListAuditLogs(r.Context(), query)
		if !runtimeStoreError(w, err) {
			runtimeJSON(w, http.StatusOK, ListResponse[repo.AuditLog]{Items: items, Total: total})
		}
	}))
	mux.HandleFunc("GET /api/v1/detection-capabilities", ui(false, func(w http.ResponseWriter, r *http.Request) {
		items := findings.Capabilities()
		runtimeJSON(w, 200, ListResponse[findings.Capability]{Items: items, Total: len(items)})
	}))
	mux.HandleFunc("GET /api/v1/scan-plans", ui(false, func(w http.ResponseWriter, r *http.Request) {
		items, err := store.ListScanPlans(r.Context())
		if !runtimeStoreError(w, err) {
			runtimeJSON(w, http.StatusOK, ListResponse[scanplans.Plan]{Items: items, Total: len(items)})
		}
	}))
	writeScanPlan := func(w http.ResponseWriter, r *http.Request, update bool) {
		var body scanplans.Input
		if !runtimeDecode(w, r, &body) {
			return
		}
		id := ""
		if update {
			id = r.PathValue("id")
		}
		item, err := store.SaveScanPlan(r.Context(), actor(r), body, id, update)
		if errors.Is(err, repo.ErrInvalidScanPlan) || errors.Is(err, scanplans.ErrInvalid) {
			bad(w, http.StatusBadRequest, "invalid_scan_plan")
			return
		}
		if errors.Is(err, repo.ErrScanPlanConflict) {
			bad(w, http.StatusConflict, "scan_plan_conflict")
			return
		}
		if !runtimeStoreError(w, err) {
			status := http.StatusOK
			if !update {
				status = http.StatusCreated
			}
			runtimeJSON(w, status, item)
		}
	}
	mux.HandleFunc("POST /api/v1/scan-plans", ui(true, func(w http.ResponseWriter, r *http.Request) { writeScanPlan(w, r, false) }))
	mux.HandleFunc("PUT /api/v1/scan-plans/{id}", ui(true, func(w http.ResponseWriter, r *http.Request) { writeScanPlan(w, r, true) }))
	mux.HandleFunc("DELETE /api/v1/scan-plans/{id}", ui(true, func(w http.ResponseWriter, r *http.Request) {
		err := store.DeleteScanPlan(r.Context(), r.PathValue("id"), actor(r))
		if errors.Is(err, repo.ErrScanPlanConflict) {
			bad(w, http.StatusConflict, "scan_plan_conflict")
		} else if !runtimeStoreError(w, err) {
			runtimeJSON(w, http.StatusOK, map[string]string{"status": "DELETED"})
		}
	}))
	mux.HandleFunc("GET /api/v1/vulnerability-categories", ui(false, func(w http.ResponseWriter, r *http.Request) {
		items := findings.Categories()
		runtimeJSON(w, 200, ListResponse[findings.Category]{Items: items, Total: len(items)})
	}))
	mux.HandleFunc("GET /api/v1/scan-policy", ui(false, func(w http.ResponseWriter, r *http.Request) {
		p, err := store.GetScanPolicy(r.Context())
		if !runtimeStoreError(w, err) {
			runtimeJSON(w, 200, p)
		}
	}))
	mux.HandleFunc("PUT /api/v1/scan-policy", admin(func(w http.ResponseWriter, r *http.Request) {
		var p repo.ScanPolicy
		if !runtimeDecode(w, r, &p) {
			return
		}
		saved, err := store.SaveScanPolicy(r.Context(), p, actor(r))
		if !runtimeStoreError(w, err) {
			runtimeJSON(w, 200, saved)
		}
	}))
	mux.HandleFunc("GET /api/v1/system-settings", adminRead(func(w http.ResponseWriter, r *http.Request) {
		settings, err := store.GetSystemSettings(r.Context())
		if !runtimeStoreError(w, err) {
			runtimeJSON(w, http.StatusOK, settings)
		}
	}))
	mux.HandleFunc("PUT /api/v1/system-settings", admin(func(w http.ResponseWriter, r *http.Request) {
		var settings repo.SystemSettings
		if !runtimeDecode(w, r, &settings) {
			return
		}
		saved, err := store.SaveSystemSettings(r.Context(), settings, actor(r))
		if errors.Is(err, repo.ErrInvalidTask) {
			bad(w, http.StatusBadRequest, "invalid_system_settings")
			return
		}
		if !runtimeStoreError(w, err) {
			runtimeJSON(w, http.StatusOK, saved)
		}
	}))
	mux.HandleFunc("GET /api/v1/knowledge", ui(false, func(w http.ResponseWriter, r *http.Request) {
		items, err := store.ListKnowledge(r.Context())
		if !runtimeStoreError(w, err) {
			runtimeJSON(w, 200, ListResponse[findings.KnowledgeEntry]{Items: items, Total: len(items)})
		}
	}))
	mux.HandleFunc("POST /api/v1/knowledge", ui(true, func(w http.ResponseWriter, r *http.Request) {
		var entry findings.KnowledgeEntry
		if !runtimeDecode(w, r, &entry) {
			return
		}
		saved, err := store.SaveKnowledge(r.Context(), entry, actor(r))
		if !runtimeStoreError(w, err) {
			runtimeJSON(w, 201, saved)
		}
	}))
	mux.HandleFunc("PUT /api/v1/knowledge/{id}", ui(true, func(w http.ResponseWriter, r *http.Request) {
		var entry findings.KnowledgeEntry
		if !runtimeDecode(w, r, &entry) {
			return
		}
		if entry.ID != "" && entry.ID != r.PathValue("id") {
			bad(w, 400, "knowledge_id_mismatch")
			return
		}
		entry.ID = r.PathValue("id")
		saved, err := store.SaveKnowledge(r.Context(), entry, actor(r))
		if !runtimeStoreError(w, err) {
			runtimeJSON(w, 200, saved)
		}
	}))
	mux.HandleFunc("DELETE /api/v1/knowledge/{id}", ui(true, func(w http.ResponseWriter, r *http.Request) {
		if !runtimeStoreError(w, store.DeleteKnowledge(r.Context(), r.PathValue("id"), actor(r))) {
			runtimeJSON(w, 200, map[string]string{"status": "DELETED"})
		}
	}))
	mux.HandleFunc("POST /api/v1/knowledge/import", ui(true, func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Items []findings.KnowledgeEntry `json:"items"`
		}
		if !runtimeDecodeLimit(w, r, &body, 10<<20) {
			return
		}
		if !runtimeStoreError(w, store.ImportKnowledge(r.Context(), body.Items, actor(r))) {
			runtimeJSON(w, 200, map[string]int{"imported": len(body.Items)})
		}
	}))
	mux.HandleFunc("GET /api/v1/tasks/{id}/findings", ui(false, func(w http.ResponseWriter, r *http.Request) {
		items, err := store.ListTaskFindings(r.Context(), r.PathValue("id"))
		if !runtimeStoreError(w, err) {
			runtimeJSON(w, 200, ListResponse[taskflow.Finding]{Items: items, Total: len(items)})
		}
	}))
	mux.HandleFunc("POST /api/v1/port-quarantines/release", admin(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			AssetID string `json:"assetId"`
			Port    int    `json:"port"`
			Reason  string `json:"reason"`
		}
		if !runtimeDecode(w, r, &body) {
			return
		}
		if !runtimeStoreError(w, store.ReleaseQuarantine(r.Context(), body.AssetID, body.Port, body.Reason, actor(r))) {
			runtimeJSON(w, 200, map[string]string{"status": "RELEASED"})
		}
	}))
}
