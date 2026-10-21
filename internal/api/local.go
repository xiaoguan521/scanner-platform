package api

import (
	"errors"
	"net/http"
	"scanner-platform/internal/repo"
	"scanner-platform/internal/rules"
	"scanner-platform/internal/taskflow"
)

func registerLocalHandlers(mux *http.ServeMux, store repo.RuntimeBackend, ui func(bool, http.HandlerFunc) http.HandlerFunc, admin func(http.HandlerFunc) http.HandlerFunc, actor func(*http.Request) string) {
	mux.HandleFunc("POST /api/v1/nodes/register", admin(func(w http.ResponseWriter, r *http.Request) {
		var input repo.NodeLifecycle
		if !runtimeDecode(w, r, &input) {
			return
		}
		item, err := store.RegisterNodeLifecycle(r.Context(), input, actor(r))
		if errors.Is(err, repo.ErrInvalidNodeLifecycle) {
			bad(w, http.StatusBadRequest, "invalid_node_registration")
			return
		}
		if errors.Is(err, repo.ErrNodeLifecycleExists) {
			bad(w, http.StatusConflict, "node_already_registered")
			return
		}
		if !runtimeStoreError(w, err) {
			runtimeJSON(w, http.StatusCreated, item)
		}
	}))
	mux.HandleFunc("POST /api/v1/nodes/{id}/revoke", admin(func(w http.ResponseWriter, r *http.Request) {
		err := store.RevokeNodeLifecycle(r.Context(), r.PathValue("id"), actor(r))
		if errors.Is(err, repo.ErrInvalidNodeLifecycle) {
			bad(w, http.StatusBadRequest, "invalid_node_id")
			return
		}
		if errors.Is(err, repo.ErrNodeLifecycleNotFound) {
			bad(w, http.StatusNotFound, "node_not_registered")
			return
		}
		if !runtimeStoreError(w, err) {
			runtimeJSON(w, http.StatusOK, map[string]string{"status": "REVOKED"})
		}
	}))
	mux.HandleFunc("GET /api/v1/nodes/{id}/lifecycle", ui(false, func(w http.ResponseWriter, r *http.Request) {
		item, found, err := store.GetNodeLifecycle(r.Context(), r.PathValue("id"))
		if runtimeStoreError(w, err) {
			return
		}
		if !found {
			bad(w, http.StatusNotFound, "node_not_registered")
			return
		}
		runtimeJSON(w, http.StatusOK, item)
	}))
	mux.HandleFunc("GET /api/v1/nodes/{id}/events", ui(false, func(w http.ResponseWriter, r *http.Request) {
		items, err := store.ListNodeLifecycleEvents(r.Context(), r.PathValue("id"))
		if errors.Is(err, repo.ErrInvalidNodeLifecycle) {
			bad(w, http.StatusBadRequest, "invalid_node_id")
			return
		}
		if !runtimeStoreError(w, err) {
			runtimeJSON(w, http.StatusOK, ListResponse[repo.NodeLifecycleEvent]{Items: items, Total: len(items)})
		}
	}))
	mux.HandleFunc("POST /api/v1/nodes/heartbeat", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			ID               string                   `json:"id"`
			Kind             string                   `json:"kind"`
			CurrentTask      string                   `json:"currentTask"`
			LocalRuleVersion string                   `json:"localRuleVersion"`
			Status           string                   `json:"status"`
			Engines          []taskflow.EngineStatus  `json:"engines"`
			Progress         *taskflow.ProgressUpdate `json:"progress,omitempty"`
		}
		if !runtimeDecode(w, r, &body) {
			return
		}
		if nodeID := AuthenticatedNodeID(r); nodeID != "" && body.ID != nodeID {
			bad(w, http.StatusUnauthorized, "node_identity_mismatch")
			return
		}
		if item, exists, err := store.GetNodeLifecycle(r.Context(), body.ID); err != nil {
			runtimeStoreError(w, err)
			return
		} else if exists && item.Kind != body.Kind {
			bad(w, http.StatusForbidden, "node_kind_mismatch")
			return
		}
		if !runtimeWorkerID.MatchString(body.ID) || (body.Kind != "worker" && body.Kind != "updater") || len(body.CurrentTask) > 128 || len(body.LocalRuleVersion) > 200 || body.LocalRuleVersion != "" && !rules.ValidateVersion(body.LocalRuleVersion) {
			bad(w, 400, "invalid_node")
			return
		}
		if body.Status != "" && body.Status != "ONLINE" && body.Status != "BUSY" && body.Status != taskflow.NodeStatusWaitingForRules && body.Status != taskflow.NodeStatusRulesError {
			bad(w, 400, "invalid_node_status")
			return
		}
		if (body.Status == taskflow.NodeStatusWaitingForRules || body.Status == taskflow.NodeStatusRulesError) && body.LocalRuleVersion != "" {
			bad(w, 400, "invalid_rule_readiness")
			return
		}
		if body.Progress != nil {
			if body.Kind != "worker" || body.CurrentTask == "" || body.Progress.TaskID != body.CurrentTask {
				bad(w, 400, "invalid_task_progress")
				return
			}
		}
		if !runtimeStoreError(w, store.TouchNodeState(r.Context(), body.ID, body.Kind, body.CurrentTask, body.LocalRuleVersion, body.Status, body.Engines)) {
			state := ""
			if body.CurrentTask != "" && body.Kind == "worker" {
				state = store.TaskStateForWorker(r.Context(), body.CurrentTask, body.ID)
			}
			if body.Progress != nil {
				if err := store.UpdateRuntimeTaskProgress(r.Context(), body.ID, *body.Progress); err != nil {
					// Keep cancellation and deadline heartbeats usable: a stale progress
					// update must not hide the task's non-running status from its Worker.
					if !errors.Is(err, repo.ErrTaskConflict) || state == "RUNNING" {
						runtimeStoreError(w, err)
						return
					}
				}
			}
			runtimeJSON(w, 200, map[string]string{"state": "alive", "taskStatus": state})
		}
	})
	mux.HandleFunc("GET /api/v1/port-quarantines", ui(false, func(w http.ResponseWriter, r *http.Request) {
		items, err := store.ListQuarantines(r.Context())
		if !runtimeStoreError(w, err) {
			runtimeJSON(w, 200, ListResponse[map[string]any]{Items: items, Total: len(items)})
		}
	}))
	mux.HandleFunc("POST /api/v1/tasks/{id}/cancel", ui(true, func(w http.ResponseWriter, r *http.Request) {
		if !runtimeStoreError(w, store.CancelTask(r.Context(), r.PathValue("id"), actor(r))) {
			runtimeJSON(w, 200, map[string]string{"status": "CANCELED"})
		}
	}))
	mux.HandleFunc("POST /api/v1/tasks/{id}/pause", ui(true, func(w http.ResponseWriter, r *http.Request) {
		if !runtimeStoreError(w, store.PauseTask(r.Context(), r.PathValue("id"), actor(r))) {
			runtimeJSON(w, http.StatusOK, map[string]string{"status": "PAUSED"})
		}
	}))
	mux.HandleFunc("POST /api/v1/tasks/{id}/resume", ui(true, func(w http.ResponseWriter, r *http.Request) {
		if !runtimeStoreError(w, store.ResumeTask(r.Context(), r.PathValue("id"), actor(r))) {
			runtimeJSON(w, http.StatusOK, map[string]string{"status": "PENDING"})
		}
	}))
	mux.HandleFunc("POST /api/v1/tasks/{id}/archive", ui(true, func(w http.ResponseWriter, r *http.Request) {
		if !runtimeStoreError(w, store.SetTaskArchived(r.Context(), r.PathValue("id"), actor(r), true)) {
			runtimeJSON(w, http.StatusOK, map[string]string{"status": "ARCHIVED"})
		}
	}))
	mux.HandleFunc("POST /api/v1/tasks/{id}/restore", ui(true, func(w http.ResponseWriter, r *http.Request) {
		if !runtimeStoreError(w, store.SetTaskArchived(r.Context(), r.PathValue("id"), actor(r), false)) {
			runtimeJSON(w, http.StatusOK, map[string]string{"status": "ACTIVE"})
		}
	}))
	mux.HandleFunc("DELETE /api/v1/tasks/{id}", admin(func(w http.ResponseWriter, r *http.Request) {
		if !runtimeStoreError(w, store.DeleteRuntimeTask(r.Context(), r.PathValue("id"), actor(r))) {
			runtimeJSON(w, http.StatusOK, map[string]string{"status": "DELETED"})
		}
	}))
	mux.HandleFunc("POST /api/v1/findings/batch-disposition", ui(true, func(w http.ResponseWriter, r *http.Request) {
		var body repo.FindingBatchDisposition
		if !runtimeDecode(w, r, &body) {
			return
		}
		items, err := store.BatchFindingDisposition(r.Context(), body, actor(r))
		if !runtimeStoreError(w, err) {
			runtimeJSON(w, http.StatusOK, map[string]any{"updated": len(items), "items": items})
		}
	}))
	mux.HandleFunc("GET /api/v1/findings/{id}/events", ui(false, func(w http.ResponseWriter, r *http.Request) {
		items, err := store.ListFindingEvents(r.Context(), r.PathValue("id"))
		if !runtimeStoreError(w, err) {
			runtimeJSON(w, 200, ListResponse[repo.FindingEvent]{Items: items, Total: len(items)})
		}
	}))
	mux.HandleFunc("PATCH /api/v1/findings/{id}", ui(true, func(w http.ResponseWriter, r *http.Request) {
		var body repo.FindingDisposition
		if !runtimeDecode(w, r, &body) {
			return
		}
		item, err := store.UpdateFindingDisposition(r.Context(), r.PathValue("id"), body, actor(r))
		if !runtimeStoreError(w, err) {
			runtimeJSON(w, 200, item)
		}
	}))
	mux.HandleFunc("GET /api/v1/schedules", ui(false, func(w http.ResponseWriter, r *http.Request) {
		items, err := store.ListSchedules(r.Context())
		if !runtimeStoreError(w, err) {
			runtimeJSON(w, 200, ListResponse[taskflow.Schedule]{Items: items, Total: len(items)})
		}
	}))
	mux.HandleFunc("GET /api/v1/schedules/{id}/runs", ui(false, func(w http.ResponseWriter, r *http.Request) {
		limit, offset, err := parseScheduleRunPagination(r)
		if err != nil {
			bad(w, http.StatusBadRequest, "invalid_schedule_run_pagination")
			return
		}
		items, total, err := store.ListScheduleRuns(r.Context(), r.PathValue("id"), limit, offset)
		if !runtimeStoreError(w, err) {
			runtimeJSON(w, http.StatusOK, ListResponse[taskflow.ScheduleRun]{Items: items, Total: total})
		}
	}))
	mux.HandleFunc("POST /api/v1/schedules", ui(true, func(w http.ResponseWriter, r *http.Request) {
		var body taskflow.Schedule
		if !runtimeDecode(w, r, &body) {
			return
		}
		item, err := store.SaveSchedule(r.Context(), body, actor(r))
		if !runtimeStoreError(w, err) {
			runtimeJSON(w, 201, item)
		}
	}))
	mux.HandleFunc("PUT /api/v1/schedules/{id}", ui(true, func(w http.ResponseWriter, r *http.Request) {
		var body taskflow.Schedule
		if !runtimeDecode(w, r, &body) {
			return
		}
		item, err := store.UpdateSchedule(r.Context(), r.PathValue("id"), body, actor(r))
		if !runtimeStoreError(w, err) {
			runtimeJSON(w, 200, item)
		}
	}))
	mux.HandleFunc("PATCH /api/v1/schedules/{id}", ui(true, func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Enabled *bool `json:"enabled"`
		}
		if !runtimeDecode(w, r, &body) {
			return
		}
		if body.Enabled == nil {
			bad(w, 400, "enabled_required")
			return
		}
		if !runtimeStoreError(w, store.ToggleSchedule(r.Context(), r.PathValue("id"), actor(r), *body.Enabled)) {
			runtimeJSON(w, 200, map[string]bool{"enabled": *body.Enabled})
		}
	}))
	mux.HandleFunc("DELETE /api/v1/schedules/{id}", ui(true, func(w http.ResponseWriter, r *http.Request) {
		if !runtimeStoreError(w, store.DeleteSchedule(r.Context(), r.PathValue("id"), actor(r))) {
			runtimeJSON(w, 200, map[string]string{"status": "DELETED"})
		}
	}))
	mux.HandleFunc("GET /api/v1/nodes", ui(false, func(w http.ResponseWriter, r *http.Request) {
		if query, paged, ok := parseNodeListQuery(r); paged {
			if !ok {
				bad(w, http.StatusBadRequest, "invalid_node_list_query")
				return
			}
			page, err := store.ListNodesPage(r.Context(), query)
			if errors.Is(err, repo.ErrInvalidNodeListQuery) {
				bad(w, http.StatusBadRequest, "invalid_node_list_query")
				return
			}
			if !runtimeStoreError(w, err) {
				runtimeJSON(w, http.StatusOK, PageListResponse[repo.LocalNode]{Items: page.Items, Total: page.Total, Page: page.Page, PageSize: page.PageSize})
			}
			return
		}
		items, err := store.ListNodes(r.Context())
		if !runtimeStoreError(w, err) {
			runtimeJSON(w, 200, ListResponse[repo.LocalNode]{Items: items, Total: len(items)})
		}
	}))
}
