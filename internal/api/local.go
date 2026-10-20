package api

import (
	"errors"
	"net/http"
	"scanner-platform/internal/repo"
	"scanner-platform/internal/taskflow"
)

func registerLocalHandlers(mux *http.ServeMux, store *repo.RuntimeStore, ui func(bool, http.HandlerFunc) http.HandlerFunc, admin func(http.HandlerFunc) http.HandlerFunc, actor func(*http.Request) string) {
	mux.HandleFunc("POST /api/v1/nodes/heartbeat", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			ID          string                   `json:"id"`
			Kind        string                   `json:"kind"`
			CurrentTask string                   `json:"currentTask"`
			Engines     []taskflow.EngineStatus  `json:"engines"`
			Progress    *taskflow.ProgressUpdate `json:"progress,omitempty"`
		}
		if !runtimeDecode(w, r, &body) {
			return
		}
		if !runtimeWorkerID.MatchString(body.ID) || (body.Kind != "worker" && body.Kind != "updater") || len(body.CurrentTask) > 128 {
			bad(w, 400, "invalid_node")
			return
		}
		if body.Progress != nil {
			if body.Kind != "worker" || body.CurrentTask == "" || body.Progress.TaskID != body.CurrentTask {
				bad(w, 400, "invalid_task_progress")
				return
			}
		}
		if !runtimeStoreError(w, store.TouchNode(r.Context(), body.ID, body.Kind, body.CurrentTask, body.Engines)) {
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
	mux.HandleFunc("PATCH /api/v1/findings/{id}", ui(true, func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Status string `json:"status"`
		}
		if !runtimeDecode(w, r, &body) {
			return
		}
		item, err := store.UpdateFinding(r.Context(), r.PathValue("id"), body.Status, actor(r))
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
		items, err := store.ListNodes(r.Context())
		if !runtimeStoreError(w, err) {
			runtimeJSON(w, 200, ListResponse[repo.LocalNode]{Items: items, Total: len(items)})
		}
	}))
}
