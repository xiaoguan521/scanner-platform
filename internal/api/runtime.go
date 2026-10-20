package api

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"regexp"

	"scanner-platform/internal/account"
	"scanner-platform/internal/repo"
	"scanner-platform/internal/rules"
	"scanner-platform/internal/taskflow"
)

var runtimeWorkerID = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$`)

// NewRuntimeHandler serves the early local task flow and existing API routes.
// Synthetic tasks never start a scan or connect to their displayed targets.
func NewRuntimeHandler(store *repo.RuntimeStore, fallback http.Handler, uiDir string, accounts ...account.Repository) http.Handler {
	mux := http.NewServeMux()
	if fallback == nil {
		fallback = NewScaffoldHandler("sec-server")
	}
	mux.Handle("/api/", fallback)
	if uiDir != "" {
		files := http.FileServer(http.Dir(uiDir))
		mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet && r.Method != http.MethodHead {
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			files.ServeHTTP(w, r)
		}))
	}
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		runtimeJSON(w, http.StatusOK, map[string]string{"state": "alive", "role": "sec-server"})
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		runtimeJSON(w, http.StatusOK, map[string]string{"state": "ready", "mode": "local"})
	})
	capabilities := []string{"database", "task-dispatch", "synthetic-worker", "web-ui", "authentication", "user-management", "asset-registry", "approval-reviews", "schedules", "rule-import", "rule-activation", "nuclei-http-baseline", "trivy-offline", "zap-passive", "bounded-tcp-port-probe", "asset-inventory", "version-matching", "async-reports", "detection-metadata"}
	unavailable := []string{"engine-validation", "rule-signatures", "harbor"}
	mux.HandleFunc("GET /api/v1/system/status", func(w http.ResponseWriter, r *http.Request) {
		runtimeJSON(w, http.StatusOK, Status{
			Role: "sec-server", Phase: "早期开发", State: "RUNNING", Ready: true,
			Enabled: capabilities, Unavailable: unavailable,
		})
	})
	mux.HandleFunc("GET /api/v1/system/capabilities", func(w http.ResponseWriter, r *http.Request) {
		runtimeJSON(w, http.StatusOK, map[string]any{"enabled": capabilities, "unavailable": unavailable})
	})
	ui := func(write bool, handler http.HandlerFunc) http.HandlerFunc {
		if len(accounts) == 0 {
			return handler
		}
		return auth(accounts[0], false, func(w http.ResponseWriter, r *http.Request, u account.User) {
			if write && u.Role != "admin" && u.Role != "security_engineer" {
				bad(w, 403, "forbidden")
				return
			}
			if write && !mutationGuard(w, r) {
				return
			}
			handler(w, r)
		})
	}
	actor := func(r *http.Request) string {
		if len(accounts) > 0 {
			user, _ := accounts[0].Session(r.Context(), sessionToken(r))
			return user.ID
		}
		return "local-test"
	}
	admin := func(handler http.HandlerFunc) http.HandlerFunc {
		return ui(true, func(w http.ResponseWriter, r *http.Request) {
			if len(accounts) > 0 {
				u, _ := accounts[0].Session(r.Context(), sessionToken(r))
				if u.Role != "admin" {
					bad(w, 403, "admin_required")
					return
				}
			}
			handler(w, r)
		})
	}
	registerProductHandlers(mux, store, ui, admin, actor)
	registerReportHandlers(mux, store, ui, actor)
	registerLocalHandlers(mux, store, ui, admin, actor)
	registerFindingWorkHandlers(mux, store, ui, actor, accounts...)
	registerRuleHandlers(mux, store, ui, actor)
	mux.HandleFunc("GET /api/v1/tasks", ui(false, func(w http.ResponseWriter, r *http.Request) {
		archived := r.URL.Query().Get("archived")
		if archived != "" && archived != "true" && archived != "false" && archived != "all" {
			bad(w, http.StatusBadRequest, "invalid_archive_filter")
			return
		}
		items, err := store.ListRuntimeTasks(r.Context())
		if !runtimeStoreError(w, err) {
			filtered := make([]taskflow.Task, 0, len(items))
			for _, item := range items {
				if archived == "" || archived == "all" || item.Archived == (archived == "true") {
					filtered = append(filtered, item)
				}
			}
			runtimeJSON(w, http.StatusOK, ListResponse[taskflow.Task]{Items: filtered, Total: len(filtered)})
		}
	}))
	mux.HandleFunc("POST /api/v1/tasks", ui(true, func(w http.ResponseWriter, r *http.Request) {
		var body taskflow.TaskInput
		if !runtimeDecode(w, r, &body) {
			return
		}
		var task taskflow.Task
		var err error
		if body.Synthetic && body.Engine == "" && body.Scheme == "" && body.InputPath == "" && body.InputKind == "" && len(body.TimeWindows) == 0 && len(body.Targets) == 0 && len(accounts) == 0 {
			task, err = store.CreateSyntheticTask(r.Context())
		} else {
			task, err = store.CreateLocalTask(r.Context(), body, actor(r))
		}
		if !runtimeStoreError(w, err) {
			runtimeJSON(w, http.StatusCreated, task)
		}
	}))
	mux.HandleFunc("GET /api/v1/findings", ui(false, func(w http.ResponseWriter, r *http.Request) {
		items, err := store.ListRuntimeFindings(r.Context())
		if !runtimeStoreError(w, err) {
			runtimeJSON(w, http.StatusOK, ListResponse[taskflow.Finding]{Items: items, Total: len(items)})
		}
	}))
	mux.HandleFunc("POST /api/v1/worker/claim", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			WorkerID         string `json:"workerId"`
			LocalRuleVersion string `json:"localRuleVersion"`
			RulesReady       *bool  `json:"rulesReady"`
		}
		if !runtimeDecode(w, r, &body) {
			return
		}
		if !runtimeWorkerID.MatchString(body.WorkerID) {
			runtimeJSON(w, http.StatusBadRequest, APIError{Error: "invalid_worker", Message: "Worker ID 格式无效"})
			return
		}
		if len(body.LocalRuleVersion) > 200 || body.LocalRuleVersion != "" && !rules.ValidateVersion(body.LocalRuleVersion) {
			bad(w, http.StatusBadRequest, "invalid_rule_version")
			return
		}
		if body.RulesReady != nil && ((!*body.RulesReady && body.LocalRuleVersion != "") || (*body.RulesReady && body.LocalRuleVersion == "")) {
			bad(w, http.StatusBadRequest, "invalid_rule_readiness")
			return
		}
		if body.RulesReady != nil {
			status := "ONLINE"
			if !*body.RulesReady {
				status = taskflow.NodeStatusWaitingForRules
			}
			if runtimeStoreError(w, store.TouchNodeState(r.Context(), body.WorkerID, "worker", "", body.LocalRuleVersion, status)) {
				return
			}
		} else if runtimeStoreError(w, store.TouchNode(r.Context(), body.WorkerID, "worker", "")) {
			return
		}
		var task *taskflow.Task
		var err error
		if body.RulesReady != nil {
			task, err = store.ClaimRuntimeTaskWithRules(r.Context(), body.WorkerID, body.LocalRuleVersion, *body.RulesReady)
		} else {
			task, err = store.ClaimRuntimeTask(r.Context(), body.WorkerID)
		}
		if runtimeStoreError(w, err) {
			return
		}
		if task == nil {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if runtimeStoreError(w, store.TouchNode(r.Context(), body.WorkerID, "worker", task.ID)) {
			return
		}
		runtimeJSON(w, http.StatusOK, task)
	})
	mux.HandleFunc("POST /api/v1/worker/report", func(w http.ResponseWriter, r *http.Request) {
		var report taskflow.Report
		if !runtimeDecodeLimit(w, r, &report, taskflow.MaxReportBytes) {
			return
		}
		if !runtimeStoreError(w, store.CompleteRuntimeTask(r.Context(), report)) {
			if runtimeStoreError(w, store.TouchNode(r.Context(), report.WorkerID, "worker", "")) {
				return
			}
			runtimeJSON(w, http.StatusOK, map[string]string{"state": "completed"})
		}
	})
	mux.HandleFunc("POST /api/v1/worker/renew", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			TaskID            string `json:"taskId"`
			WorkerID          string `json:"workerId"`
			PinnedRuleVersion string `json:"pinnedRuleVersion"`
		}
		if !runtimeDecode(w, r, &body) {
			return
		}
		if !runtimeWorkerID.MatchString(body.WorkerID) || body.TaskID == "" || len(body.TaskID) > 128 || body.PinnedRuleVersion == "" || len(body.PinnedRuleVersion) > 200 {
			bad(w, http.StatusBadRequest, "invalid_lease")
			return
		}
		expires, err := store.RenewChunkLease(r.Context(), body.TaskID, body.WorkerID, body.PinnedRuleVersion)
		if runtimeStoreError(w, err) {
			return
		}
		runtimeJSON(w, http.StatusOK, map[string]any{"taskId": body.TaskID, "workerId": body.WorkerID, "pinnedRuleVersion": body.PinnedRuleVersion, "leaseExpiresAt": expires})
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		mux.ServeHTTP(w, r)
	})
}

func runtimeJSON(w http.ResponseWriter, code int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(value)
}

func runtimeDecode(w http.ResponseWriter, r *http.Request, value any) bool {
	return runtimeDecodeLimit(w, r, value, 64<<10)
}
func runtimeDecodeLimit(w http.ResponseWriter, r *http.Request, value any, limit int64) bool {
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		runtimeJSON(w, http.StatusBadRequest, APIError{Error: "invalid_json", Message: "请求格式无效"})
		return false
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		runtimeJSON(w, http.StatusBadRequest, APIError{Error: "invalid_json", Message: "请求只能包含一个 JSON 对象"})
		return false
	}
	return true
}

func runtimeStoreError(w http.ResponseWriter, err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, repo.ErrInvalidTask) {
		runtimeJSON(w, 400, APIError{Error: "invalid_input", Message: err.Error()})
		return true
	}
	if errors.Is(err, repo.ErrTaskConflict) {
		runtimeJSON(w, http.StatusConflict, APIError{Error: "task_conflict", Message: "任务或结果与领取记录不一致"})
		return true
	}
	if errors.Is(err, repo.ErrTaskLease) {
		runtimeJSON(w, http.StatusConflict, APIError{Error: "lease_conflict", Message: "任务租约已失效或绑定不一致"})
		return true
	}
	if errors.Is(err, repo.ErrTaskNotFound) {
		runtimeJSON(w, http.StatusNotFound, APIError{Error: "task_not_found", Message: "扫描任务不存在"})
		return true
	}
	if errors.Is(err, repo.ErrTaskNotTerminal) {
		runtimeJSON(w, http.StatusConflict, APIError{Error: "task_not_terminal", Message: "只能归档或删除已结束的任务"})
		return true
	}
	if errors.Is(err, repo.ErrTaskHasFindings) {
		runtimeJSON(w, http.StatusConflict, APIError{Error: "task_has_findings", Message: "任务存在关联发现项，请归档以保留扫描记录"})
		return true
	}
	slog.Error("task database operation failed", "error", err)
	runtimeJSON(w, http.StatusInternalServerError, APIError{Error: "database_error", Message: "数据库操作失败"})
	return true
}
