// Package api defines the UI API boundary. This Phase 0 handler exposes
// only diagnostic metadata. The Node API and all mutations are disabled.
package api

import (
	"net/http"
	"time"
)

// Status describes a local development scaffold, not a healthy scanner.
type Status struct {
	Role        string   `json:"role"`
	Mode        string   `json:"mode,omitempty"`
	Phase       string   `json:"phase"`
	State       string   `json:"state"`
	Ready       bool     `json:"ready"`
	Enabled     []string `json:"enabled"`
	Unavailable []string `json:"unavailable"`
}

// NewScaffoldHandler exposes no target, token, finding or database data.
// It MUST NOT be wired to the Node API listener without TLS/auth.
func NewScaffoldHandler(role string) http.Handler {
	mux := http.NewServeMux()
	status := Status{
		Role: role, Phase: "Phase 0 / PoC", State: "SCAFFOLD",
		Ready: false, Enabled: []string{"local-status"},
		Unavailable: []string{"node-api", "database", "task-dispatch", "rule-activation", "scanning", "authentication", "user-management", "rbac"},
	}
	encode := func(w http.ResponseWriter, code int, v any) {
		runtimeJSON(w, code, v)
	}
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		encode(w, http.StatusOK, map[string]string{"state": "alive", "role": role})
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		encode(w, http.StatusServiceUnavailable, map[string]string{
			"state": "not_ready", "reason": "security gates and backends are not integrated",
		})
	})
	mux.HandleFunc("GET /api/v1/system/status", func(w http.ResponseWriter, r *http.Request) {
		encode(w, http.StatusOK, status)
	})
	mux.HandleFunc("GET /api/v1/system/capabilities", func(w http.ResponseWriter, r *http.Request) {
		encode(w, http.StatusOK, map[string]any{
			"enabled": status.Enabled, "unavailable": status.Unavailable,
		})
	})
	for _, route := range []string{
		"/api/v1/users", "/api/v1/assets", "/api/v1/port-quarantines", "/api/v1/scopes", "/api/v1/tasks",
		"/api/v1/findings", "/api/v1/nodes", "/api/v1/rules",
	} {
		mux.HandleFunc("GET "+route, func(w http.ResponseWriter, r *http.Request) {
			encode(w, http.StatusNotImplemented, APIError{Error: "not_implemented", Message: "Phase 0 scaffold does not expose business data or operations"})
		})
	}
	return withRequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		// Never expose anything outside the explicit diagnostic routes.
		mux.ServeHTTP(w, r)
	}))
}

// Read-only local HTTP serving is for frontend wiring; this does not perform
// authorization and must never serve real customer data.
const DevelopmentReadHeaderTimeout = 5 * time.Second
