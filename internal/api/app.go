package api

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"scanner-platform/internal/account"
)

const sessionCookie = "scanner_session"

type loginLimiter struct {
	mu       sync.Mutex
	failures map[string][]time.Time
}

func (l *loginLimiter) allow(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.failures == nil {
		l.failures = map[string][]time.Time{}
	}
	cutoff := time.Now().Add(-time.Minute)
	recent := l.failures[host][:0]
	for _, t := range l.failures[host] {
		if t.After(cutoff) {
			recent = append(recent, t)
		}
	}
	l.failures[host] = recent
	return len(recent) < 5
}
func (l *loginLimiter) failed(addr string) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.failures[host] = append(l.failures[host], time.Now())
}
func (l *loginLimiter) success(addr string) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.failures, host)
}
func respond(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
func bad(w http.ResponseWriter, status int, code string) {
	respond(w, status, APIError{Error: code, Message: code})
}
func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		bad(w, http.StatusUnsupportedMediaType, "json_required")
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		bad(w, http.StatusBadRequest, "invalid_json")
		return false
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		bad(w, http.StatusBadRequest, "extra_json")
		return false
	}
	return true
}
func mutationGuard(w http.ResponseWriter, r *http.Request) bool {
	// Cross-origin forms cannot set this custom header, and no permissive CORS
	// headers are served. This is required even for unauthenticated login.
	if r.Header.Get("X-Requested-With") != "XMLHttpRequest" {
		bad(w, http.StatusForbidden, "request_header_required")
		return false
	}
	return true
}
func sessionToken(r *http.Request) string {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return ""
	}
	return c.Value
}
func auth(s account.Repository, adminOnly bool, next func(http.ResponseWriter, *http.Request, account.User)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, err := s.Session(r.Context(), sessionToken(r))
		if err != nil {
			bad(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		if adminOnly && user.Role != "admin" {
			bad(w, http.StatusForbidden, "forbidden")
			return
		}
		next(w, r, user)
	}
}

// NewDevelopmentHandler builds the minimal authenticated UI API.
// All scanner endpoints remain in the fail-closed scaffold handler.
func NewDevelopmentHandler(s account.Repository) http.Handler {
	mux := http.NewServeMux()
	limiter := &loginLimiter{}
	scaffold := NewScaffoldHandler("sec-server")
	mux.Handle("/", scaffold)
	mux.HandleFunc("GET /api/v1/system/status", func(w http.ResponseWriter, r *http.Request) {
		respond(w, 200, Status{
			Role: "sec-server", Phase: "Phase 0 / early MVP", State: "SCAFFOLD", Ready: false,
			Enabled:     []string{"local-status", "authentication", "user-management", "rbac-users"},
			Unavailable: []string{"node-api", "task-dispatch", "scanning", "rule-activation"},
		})
	})
	mux.HandleFunc("GET /api/v1/system/capabilities", func(w http.ResponseWriter, r *http.Request) {
		respond(w, 200, map[string]any{"enabled": []string{"local-status", "authentication", "user-management", "rbac-users"}, "unavailable": []string{"node-api", "task-dispatch", "scanning", "rule-activation"}})
	})
	mux.HandleFunc("POST /api/v1/auth/login", func(w http.ResponseWriter, r *http.Request) {
		if !mutationGuard(w, r) {
			return
		}
		if !limiter.allow(r.RemoteAddr) {
			bad(w, http.StatusTooManyRequests, "rate_limited")
			return
		}
		var body struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if !readJSON(w, r, &body) {
			return
		}
		user, token, err := s.Authenticate(r.Context(), body.Username, body.Password)
		if err != nil {
			limiter.failed(r.RemoteAddr)
			bad(w, http.StatusUnauthorized, "invalid_credentials")
			return
		}
		limiter.success(r.RemoteAddr)
		http.SetCookie(w, &http.Cookie{
			Name: sessionCookie, Value: token, Path: "/api/v1", HttpOnly: true,
			SameSite: http.SameSiteStrictMode, Secure: r.TLS != nil,
			Expires: time.Now().Add(8 * time.Hour), MaxAge: int((8 * time.Hour).Seconds()),
		})
		respond(w, http.StatusOK, user)
	})
	mux.HandleFunc("POST /api/v1/auth/logout", func(w http.ResponseWriter, r *http.Request) {
		if !mutationGuard(w, r) {
			return
		}
		token := sessionToken(r)
		if token != "" {
			_ = s.Logout(r.Context(), token)
		}
		http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/api/v1", HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: -1, Secure: r.TLS != nil})
		respond(w, http.StatusOK, map[string]string{"state": "logged_out"})
	})
	mux.HandleFunc("GET /api/v1/auth/me", auth(s, false, func(w http.ResponseWriter, r *http.Request, u account.User) { respond(w, 200, u) }))
	mux.HandleFunc("GET /api/v1/users", auth(s, true, func(w http.ResponseWriter, r *http.Request, _ account.User) {
		users, err := s.List(r.Context())
		if err != nil {
			bad(w, 500, "db_error")
			return
		}
		respond(w, 200, ListResponse[account.User]{Items: users, Total: len(users)})
	}))
	mux.HandleFunc("POST /api/v1/users", auth(s, true, func(w http.ResponseWriter, r *http.Request, u account.User) {
		if !mutationGuard(w, r) {
			return
		}
		var body struct {
			Username string `json:"username"`
			Password string `json:"password"`
			Role     string `json:"role"`
		}
		if !readJSON(w, r, &body) {
			return
		}
		user, err := s.Create(r.Context(), u, body.Username, body.Password, body.Role)
		if err != nil {
			switch {
			case errors.Is(err, account.ErrInvalid):
				bad(w, 400, "invalid_user")
			case errors.Is(err, account.ErrExists):
				bad(w, 409, "user_exists")
			default:
				bad(w, 500, "db_error")
			}
			return
		}
		respond(w, http.StatusCreated, user)
	}))
	mux.HandleFunc("PATCH /api/v1/users/{id}", auth(s, true, func(w http.ResponseWriter, r *http.Request, u account.User) {
		if !mutationGuard(w, r) {
			return
		}
		var body struct {
			Role     string `json:"role"`
			IsActive *bool  `json:"isActive"`
		}
		if !readJSON(w, r, &body) {
			return
		}
		if body.IsActive == nil {
			bad(w, 400, "invalid_user")
			return
		}
		user, err := s.Update(r.Context(), u, r.PathValue("id"), body.Role, *body.IsActive)
		if err != nil {
			switch {
			case errors.Is(err, account.ErrInvalid):
				bad(w, 400, "invalid_user")
			case errors.Is(err, account.ErrForbidden):
				bad(w, 403, "forbidden")
			case errors.Is(err, account.ErrMissing):
				bad(w, 404, "not_found")
			default:
				bad(w, 500, "db_error")
			}
			return
		}
		respond(w, 200, user)
	}))
	return mux
}
