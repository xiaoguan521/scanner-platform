package api

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"scanner-platform/internal/repo"
	"strings"
	"testing"
)

func TestNodeLifecycleManagementAndRevocationGate(t *testing.T) {
	store, err := repo.OpenRuntime(filepath.Join(t.TempDir(), "nodes.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	base := NewRuntimeHandler(store, nil, "")
	registry := NewNodeTokenRegistry(NodeTokenSet{"worker-a": "0123456789abcdef0123456789abcdef", "legacy-b": "abcdef0123456789abcdef0123456789"})
	handler := NodeAuthMiddlewareWithRegistry(NodeLifecycleMiddleware(base, store), registry)
	request := func(method, path, body, id, token string) int {
		t.Helper()
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		if id != "" {
			r.Header.Set("X-Node-ID", id)
			r.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w.Code
	}
	if got := request("POST", "/api/v1/nodes/register", `{"id":"worker-a","kind":"worker","hostId":"host-a"}`, "", ""); got != http.StatusCreated {
		t.Fatalf("register=%d", got)
	}
	if got := request("POST", "/api/v1/nodes/register", `{"id":"worker-a","kind":"worker","hostId":"host-a"}`, "", ""); got != http.StatusConflict {
		t.Fatalf("duplicate=%d", got)
	}
	if got := request("POST", "/api/v1/nodes/heartbeat", `{"id":"worker-a","kind":"updater"}`, "worker-a", "0123456789abcdef0123456789abcdef"); got != http.StatusForbidden {
		t.Fatalf("kind mismatch=%d", got)
	}
	if got := request("POST", "/api/v1/nodes/heartbeat", `{"id":"worker-a","kind":"worker"}`, "worker-a", "0123456789abcdef0123456789abcdef"); got != http.StatusOK {
		t.Fatalf("heartbeat=%d", got)
	}
	if got := request("POST", "/api/v1/nodes/heartbeat", `{"id":"legacy-b","kind":"worker"}`, "legacy-b", "abcdef0123456789abcdef0123456789"); got != http.StatusOK {
		t.Fatalf("legacy token=%d", got)
	}
	if got := request("POST", "/api/v1/nodes/worker-a/revoke", `{}`, "", ""); got != http.StatusOK {
		t.Fatalf("revoke=%d", got)
	}
	if got := request("POST", "/api/v1/nodes/heartbeat", `{"id":"worker-a","kind":"worker"}`, "worker-a", "0123456789abcdef0123456789abcdef"); got != http.StatusForbidden {
		t.Fatalf("revoked heartbeat=%d", got)
	}
	if got := request("POST", "/api/v1/worker/claim", `{"workerId":"worker-a"}`, "worker-a", "0123456789abcdef0123456789abcdef"); got != http.StatusForbidden {
		t.Fatalf("revoked claim=%d", got)
	}
	if got := request("POST", "/api/v1/nodes/worker-a/revoke", `{}`, "", ""); got != http.StatusOK {
		t.Fatalf("repeat revoke=%d", got)
	}
}
