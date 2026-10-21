package api

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const nodeAuthFixtureToken = "0123456789abcdef0123456789abcdef"

func TestNodeAuthMiddlewareBindsTokenToNodeIdentity(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/worker/claim" {
			if got := AuthenticatedNodeID(r); got != "worker-a" {
				t.Errorf("authenticated node = %q, want worker-a", got)
			}
		}
		w.WriteHeader(http.StatusNoContent)
	})
	handler := NodeAuthMiddleware(next, NodeTokenSet{"worker-a": nodeAuthFixtureToken})

	for _, test := range []struct {
		name       string
		auth       string
		node       string
		wantStatus int
	}{
		{name: "missing", wantStatus: http.StatusUnauthorized},
		{name: "wrong token", auth: "Bearer wrong-token-012345", node: "worker-a", wantStatus: http.StatusUnauthorized},
		{name: "unknown node", auth: "Bearer " + nodeAuthFixtureToken, node: "worker-b", wantStatus: http.StatusUnauthorized},
		{name: "valid", auth: "Bearer " + nodeAuthFixtureToken, node: "worker-a", wantStatus: http.StatusNoContent},
	} {
		t.Run(test.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "http://example.test/api/v1/worker/claim", nil)
			if test.auth != "" {
				req.Header.Set("Authorization", test.auth)
			}
			if test.node != "" {
				req.Header.Set("X-Node-ID", test.node)
			}
			resp := httptest.NewRecorder()
			handler.ServeHTTP(resp, req)
			if resp.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d; body=%s", resp.Code, test.wantStatus, resp.Body.String())
			}
			if test.wantStatus == http.StatusUnauthorized && resp.Header().Get("WWW-Authenticate") != "Bearer" {
				t.Fatalf("missing bearer challenge: %q", resp.Header().Get("WWW-Authenticate"))
			}
		})
	}

	request := httptest.NewRequest(http.MethodGet, "http://example.test/api/v1/users", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("unprotected path status = %d, want 204", response.Code)
	}
}

func TestNodeAuthMiddlewareRegistryCanRotateWithoutRaces(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })
	oldToken := nodeAuthFixtureToken
	newToken := "fedcba9876543210fedcba9876543210"
	registry := NewNodeTokenRegistry(NodeTokenSet{"worker-a": oldToken})
	handler := NodeAuthMiddlewareWithRegistry(next, registry)
	request := func(token string) int {
		req := httptest.NewRequest(http.MethodPost, "http://example.test/api/v1/worker/claim", nil)
		req.Header.Set("X-Node-ID", "worker-a")
		req.Header.Set("Authorization", "Bearer "+token)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, req)
		return response.Code
	}
	if got := request(oldToken); got != http.StatusNoContent {
		t.Fatalf("old token status = %d, want 204", got)
	}
	registry.Replace(NodeTokenSet{"worker-a": newToken})
	if got := request(oldToken); got != http.StatusUnauthorized {
		t.Fatalf("rotated old token status = %d, want 401", got)
	}
	if got := request(newToken); got != http.StatusNoContent {
		t.Fatalf("rotated new token status = %d, want 204", got)
	}
}

func TestNodeProtocolHandlerRejectsHumanAndUnknownPaths(t *testing.T) {
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	})
	handler := NodeProtocolHandler(next)

	allowed := httptest.NewRecorder()
	handler.ServeHTTP(allowed, httptest.NewRequest(http.MethodPost, "http://example.test/api/v1/worker/claim", nil))
	if allowed.Code != http.StatusNoContent || !called {
		t.Fatalf("allowed node path status=%d called=%v, want 204/true", allowed.Code, called)
	}

	called = false
	for _, path := range []string{"/", "/api/v1/users", "/api/v1/workerish/claim"} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "http://example.test"+path, nil))
		if response.Code != http.StatusNotFound || called {
			t.Fatalf("path %q status=%d called=%v, want 404/false", path, response.Code, called)
		}
	}
}

func TestReadNodeTokenFilesRequiresOwnerOnlyFiles(t *testing.T) {
	dir := t.TempDir()
	single := filepath.Join(dir, "worker.token")
	if err := os.WriteFile(single, []byte(nodeAuthFixtureToken+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if got, err := ReadNodeTokenFile(single); err != nil || got != nodeAuthFixtureToken {
		t.Fatalf("ReadNodeTokenFile() = %q, %v", got, err)
	}

	registry := filepath.Join(dir, "nodes.tokens")
	content := "worker-a=" + nodeAuthFixtureToken + "\nupdater-a=abcdef0123456789abcdef0123456789\n"
	if err := os.WriteFile(registry, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	set, err := ReadNodeTokenSetFile(registry)
	if err != nil {
		t.Fatal(err)
	}
	if set["worker-a"] != nodeAuthFixtureToken || set["updater-a"] == "" {
		t.Fatalf("unexpected token registry: %#v", set)
	}

	insecure := filepath.Join(dir, "insecure.token")
	if err := os.WriteFile(insecure, []byte(nodeAuthFixtureToken), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadNodeTokenFile(insecure); err == nil {
		t.Fatal("world-readable token file was accepted")
	}

	link := filepath.Join(dir, "link.token")
	if err := os.Symlink(single, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadNodeTokenFile(link); err == nil {
		t.Fatal("symlink token file was accepted")
	}

	badRegistry := filepath.Join(dir, "bad.nodes")
	if err := os.WriteFile(badRegistry, []byte("worker-a="+nodeAuthFixtureToken+"\nworker-a=abcdef0123456789abcdef0123456789"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadNodeTokenSetFile(badRegistry); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate registry entry error = %v", err)
	}
}

func TestNodeAuthMiddlewareDoesNotEchoCredentials(t *testing.T) {
	handler := NodeAuthMiddleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), NodeTokenSet{"worker-a": nodeAuthFixtureToken})
	req := httptest.NewRequest(http.MethodPost, "http://example.test/api/v1/worker/claim", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer "+nodeAuthFixtureToken)
	req.Header.Set("X-Node-ID", "unknown")
	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, req)
	body, _ := io.ReadAll(resp.Result().Body)
	if strings.Contains(string(body), nodeAuthFixtureToken) {
		t.Fatal("authentication response echoed the bearer token")
	}
}
