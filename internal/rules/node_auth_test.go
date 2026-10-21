package rules

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAgentPostAddsNodeAuthenticationHeaders(t *testing.T) {
	const token = "0123456789abcdef0123456789abcdef"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer "+token {
			t.Errorf("authorization = %q", got)
		}
		if got := r.Header.Get("X-Node-ID"); got != "updater-a" {
			t.Errorf("node id = %q", got)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	agent := Agent{ServerURL: server.URL, ID: "updater-a", NodeToken: token, Client: server.Client()}
	if code, err := agent.post(context.Background(), "/api/v1/updater/state", map[string]string{"nodeId": "updater-a"}, nil); err != nil || code != http.StatusNoContent {
		t.Fatalf("post() = %d, %v", code, err)
	}
}
