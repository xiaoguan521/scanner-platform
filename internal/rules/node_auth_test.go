package rules

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
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

func TestAgentSyncStatePublishesCatalogWithoutClaimingJobs(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/updater/state" || r.Method != http.MethodPost {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		var body struct {
			NodeID  string   `json:"nodeId"`
			Bundles []Bundle `json:"bundles"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body.NodeID != "updater-pg" || len(body.Bundles) != 0 {
			t.Fatalf("unexpected state body: %+v", body)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	agent := Agent{ServerURL: server.URL, ID: "updater-pg", Client: server.Client(), Manager: &Manager{Root: filepath.Join(t.TempDir(), "rules")}}
	if err := agent.SyncState(context.Background()); err != nil {
		t.Fatal(err)
	}
}
