package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"scanner-platform/internal/repo"
)

func TestFileNodeCredentialIssuerWritesProtectedRegistryAndAudits(t *testing.T) {
	store, err := repo.OpenRuntime(filepath.Join(t.TempDir(), "node-issue.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	if _, err := store.RegisterNodeLifecycle(ctx, repo.NodeLifecycle{ID: "issue-worker", Kind: "worker", HostID: "scan-host"}, "admin"); err != nil {
		t.Fatal(err)
	}
	registryPath := filepath.Join(t.TempDir(), "node-tokens")
	if err := os.WriteFile(registryPath, []byte("legacy-worker=0123456789abcdef0123456789abcdef\n"), 0600); err != nil {
		t.Fatal(err)
	}
	registry := NewNodeTokenRegistry(NodeTokenSet{"legacy-worker": "0123456789abcdef0123456789abcdef"})
	issuer := NewFileNodeCredentialIssuer(store, registry, registryPath, "https://192.0.2.10:8443")
	credential, err := issuer.IssueNodeCredential(ctx, "issue-worker", "admin")
	if err != nil {
		t.Fatal(err)
	}
	if credential.ID != "issue-worker" || credential.Kind != "worker" || credential.ServerURL == "" || len(credential.Token) < 16 || strings.Contains(credential.Token, "\n") {
		t.Fatalf("unexpected credential metadata: id=%q kind=%q server=%q tokenLength=%d", credential.ID, credential.Kind, credential.ServerURL, len(credential.Token))
	}
	tokens, err := ReadNodeTokenSetFile(registryPath)
	if err != nil || tokens[credential.ID] != credential.Token || tokens["legacy-worker"] == "" {
		t.Fatalf("registry missing issued and legacy entries: issued=%t legacy=%t err=%v", tokens[credential.ID] != "", tokens["legacy-worker"] != "", err)
	}
	if info, statErr := os.Stat(registryPath); statErr != nil {
		t.Fatalf("registry stat failed: %v", statErr)
	} else if info.Mode().Perm() != 0600 {
		t.Fatalf("registry permissions=%v", info.Mode().Perm())
	}
	_, auditCount, err := store.ListAuditLogs(ctx, repo.AuditLogQuery{Action: "issue_node_credential", ObjectType: "node", Limit: 10})
	if err != nil || auditCount != 1 {
		t.Fatalf("credential audit count=%d err=%v", auditCount, err)
	}
	if _, err := issuer.IssueNodeCredential(ctx, credential.ID, "admin"); !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("duplicate issuance err=%v", err)
	}
}

func TestFileNodeCredentialIssuerRollsBackRegistryWhenAuditFails(t *testing.T) {
	store, err := repo.OpenRuntime(filepath.Join(t.TempDir(), "node-issue-rollback.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	if _, err := store.RegisterNodeLifecycle(ctx, repo.NodeLifecycle{ID: "rollback-worker", Kind: "worker", HostID: "scan-host"}, "admin"); err != nil {
		t.Fatal(err)
	}
	registryPath := filepath.Join(t.TempDir(), "node-tokens")
	if err := os.WriteFile(registryPath, []byte("legacy-worker=0123456789abcdef0123456789abcdef\n"), 0600); err != nil {
		t.Fatal(err)
	}
	issuer := NewFileNodeCredentialIssuer(failingCredentialBackend{RuntimeBackend: store}, NewNodeTokenRegistry(NodeTokenSet{"legacy-worker": "0123456789abcdef0123456789abcdef"}), registryPath, "https://192.0.2.10:8443")
	if _, err := issuer.IssueNodeCredential(ctx, "rollback-worker", "admin"); err == nil {
		t.Fatal("audit failure accepted")
	}
	tokens, err := ReadNodeTokenSetFile(registryPath)
	if err != nil || len(tokens) != 1 || tokens["rollback-worker"] != "" {
		t.Fatalf("registry was not rolled back: count=%d rollbackEntry=%t err=%v", len(tokens), tokens["rollback-worker"] != "", err)
	}
}

type failingCredentialBackend struct {
	repo.RuntimeBackend
}

func (failingCredentialBackend) RecordNodeCredentialIssued(context.Context, string, string) error {
	return os.ErrPermission
}

func TestNodeCredentialIssueAPIReturnsNoStoreAndOneTimeCredential(t *testing.T) {
	store, err := repo.OpenRuntime(filepath.Join(t.TempDir(), "node-issue-api.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	if _, err := store.RegisterNodeLifecycle(ctx, repo.NodeLifecycle{ID: "api-worker", Kind: "worker", HostID: "scan-host"}, "admin"); err != nil {
		t.Fatal(err)
	}
	registryPath := filepath.Join(t.TempDir(), "node-tokens")
	if err := os.WriteFile(registryPath, []byte("legacy-worker=0123456789abcdef0123456789abcdef\n"), 0600); err != nil {
		t.Fatal(err)
	}
	issuer := NewFileNodeCredentialIssuer(store, NewNodeTokenRegistry(NodeTokenSet{"legacy-worker": "0123456789abcdef0123456789abcdef"}), registryPath, "https://192.0.2.10:8443")
	server := httptest.NewServer(NewRuntimeHandlerWithNodeIssuer(store, nil, "", issuer))
	defer server.Close()
	request := httptest.NewRequest(http.MethodPost, server.URL+"/api/v1/nodes/api-worker/issue", nil)
	response := httptest.NewRecorder()
	server.Config.Handler.ServeHTTP(response, request)
	if response.Code != http.StatusCreated || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("status=%d cacheControl=%q", response.Code, response.Header().Get("Cache-Control"))
	}
	var body NodeCredential
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil || body.ID != "api-worker" || body.Token == "" {
		t.Fatalf("credential metadata: id=%q tokenLength=%d err=%v", body.ID, len(body.Token), err)
	}
}
