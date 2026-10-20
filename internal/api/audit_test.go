package api

import (
	"context"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"scanner-platform/internal/account"
	"scanner-platform/internal/repo"
)

func TestAuditLogAPIIsAdminReadOnlyAndFiltersWithoutDetail(t *testing.T) {
	ctx := context.Background()
	accounts, err := account.New(filepath.Join(t.TempDir(), "accounts.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer accounts.Close()
	password := "Example-" + rand.Text()
	if err := accounts.InitAdmin(ctx, "auditadmin", password); err != nil {
		t.Fatal(err)
	}
	admin, adminToken, err := accounts.Authenticate(ctx, "auditadmin", password)
	if err != nil {
		t.Fatal(err)
	}
	viewerPassword := "Example-" + rand.Text()
	if _, err := accounts.Create(ctx, admin, "auditviewer", viewerPassword, "viewer"); err != nil {
		t.Fatal(err)
	}
	_, viewerToken, err := accounts.Authenticate(ctx, "auditviewer", viewerPassword)
	if err != nil {
		t.Fatal(err)
	}
	store, err := repo.NewRuntime(accounts.SQLDB())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := accounts.SQLDB().ExecContext(ctx, `INSERT INTO audit_logs(id,actor,action,object_type,object_id,detail,created_at) VALUES(?,?,?,?,?,?,?)`, "audit-api-1", admin.ID, "create_asset", "asset", "asset-1", `{"secret":"do-not-return"}`, "2026-10-20T10:00:00Z"); err != nil {
		t.Fatal(err)
	}
	handler := NewRuntimeHandler(store, nil, "", accounts)
	send := func(path, token string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, path, nil)
		if token != "" {
			r.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
		}
		out := httptest.NewRecorder()
		handler.ServeHTTP(out, r)
		return out
	}
	if got := send("/api/v1/audit-logs", ""); got.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous audit query: %d", got.Code)
	}
	if got := send("/api/v1/audit-logs", viewerToken); got.Code != http.StatusForbidden {
		t.Fatalf("viewer audit query: %d", got.Code)
	}
	got := send("/api/v1/audit-logs?action=create_asset&limit=1", adminToken)
	if got.Code != http.StatusOK || strings.Contains(got.Body.String(), "do-not-return") || strings.Contains(got.Body.String(), `"detail"`) || !strings.Contains(got.Body.String(), "create_asset") {
		t.Fatalf("admin audit projection: %d %s", got.Code, got.Body.String())
	}
	if got := send("/api/v1/audit-logs?limit=0", adminToken); got.Code != http.StatusBadRequest {
		t.Fatalf("invalid limit: %d", got.Code)
	}
	if got := send("/api/v1/audit-logs?from=not-a-time", adminToken); got.Code != http.StatusBadRequest {
		t.Fatalf("invalid time: %d", got.Code)
	}
}
