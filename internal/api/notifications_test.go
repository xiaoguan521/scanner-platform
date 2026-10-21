package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"scanner-platform/internal/account"
	"scanner-platform/internal/findings"
	"scanner-platform/internal/repo"
)

func TestNotificationsAPIAuthFilterAndReadActions(t *testing.T) {
	ctx := context.Background()
	accounts, err := account.New(filepath.Join(t.TempDir(), "accounts.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer accounts.Close()
	password := "Notification-Admin-Password-2026"
	if err := accounts.InitAdmin(ctx, "notificationadmin", password); err != nil {
		t.Fatal(err)
	}
	admin, token, err := accounts.Authenticate(ctx, "notificationadmin", password)
	if err != nil {
		t.Fatal(err)
	}
	viewerPassword := "Notification-Viewer-Password-2026"
	viewer, err := accounts.Create(ctx, admin, "notificationviewer", viewerPassword, "viewer")
	if err != nil {
		t.Fatal(err)
	}
	_, viewerToken, err := accounts.Authenticate(ctx, viewer.Username, viewerPassword)
	if err != nil {
		t.Fatal(err)
	}
	store, err := repo.NewRuntime(accounts.SQLDB())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	handler := NewRuntimeHandler(store, nil, "", accounts)
	send := func(method, path string, mutation bool, withToken bool) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, nil)
		if mutation {
			r.Header.Set("X-Requested-With", "XMLHttpRequest")
		}
		if withToken {
			r.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
		}
		out := httptest.NewRecorder()
		handler.ServeHTTP(out, r)
		return out
	}
	if got := send(http.MethodGet, "/api/v1/notifications", false, false); got.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous notifications: %d", got.Code)
	}
	if got := send(http.MethodGet, "/api/v1/notifications?unread=maybe", false, true); got.Code != http.StatusBadRequest {
		t.Fatalf("invalid notification filter: %d", got.Code)
	}
	got := send(http.MethodGet, "/api/v1/notifications?unread=true", false, true)
	if got.Code != http.StatusOK || got.Body.String() == "" {
		t.Fatalf("notification list: %d %s", got.Code, got.Body.String())
	}
	page := send(http.MethodGet, "/api/v1/notifications?page=1&page_size=1&unread=true", false, true)
	if page.Code != http.StatusOK || !strings.Contains(page.Body.String(), `"page":1`) || !strings.Contains(page.Body.String(), `"pageSize":1`) {
		t.Fatalf("notification page: %d %s", page.Code, page.Body.String())
	}
	if invalid := send(http.MethodGet, "/api/v1/notifications?page=1&page_size=101", false, true); invalid.Code != http.StatusBadRequest {
		t.Fatalf("invalid notification page: %d %s", invalid.Code, invalid.Body.String())
	}
	score := 5.0
	if _, err := store.SaveKnowledge(ctx, findings.KnowledgeEntry{ID: "API-KNOWLEDGE-001", Title: "Example vulnerability", Description: "safe summary", Component: "apache", Source: "fixture", Solution: "upgrade", Language: "en", CVSSScore: &score, AffectedRanges: []findings.VersionRange{{Introduced: "1.0", Fixed: "2.0"}}}, admin.ID); err != nil {
		t.Fatal(err)
	}
	knowledge := send(http.MethodGet, "/api/v1/knowledge?page=1&page_size=1&q=apache", false, true)
	if knowledge.Code != http.StatusOK || !strings.Contains(knowledge.Body.String(), `"page":1`) || !strings.Contains(knowledge.Body.String(), `API-KNOWLEDGE-001`) {
		t.Fatalf("knowledge page: %d %s", knowledge.Code, knowledge.Body.String())
	}
	if invalid := send(http.MethodGet, "/api/v1/knowledge?page=1&page_size=101", false, true); invalid.Code != http.StatusBadRequest {
		t.Fatalf("invalid knowledge page: %d %s", invalid.Code, invalid.Body.String())
	}
	if got := send(http.MethodPost, "/api/v1/notifications/read-all", false, true); got.Code != http.StatusForbidden {
		t.Fatalf("missing read csrf: %d", got.Code)
	}
	if got := send(http.MethodPost, "/api/v1/notifications/read-all", true, true); got.Code != http.StatusOK {
		t.Fatalf("read all: %d %s", got.Code, got.Body.String())
	}
	viewerSend := func(method, path string, mutation bool) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, nil)
		if mutation {
			r.Header.Set("X-Requested-With", "XMLHttpRequest")
		}
		r.AddCookie(&http.Cookie{Name: sessionCookie, Value: viewerToken})
		out := httptest.NewRecorder()
		handler.ServeHTTP(out, r)
		return out
	}
	if got := viewerSend(http.MethodPost, "/api/v1/notifications/read-all", true); got.Code != http.StatusOK {
		t.Fatalf("viewer read all: %d %s", got.Code, got.Body.String())
	}
	if got := send(http.MethodPost, "/api/v1/notifications/missing/read", true, true); got.Code != http.StatusNotFound {
		t.Fatalf("missing notification: %d %s", got.Code, got.Body.String())
	}
}
