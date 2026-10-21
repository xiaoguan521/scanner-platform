package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"scanner-platform/internal/account"
	"scanner-platform/internal/assets"
	"scanner-platform/internal/repo"
)

func TestSystemSettingsAdminAPIAndSessionCookiePolicy(t *testing.T) {
	ctx := context.Background()
	accounts, err := account.New(filepath.Join(t.TempDir(), "accounts.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer accounts.Close()
	adminPassword := "Admin-System-Password-2026"
	if err := accounts.InitAdmin(ctx, "settingsadmin", adminPassword); err != nil {
		t.Fatal(err)
	}
	admin, adminToken, err := accounts.Authenticate(ctx, "settingsadmin", adminPassword)
	if err != nil {
		t.Fatal(err)
	}
	viewerPassword := "Viewer-System-Password-2026"
	if _, err := accounts.Create(ctx, admin, "settingsviewer", viewerPassword, "viewer"); err != nil {
		t.Fatal(err)
	}
	_, viewerToken, err := accounts.Authenticate(ctx, "settingsviewer", viewerPassword)
	if err != nil {
		t.Fatal(err)
	}
	registry, err := assets.New(accounts.SQLDB())
	if err != nil {
		t.Fatal(err)
	}
	store, err := repo.NewRuntime(accounts.SQLDB())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	handler := NewRuntimeHandler(store, NewDevelopmentHandler(accounts, registry), "", accounts)
	send := func(method, path, body, token string, mutation bool) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, bytes.NewBufferString(body))
		if body != "" {
			r.Header.Set("Content-Type", "application/json")
		}
		if mutation {
			r.Header.Set("X-Requested-With", "XMLHttpRequest")
		}
		if token != "" {
			r.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
		}
		out := httptest.NewRecorder()
		handler.ServeHTTP(out, r)
		return out
	}
	if got := send(http.MethodGet, "/api/v1/system-settings", "", "", false); got.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous settings read: %d", got.Code)
	}
	if got := send(http.MethodGet, "/api/v1/system-settings", "", viewerToken, false); got.Code != http.StatusForbidden {
		t.Fatalf("viewer settings read: %d", got.Code)
	}
	got := send(http.MethodGet, "/api/v1/system-settings", "", adminToken, false)
	if got.Code != http.StatusOK {
		t.Fatalf("admin settings read: %d %s", got.Code, got.Body.String())
	}
	var defaults repo.SystemSettings
	if err := json.Unmarshal(got.Body.Bytes(), &defaults); err != nil || defaults.SessionDurationMinutes != 480 {
		t.Fatalf("default settings: %+v %v", defaults, err)
	}
	if got := send(http.MethodPut, "/api/v1/system-settings", `{"timeZone":"UTC","sessionDurationMinutes":60}`, adminToken, false); got.Code != http.StatusForbidden {
		t.Fatalf("missing mutation header: %d", got.Code)
	}
	if got := send(http.MethodPut, "/api/v1/system-settings", `{"timeZone":"Mars/Phobos","sessionDurationMinutes":60}`, adminToken, true); got.Code != http.StatusBadRequest {
		t.Fatalf("invalid settings: %d %s", got.Code, got.Body.String())
	}
	if got := send(http.MethodPut, "/api/v1/system-settings", `{"timeZone":"UTC","sessionDurationMinutes":60}`, viewerToken, true); got.Code != http.StatusForbidden {
		t.Fatalf("viewer settings write: %d", got.Code)
	}
	if got := send(http.MethodPut, "/api/v1/system-settings", `{"timeZone":"UTC","sessionDurationMinutes":60}`, adminToken, true); got.Code != http.StatusOK {
		t.Fatalf("admin settings write: %d %s", got.Code, got.Body.String())
	}
	if got := send(http.MethodGet, "/api/v1/notification-settings", "", viewerToken, false); got.Code != http.StatusForbidden {
		t.Fatalf("viewer notification settings read: %d", got.Code)
	}
	if got := send(http.MethodGet, "/api/v1/notification-settings", "", adminToken, false); got.Code != http.StatusOK {
		t.Fatalf("admin notification settings read: %d %s", got.Code, got.Body.String())
	}
	if got := send(http.MethodPut, "/api/v1/notification-settings", `{"webhookEnabled":true,"webhookUrl":"http://notify.example.test/hook"}`, adminToken, true); got.Code != http.StatusBadRequest {
		t.Fatalf("unsafe notification webhook accepted: %d %s", got.Code, got.Body.String())
	}
	if got := send(http.MethodPut, "/api/v1/notification-settings", `{"webhookEnabled":true,"webhookUrl":"https://notify.example.test/hook"}`, viewerToken, true); got.Code != http.StatusForbidden {
		t.Fatalf("viewer notification settings write: %d", got.Code)
	}
	if got := send(http.MethodPut, "/api/v1/notification-settings", `{"webhookEnabled":true,"webhookUrl":"https://notify.example.test/hook"}`, adminToken, true); got.Code != http.StatusOK {
		t.Fatalf("admin notification settings write: %d %s", got.Code, got.Body.String())
	}
	if got := send(http.MethodGet, "/api/v1/notification-deliveries?limit=1&offset=0", "", adminToken, false); got.Code != http.StatusOK {
		t.Fatalf("admin notification deliveries read: %d %s", got.Code, got.Body.String())
	}
	if got := send(http.MethodGet, "/api/v1/notification-deliveries?limit=0", "", adminToken, false); got.Code != http.StatusBadRequest {
		t.Fatalf("invalid notification delivery pagination accepted: %d", got.Code)
	}
	if got := send(http.MethodGet, "/api/v1/notification-deliveries?secret=1", "", adminToken, false); got.Code != http.StatusBadRequest {
		t.Fatalf("unknown notification delivery query accepted: %d", got.Code)
	}
	if got := send(http.MethodGet, "/api/v1/notification-deliveries", "", viewerToken, false); got.Code != http.StatusForbidden {
		t.Fatalf("viewer notification deliveries read: %d", got.Code)
	}
	loginHandler := NewDevelopmentHandler(accounts, registry)
	login := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewBufferString(`{"username":"settingsviewer","password":"Viewer-System-Password-2026"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Requested-With", "XMLHttpRequest")
	loginHandler.ServeHTTP(login, request)
	if login.Code != http.StatusOK || len(login.Result().Cookies()) != 1 || login.Result().Cookies()[0].MaxAge != 3600 {
		t.Fatalf("session cookie did not use settings: code=%d cookies=%v", login.Code, login.Result().Cookies())
	}
}
