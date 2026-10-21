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
)

func TestUserAPILoginRBACAndLogout(t *testing.T) {
	store, err := account.New(filepath.Join(t.TempDir(), "test.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.InitAdmin(context.Background(), "siteadmin", "Test-Secure-Password-123"); err != nil {
		t.Fatal(err)
	}
	assetStore, err := assets.New(store.SQLDB())
	if err != nil {
		t.Fatal(err)
	}
	handler := NewDevelopmentHandler(store, assetStore)
	send := func(method, path, payload string, cookie *http.Cookie, header bool) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, bytes.NewBufferString(payload))
		req.RemoteAddr = "127.0.0.1:57432"
		if payload != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		if header {
			req.Header.Set("X-Requested-With", "XMLHttpRequest")
		}
		if cookie != nil {
			req.AddCookie(cookie)
		}
		resp := httptest.NewRecorder()
		handler.ServeHTTP(resp, req)
		return resp
	}
	badLogin := send("POST", "/api/v1/auth/login", `{"username":"siteadmin","password":"Test-Secure-Password-123"}`, nil, false)
	if badLogin.Code != 403 {
		t.Fatalf("missing anti-CSRF header: %d", badLogin.Code)
	}
	login := send("POST", "/api/v1/auth/login", `{"username":"siteadmin","password":"Test-Secure-Password-123"}`, nil, true)
	if login.Code != 200 {
		t.Fatalf("login: %d %s", login.Code, login.Body.String())
	}
	cookies := login.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode {
		t.Fatalf("cookie flags: %+v", cookies)
	}
	c := cookies[0]
	if resp := send("GET", "/api/v1/auth/me", "", c, false); resp.Code != 200 {
		t.Fatalf("me: %d", resp.Code)
	}
	if resp := send("GET", "/api/v1/users", "", nil, false); resp.Code != 401 {
		t.Fatalf("anonymous users list: %d", resp.Code)
	}
	if resp := send("GET", "/api/v1/users", "", c, false); resp.Code != 200 {
		t.Fatalf("admin users list: %d", resp.Code)
	}
	create := send("POST", "/api/v1/users", `{"username":"testviewer","password":"Viewer-Test-Password-123","role":"viewer"}`, c, true)
	if create.Code != 201 {
		t.Fatalf("create: %d %s", create.Code, create.Body.String())
	}
	var viewer account.User
	if err := json.Unmarshal(create.Body.Bytes(), &viewer); err != nil {
		t.Fatal(err)
	}
	if viewer.Role != "viewer" {
		t.Fatalf("wrong role: %+v", viewer)
	}
	viewerLogin := send("POST", "/api/v1/auth/login", `{"username":"testviewer","password":"Viewer-Test-Password-123"}`, nil, true)
	if viewerLogin.Code != 200 {
		t.Fatalf("viewer login: %d", viewerLogin.Code)
	}
	vc := viewerLogin.Result().Cookies()[0]
	if resp := send("POST", "/api/v1/users/"+viewer.ID+"/password-reset", `{"password":"Reset-Viewer-Password-456"}`, c, false); resp.Code != 403 {
		t.Fatalf("missing password reset header: %d", resp.Code)
	}
	reset := send("POST", "/api/v1/users/"+viewer.ID+"/password-reset", `{"password":"Reset-Viewer-Password-456"}`, c, true)
	if reset.Code != 200 {
		t.Fatalf("password reset: %d %s", reset.Code, reset.Body.String())
	}
	if resp := send("GET", "/api/v1/auth/me", "", vc, false); resp.Code != 401 {
		t.Fatalf("old viewer session survived password reset: %d", resp.Code)
	}
	newViewerLogin := send("POST", "/api/v1/auth/login", `{"username":"testviewer","password":"Reset-Viewer-Password-456"}`, nil, true)
	if newViewerLogin.Code != 200 {
		t.Fatalf("new viewer password did not authenticate: %d", newViewerLogin.Code)
	}
	vc = newViewerLogin.Result().Cookies()[0]
	if resp := send("GET", "/api/v1/users", "", vc, false); resp.Code != 403 {
		t.Fatalf("viewer listed users: %d", resp.Code)
	}
	if resp := send("POST", "/api/v1/users", `{"username":"hacker","password":"Another-Demo-Password-33","role":"admin"}`, vc, true); resp.Code != 403 {
		t.Fatalf("viewer created admin: %d", resp.Code)
	}
	if resp := send("POST", "/api/v1/users", `{"username":"nocsrf","password":"Another-Demo-Password-33","role":"viewer"}`, c, false); resp.Code != 403 {
		t.Fatalf("missing mutation header: %d", resp.Code)
	}
	update := send("PATCH", "/api/v1/users/"+viewer.ID, `{"role":"viewer","isActive":false}`, c, true)
	if update.Code != 200 {
		t.Fatalf("disable: %d %s", update.Code, update.Body.String())
	}
	if resp := send("GET", "/api/v1/auth/me", "", vc, false); resp.Code != 401 {
		t.Fatalf("disabled session accepted: %d", resp.Code)
	}
	if resp := send("GET", "/api/v1/tasks", "", c, false); resp.Code != 501 {
		t.Fatalf("scanning unexpectedly enabled: %d", resp.Code)
	}
	if resp := send("POST", "/api/v1/tasks", `{}`, c, true); resp.Code != 405 {
		t.Fatalf("scan mutation unexpectedly enabled: %d", resp.Code)
	}
	if resp := send("POST", "/api/v1/auth/logout", "", c, true); resp.Code != 200 {
		t.Fatalf("logout: %d", resp.Code)
	}
	if resp := send("GET", "/api/v1/auth/me", "", c, false); resp.Code != 401 {
		t.Fatalf("logout session accepted: %d", resp.Code)
	}
}
