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

func TestAssetAPIRequiresLoginAndScopedWrites(t *testing.T) {
	a, err := account.New(filepath.Join(t.TempDir(), "registry.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	if err := a.InitAdmin(context.Background(), "testadmin", "Safe-Sample-Password-12"); err != nil {
		t.Fatal(err)
	}
	store, err := assets.New(a.SQLDB())
	if err != nil {
		t.Fatal(err)
	}
	handler := NewDevelopmentHandler(a, store)
	send := func(method, path, body string, cookie *http.Cookie, guard bool) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, bytes.NewBufferString(body))
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		if guard {
			req.Header.Set("X-Requested-With", "XMLHttpRequest")
		}
		if cookie != nil {
			req.AddCookie(cookie)
		}
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		return rr
	}
	if got := send("GET", "/api/v1/assets", "", nil, false); got.Code != 401 {
		t.Fatalf("anonymous list: %d", got.Code)
	}
	login := send("POST", "/api/v1/auth/login", `{"username":"testadmin","password":"Safe-Sample-Password-12"}`, nil, true)
	if login.Code != 200 {
		t.Fatalf("login: %d", login.Code)
	}
	c := login.Result().Cookies()[0]
	reqBody := `{"kind":"host","address":"192.0.2.20","businessGroup":"QA","owner":"Engineer","requestedPorts":[443,80]}`
	if got := send("POST", "/api/v1/assets", reqBody, c, false); got.Code != 403 {
		t.Fatalf("CSRF guard: %d", got.Code)
	}
	created := send("POST", "/api/v1/assets", reqBody, c, true)
	if created.Code != 201 {
		t.Fatalf("create: %d %s", created.Code, created.Body.String())
	}
	var asset assets.Asset
	if err := json.Unmarshal(created.Body.Bytes(), &asset); err != nil {
		t.Fatal(err)
	}
	if len(asset.Ports) != 0 || len(asset.RequestedPorts) != 2 {
		t.Fatalf("unsafe grant: %+v", asset)
	}
	if got := send("POST", "/api/v1/assets", reqBody, c, true); got.Code != 409 {
		t.Fatalf("duplicate asset: %d", got.Code)
	}
	if got := send("POST", "/api/v1/assets", `{"kind":"host","address":"192.0.2.0/24","businessGroup":"QA","owner":"Engineer"}`, c, true); got.Code != 400 {
		t.Fatalf("CIDR accepted: %d", got.Code)
	}
	if got := send("GET", "/api/v1/assets", "", c, false); got.Code != 200 {
		t.Fatalf("list: %d", got.Code)
	}
	updated := send("PATCH", "/api/v1/assets/"+asset.ID, `{"businessGroup":"New Group","owner":"Engineer","requestedPorts":[8443]}`, c, true)
	if updated.Code != 200 {
		t.Fatalf("update: %d %s", updated.Code, updated.Body.String())
	}
	if got := send("PATCH", "/api/v1/assets/missing", `{"businessGroup":"QA","owner":"Engineer"}`, c, true); got.Code != 404 {
		t.Fatalf("missing asset: %d", got.Code)
	}
	viewer, err := a.Create(context.Background(), account.User{ID: "testadmin", Role: "admin"}, "testviewer", "Another-Safe-Password-14", "viewer")
	if err != nil {
		t.Fatal(err)
	}
	_ = viewer
	loginViewer := send("POST", "/api/v1/auth/login", `{"username":"testviewer","password":"Another-Safe-Password-14"}`, nil, true)
	if loginViewer.Code != 200 {
		t.Fatalf("viewer login: %d", loginViewer.Code)
	}
	vc := loginViewer.Result().Cookies()[0]
	if got := send("GET", "/api/v1/assets", "", vc, false); got.Code != 200 {
		t.Fatalf("viewer list: %d", got.Code)
	}
	if got := send("POST", "/api/v1/assets", reqBody, vc, true); got.Code != 403 {
		t.Fatalf("viewer created asset: %d", got.Code)
	}
	if got := send("PATCH", "/api/v1/assets/"+asset.ID, `{"businessGroup":"Bad","owner":"Bad"}`, vc, true); got.Code != 403 {
		t.Fatalf("viewer edited asset: %d", got.Code)
	}
	for _, tc := range []struct {
		role     string
		expected int
	}{
		{"security_engineer", 200},
		{"ops_approver", 403},
	} {
		loginName := "role_" + tc.role
		if _, err := a.Create(context.Background(), account.User{ID: "testadmin", Role: "admin"}, loginName, "Safe-Role-Password-32", tc.role); err != nil {
			t.Fatal(err)
		}
		roleLogin := send("POST", "/api/v1/auth/login", `{"username":"`+loginName+`","password":"Safe-Role-Password-32"}`, nil, true)
		if roleLogin.Code != 200 {
			t.Fatalf("%s login: %d", tc.role, roleLogin.Code)
		}
		roleCookie := roleLogin.Result().Cookies()[0]
		patch := send("PATCH", "/api/v1/assets/"+asset.ID, `{"businessGroup":"New Group","owner":"Engineer","requestedPorts":[8080]}`, roleCookie, true)
		if patch.Code != tc.expected {
			t.Fatalf("%s patch: got %d want %d", tc.role, patch.Code, tc.expected)
		}
	}
	if got := send("GET", "/api/v1/port-quarantines", "", c, false); got.Code != 501 {
		t.Fatalf("quarantine should remain unavailable: %d", got.Code)
	}
}
