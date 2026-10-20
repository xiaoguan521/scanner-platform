package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"scanner-platform/internal/account"
	"scanner-platform/internal/assets"
)

func TestAssetImportAPIAuthorizationAndConfirmation(t *testing.T) {
	ctx := context.Background()
	accounts, err := account.New(filepath.Join(t.TempDir(), "import.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer accounts.Close()
	if err := accounts.InitAdmin(ctx, "testadmin", "Safe-Example-Password-14"); err != nil {
		t.Fatal(err)
	}
	admin, _, err := accounts.Authenticate(ctx, "testadmin", "Safe-Example-Password-14")
	if err != nil {
		t.Fatal(err)
	}
	store, err := assets.NewWithPinger(accounts.SQLDB(), func(context.Context, string) (bool, error) { t.Error("import must not ping"); return false, nil })
	if err != nil {
		t.Fatal(err)
	}
	handler := NewDevelopmentHandler(accounts, store)
	send := func(method, path, body, contentType string, cookie *http.Cookie, guard bool) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", contentType)
		if cookie != nil {
			req.AddCookie(cookie)
		}
		if guard {
			req.Header.Set("X-Requested-With", "XMLHttpRequest")
		}
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		return rr
	}
	cookies := map[string]*http.Cookie{}
	for _, role := range []string{"admin", "security_engineer", "ops_approver", "viewer"} {
		username := "testadmin"
		if role != "admin" {
			username = "import_" + role
			if _, err := accounts.Create(ctx, admin, username, "Safe-Example-Password-14", role); err != nil {
				t.Fatal(err)
			}
		}
		login := send("POST", "/api/v1/auth/login", `{"username":"`+username+`","password":"Safe-Example-Password-14"}`, "application/json", nil, true)
		if login.Code != 200 {
			t.Fatalf("login %s=%d", role, login.Code)
		}
		cookies[role] = login.Result().Cookies()[0]
	}
	for _, tc := range []struct {
		name, method, path, body, media, role string
		guard                                 bool
		status                                int
	}{
		{"anonymous preview", "POST", "preview", assets.ImportTemplate, "text/csv", "", true, 401},
		{"anonymous template", "GET", "template", "", "", "", false, 401},
		{"viewer preview", "POST", "preview", assets.ImportTemplate, "text/csv", "viewer", true, 403},
		{"ops confirm", "POST", "confirm", `{"previewId":"missing"}`, "application/json", "ops_approver", true, 403},
		{"viewer template", "GET", "template", "", "", "viewer", false, 403},
		{"preview CSRF", "POST", "preview", assets.ImportTemplate, "text/csv", "admin", false, 403},
		{"confirm CSRF", "POST", "confirm", `{"previewId":"missing"}`, "application/json", "admin", false, 403},
		{"wrong media", "POST", "preview", assets.ImportTemplate, "application/json", "admin", true, 415},
		{"wrong charset", "POST", "preview", assets.ImportTemplate, "text/csv; charset=gbk", "admin", true, 415},
		{"size limit", "POST", "preview", strings.Repeat("x", assets.MaxImportBytes+1), "text/csv", "admin", true, 413},
		{"bad header", "POST", "preview", "kind,address,owner,owner\n", "text/csv", "admin", true, 400},
		{"missing preview", "POST", "confirm", `{"previewId":"missing"}`, "application/json", "admin", true, 409},
		{"client rows rejected", "POST", "confirm", `{"previewId":"missing","rows":[]}`, "application/json", "admin", true, 400},
		{"template", "GET", "template", "", "", "security_engineer", false, 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := send(tc.method, "/api/v1/assets/import/"+tc.path, tc.body, tc.media, cookies[tc.role], tc.guard)
			if got.Code != tc.status {
				t.Fatalf("status=%d want=%d body=%s", got.Code, tc.status, got.Body.String())
			}
		})
	}
	preview := send("POST", "/api/v1/assets/import/preview", assets.ImportTemplate, "text/csv; charset=utf-8", cookies["admin"], true)
	var p assets.ImportPreview
	if err := json.Unmarshal(preview.Body.Bytes(), &p); err != nil || preview.Code != 200 || p.PreviewID == "" {
		t.Fatalf("preview=%s status=%d err=%v", preview.Body.String(), preview.Code, err)
	}
	var count int
	if err := accounts.SQLDB().QueryRow("SELECT count(*) FROM assets").Scan(&count); err != nil || count != 0 {
		t.Fatalf("preview changed registry=%d err=%v", count, err)
	}
	body := `{"previewId":"` + p.PreviewID + `"}`
	if got := send("POST", "/api/v1/assets/import/confirm", body, "application/json", cookies["security_engineer"], true); got.Code != 409 {
		t.Fatalf("cross user=%d", got.Code)
	}
	if got := send("POST", "/api/v1/assets/import/confirm", body, "application/json", cookies["admin"], true); got.Code != 201 {
		t.Fatalf("confirm=%d %s", got.Code, got.Body.String())
	}
	if got := send("POST", "/api/v1/assets/import/confirm", body, "application/json", cookies["admin"], true); got.Code != 409 {
		t.Fatalf("repeat=%d", got.Code)
	}
}
