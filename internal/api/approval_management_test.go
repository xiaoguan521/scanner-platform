package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"scanner-platform/internal/account"
	"scanner-platform/internal/approvals"
	"scanner-platform/internal/assets"
)

func TestScopeUpdateDeleteAndRevokeEndpoints(t *testing.T) {
	ctx := context.Background()
	accounts, err := account.New(filepath.Join(t.TempDir(), "approval-api.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer accounts.Close()
	if err := accounts.InitAdmin(ctx, "testadmin", "Safe-Sample-Password-12"); err != nil {
		t.Fatal(err)
	}
	admin, _, err := accounts.Authenticate(ctx, "testadmin", "Safe-Sample-Password-12")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := accounts.Create(ctx, admin, "opsreviewer", "Safe-Other-Password-14", "ops_approver"); err != nil {
		t.Fatal(err)
	}
	assetStore, err := assets.New(accounts.SQLDB())
	if err != nil {
		t.Fatal(err)
	}
	asset, err := assetStore.Create(ctx, admin.ID, assets.Input{Kind: "host", Address: "192.0.2.20", BusinessGroup: "QA", Owner: "Owner"})
	if err != nil {
		t.Fatal(err)
	}
	approvalStore, err := approvals.New(accounts.SQLDB())
	if err != nil {
		t.Fatal(err)
	}
	handler := NewDevelopmentHandler(accounts, assetStore, approvalStore)
	send := func(method, path, body string, cookie *http.Cookie) *httptest.ResponseRecorder {
		request := httptest.NewRequest(method, path, strings.NewReader(body))
		request.Header.Set("X-Requested-With", "XMLHttpRequest")
		if body != "" {
			request.Header.Set("Content-Type", "application/json")
		}
		if cookie != nil {
			request.AddCookie(cookie)
		}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response
	}
	login := func(username, password string) *http.Cookie {
		t.Helper()
		response := send("POST", "/api/v1/auth/login", `{"username":"`+username+`","password":"`+password+`"}`, nil)
		if response.Code != 200 {
			t.Fatalf("login %s: %d %s", username, response.Code, response.Body.String())
		}
		return response.Result().Cookies()[0]
	}
	adminCookie := login("testadmin", "Safe-Sample-Password-12")
	opsCookie := login("opsreviewer", "Safe-Other-Password-14")
	requestBody := func(end string) string {
		return `{"assetId":"` + asset.ID + `","timeWindows":[{"weekdays":[1,2,3,4,5],"start":"09:00","end":"` + end + `","timeZone":"Asia/Shanghai"}],"expiresAt":"` + time.Now().Add(2*time.Hour).UTC().Format(time.RFC3339) + `"}`
	}
	created := send("POST", "/api/v1/scopes", requestBody("18:00"), adminCookie)
	if created.Code != http.StatusCreated {
		t.Fatalf("create scope: %d %s", created.Code, created.Body.String())
	}
	var scope approvals.Scope
	if err := json.NewDecoder(created.Body).Decode(&scope); err != nil {
		t.Fatal(err)
	}
	updated := send("PUT", "/api/v1/scopes/"+scope.ID, requestBody("17:00"), adminCookie)
	if updated.Code != http.StatusOK {
		t.Fatalf("update scope: %d %s", updated.Code, updated.Body.String())
	}
	if err := json.NewDecoder(updated.Body).Decode(&scope); err != nil {
		t.Fatal(err)
	}
	if scope.Status != "PENDING" || scope.TimeWindows[0].End != "17:00" {
		t.Fatalf("updated scope=%+v", scope)
	}
	if deleted := send("DELETE", "/api/v1/scopes/"+scope.ID, "", adminCookie); deleted.Code != http.StatusOK {
		t.Fatalf("delete pending scope: %d %s", deleted.Code, deleted.Body.String())
	}
	created = send("POST", "/api/v1/scopes", requestBody("18:00"), adminCookie)
	if created.Code != http.StatusCreated {
		t.Fatalf("recreate scope: %d %s", created.Code, created.Body.String())
	}
	if err := json.NewDecoder(created.Body).Decode(&scope); err != nil {
		t.Fatal(err)
	}
	decision := `{"decision":"APPROVE","approvalTicket":"SEC-101","note":"approved"}`
	if reviewed := send("POST", "/api/v1/scopes/"+scope.ID+"/review", decision, opsCookie); reviewed.Code != http.StatusOK {
		t.Fatalf("approve scope: %d %s", reviewed.Code, reviewed.Body.String())
	}
	renewed := send("POST", "/api/v1/scopes/renew", `{"ids":["`+scope.ID+`"],"expiresAt":"`+time.Now().Add(4*time.Hour).UTC().Format(time.RFC3339)+`"}`, adminCookie)
	if renewed.Code != http.StatusOK || !strings.Contains(renewed.Body.String(), `"status":"PENDING"`) {
		t.Fatalf("renew scope: %d %s", renewed.Code, renewed.Body.String())
	}
	if reviewed := send("POST", "/api/v1/scopes/"+scope.ID+"/review", decision, opsCookie); reviewed.Code != http.StatusOK {
		t.Fatalf("reapprove renewed scope: %d %s", reviewed.Code, reviewed.Body.String())
	}
	if deleted := send("DELETE", "/api/v1/scopes/"+scope.ID, "", adminCookie); deleted.Code != http.StatusConflict {
		t.Fatalf("delete approved scope: %d %s", deleted.Code, deleted.Body.String())
	}
	revoked := send("POST", "/api/v1/scopes/"+scope.ID+"/revoke", `{}`, adminCookie)
	if revoked.Code != http.StatusOK || !strings.Contains(revoked.Body.String(), `"status":"REVOKED"`) {
		t.Fatalf("revoke scope: %d %s", revoked.Code, revoked.Body.String())
	}
	if deleted := send("DELETE", "/api/v1/scopes/"+scope.ID, "", adminCookie); deleted.Code != http.StatusOK {
		t.Fatalf("delete revoked scope: %d %s", deleted.Code, deleted.Body.String())
	}
}

func TestApprovalListPaginationEndpoints(t *testing.T) {
	ctx := context.Background()
	accounts, err := account.New(filepath.Join(t.TempDir(), "approval-page-api.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer accounts.Close()
	if err := accounts.InitAdmin(ctx, "pageadmin", "Safe-Sample-Password-12"); err != nil {
		t.Fatal(err)
	}
	admin, _, err := accounts.Authenticate(ctx, "pageadmin", "Safe-Sample-Password-12")
	if err != nil {
		t.Fatal(err)
	}
	assetStore, err := assets.New(accounts.SQLDB())
	if err != nil {
		t.Fatal(err)
	}
	asset, err := assetStore.Create(ctx, admin.ID, assets.Input{Kind: "host", Address: "192.0.2.41", BusinessGroup: "QA", Owner: "Owner", RequestedPorts: []int{22, 8080}})
	if err != nil {
		t.Fatal(err)
	}
	approvalStore, err := approvals.New(accounts.SQLDB())
	if err != nil {
		t.Fatal(err)
	}
	handler := NewDevelopmentHandler(accounts, assetStore, approvalStore)
	send := func(path string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, path, nil)
		r.AddCookie(&http.Cookie{Name: sessionCookie, Value: mustSession(t, accounts, "pageadmin", "Safe-Sample-Password-12")})
		out := httptest.NewRecorder()
		handler.ServeHTTP(out, r)
		return out
	}
	request := `{"assetId":"` + asset.ID + `","timeWindows":[{"weekdays":[1],"start":"09:00","end":"18:00","timeZone":"UTC"}],"expiresAt":"` + time.Now().Add(2*time.Hour).UTC().Format(time.RFC3339) + `"}`
	post := httptest.NewRequest(http.MethodPost, "/api/v1/scopes", strings.NewReader(request))
	post.Header.Set("Content-Type", "application/json")
	post.Header.Set("X-Requested-With", "XMLHttpRequest")
	post.AddCookie(&http.Cookie{Name: sessionCookie, Value: mustSession(t, accounts, "pageadmin", "Safe-Sample-Password-12")})
	created := httptest.NewRecorder()
	handler.ServeHTTP(created, post)
	if created.Code != http.StatusCreated {
		t.Fatalf("create scope: %d %s", created.Code, created.Body.String())
	}
	var scopePage ScopePageResponse
	if got := send("/api/v1/scopes?page=1&page_size=1&expiry=all"); got.Code != http.StatusOK || json.Unmarshal(got.Body.Bytes(), &scopePage) != nil || scopePage.Total != 1 || scopePage.PageSize != 1 {
		t.Fatalf("scope page: %d %s %+v", got.Code, got.Body.String(), scopePage)
	}
	if got := send("/api/v1/scopes?page=1&page_size=101"); got.Code != http.StatusBadRequest || !strings.Contains(got.Body.String(), "invalid_scope_list_query") {
		t.Fatalf("invalid scope page: %d %s", got.Code, got.Body.String())
	}
	var portPage PageListResponse[approvals.PortRequest]
	if got := send("/api/v1/port-requests?page=1&page_size=1&status=PENDING&q=192.0.2.41"); got.Code != http.StatusOK || json.Unmarshal(got.Body.Bytes(), &portPage) != nil || portPage.Total != 2 || len(portPage.Items) != 1 {
		t.Fatalf("port page: %d %s %+v", got.Code, got.Body.String(), portPage)
	}
	if got := send("/api/v1/port-requests?page=1&page_size=1&status=UNKNOWN"); got.Code != http.StatusBadRequest || !strings.Contains(got.Body.String(), "invalid_port_request_list_query") {
		t.Fatalf("invalid port page: %d %s", got.Code, got.Body.String())
	}
}

func mustSession(t *testing.T, accounts account.Repository, username, password string) string {
	t.Helper()
	_, token, err := accounts.Authenticate(context.Background(), username, password)
	if err != nil {
		t.Fatal(err)
	}
	return token
}
