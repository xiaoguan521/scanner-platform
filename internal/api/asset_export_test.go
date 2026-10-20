package api

import (
	"bytes"
	"context"
	"encoding/csv"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"scanner-platform/internal/account"
	"scanner-platform/internal/assets"
)

func TestAssetExportIsAuthenticatedFilteredAndFormulaSafe(t *testing.T) {
	accounts, err := account.New(filepath.Join(t.TempDir(), "registry.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer accounts.Close()
	if err := accounts.InitAdmin(context.Background(), "exportadmin", "Safe-Export-Password-12"); err != nil {
		t.Fatal(err)
	}
	store, err := assets.NewWithPinger(accounts.SQLDB(), func(context.Context, string) (bool, error) { return true, nil })
	if err != nil {
		t.Fatal(err)
	}
	handler := NewDevelopmentHandler(accounts, store)
	send := func(method, path, body string, cookie *http.Cookie) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, bytes.NewBufferString(body))
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		if method != http.MethodGet && method != http.MethodHead {
			req.Header.Set("X-Requested-With", "XMLHttpRequest")
		}
		if cookie != nil {
			req.AddCookie(cookie)
		}
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		return rr
	}
	if got := send(http.MethodGet, "/api/v1/assets/export", "", nil); got.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous export: %d", got.Code)
	}
	login := send(http.MethodPost, "/api/v1/auth/login", `{"username":"exportadmin","password":"Safe-Export-Password-12"}`, nil)
	if login.Code != http.StatusOK {
		t.Fatalf("login: %d %s", login.Code, login.Body.String())
	}
	cookie := login.Result().Cookies()[0]
	create := func(body string) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/assets", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Requested-With", "XMLHttpRequest")
		req.AddCookie(cookie)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusCreated {
			t.Fatalf("create asset: %d %s", rr.Code, rr.Body.String())
		}
	}
	create(`{"kind":"host","address":"192.0.2.40","name":"=SUM(A1:A2)","businessGroup":"-group","owner":"+owner","requestedPorts":[22,80],"skippedPorts":[443]}`)
	create(`{"kind":"host","address":"192.0.2.41","name":"other","businessGroup":"QA","owner":"Engineer","requestedPorts":[8080]}`)

	path := "/api/v1/assets/export?q=" + url.QueryEscape("192.0.2.40")
	export := send(http.MethodGet, path, "", cookie)
	if export.Code != http.StatusOK {
		t.Fatalf("filtered export: %d %s", export.Code, export.Body.String())
	}
	if got := export.Header().Get("Content-Type"); got != "text/csv; charset=utf-8" {
		t.Fatalf("content type: %q", got)
	}
	if got := export.Header().Get("Content-Disposition"); got != `attachment; filename="assets.csv"` {
		t.Fatalf("content disposition: %q", got)
	}
	rows, err := csv.NewReader(strings.NewReader(export.Body.String())).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("filtered rows: got %d, want header plus one asset", len(rows))
	}
	if !reflect.DeepEqual(rows[0], assetExportHeader) {
		t.Fatalf("header: %#v", rows[0])
	}
	if got, want := rows[1][3], "'=SUM(A1:A2)"; got != want {
		t.Fatalf("formula name: got %q want %q", got, want)
	}
	if got, want := rows[1][5], "'-group"; got != want {
		t.Fatalf("formula group: got %q want %q", got, want)
	}
	if got, want := rows[1][6], "'+owner"; got != want {
		t.Fatalf("formula owner: got %q want %q", got, want)
	}
	if got := strings.Join(rows[0], ","); strings.Contains(got, "services") || strings.Contains(got, "loginEntries") {
		t.Fatalf("sensitive detail column exported: %q", got)
	}
	if strings.Contains(export.Body.String(), "192.0.2.41") {
		t.Fatalf("filter leaked an unmatching asset: %s", export.Body.String())
	}
	if got := send(http.MethodGet, "/api/v1/assets/export?q=one&q=two", "", cookie).Code; got != http.StatusBadRequest {
		t.Fatalf("repeated filter: %d", got)
	}
	longFilter := "/api/v1/assets/export?q=" + url.QueryEscape(strings.Repeat("x", assetExportMaxFilterBytes+1))
	if got := send(http.MethodGet, longFilter, "", cookie).Code; got != http.StatusBadRequest {
		t.Fatalf("long filter: %d", got)
	}
}
