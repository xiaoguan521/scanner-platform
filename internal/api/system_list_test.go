package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"scanner-platform/internal/repo"
	"scanner-platform/internal/rules"
)

func TestNodeAndRuleListPaginationAPI(t *testing.T) {
	ctx := context.Background()
	store, err := repo.OpenRuntime(filepath.Join(t.TempDir(), "system-lists.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.TouchNodeState(ctx, "node-alpha", "worker", "", "", "ONLINE"); err != nil {
		t.Fatal(err)
	}
	if err := store.TouchNodeState(ctx, "node-beta", "updater", "", "", "ONLINE"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.RegisterNodeLifecycle(ctx, repo.NodeLifecycle{ID: "registered-only", Kind: "worker", HostID: "scan-host"}, "admin"); err != nil {
		t.Fatal(err)
	}
	if err := store.SyncRules(ctx, []rules.Bundle{{Version: "20261021.01", Channel: "stable"}, {Version: "20261020.01", Channel: "local"}}); err != nil {
		t.Fatal(err)
	}
	handler := NewRuntimeHandler(store, nil, "")
	for _, test := range []struct {
		path       string
		wantTotal  int
		wantLength int
	}{
		{path: "/api/v1/nodes?page=1&page_size=1&q=worker", wantTotal: 2, wantLength: 1},
		{path: "/api/v1/nodes?page=1&page_size=1&q=registered-only", wantTotal: 1, wantLength: 1},
		{path: "/api/v1/rules?page=1&page_size=1&sort=-version", wantTotal: 2, wantLength: 1},
	} {
		request := httptest.NewRequest(http.MethodGet, test.path, nil)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusOK {
			t.Fatalf("%s status=%d body=%s", test.path, response.Code, response.Body.String())
		}
		var body PageListResponse[map[string]any]
		if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body.Total != test.wantTotal || len(body.Items) != test.wantLength || body.Page != 1 || body.PageSize != 1 {
			t.Fatalf("%s body=%+v", test.path, body)
		}
	}
	for _, path := range []string{
		"/api/v1/nodes?page=0&page_size=1",
		"/api/v1/nodes?page=1&page=2&page_size=1",
		"/api/v1/nodes?page=1&page_size=101",
		"/api/v1/nodes?page=1&sort=drop_table",
		"/api/v1/rules?page=1&unknown=x",
		"/api/v1/rules?page=1&sort=drop_table",
	} {
		request := httptest.NewRequest(http.MethodGet, path, strings.NewReader(""))
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("%s status=%d body=%s", path, response.Code, response.Body.String())
		}
	}
}

func TestRuleJobAndCustomRuleListPaginationAPI(t *testing.T) {
	ctx := context.Background()
	store, err := repo.OpenRuntime(filepath.Join(t.TempDir(), "rule-lists.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := store.QueueRuleJob(ctx, rules.Job{Kind: "IMPORT", Bundle: []byte("zip")}, "tester"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SaveCustomRule(ctx, "tester", rules.CustomRule{ID: "legacy-console", Name: "Legacy console", Severity: "medium", MatchType: "word", Part: "body", Values: []string{"marker"}, Enabled: true}, true); err != nil {
		t.Fatal(err)
	}
	handler := NewRuntimeHandler(store, nil, "")
	for _, test := range []struct {
		path string
	}{
		{path: "/api/v1/rule-jobs?page=1&page_size=1&kind=IMPORT"},
		{path: "/api/v1/custom-rules?page=1&page_size=1&severity=medium&enabled=true&q=legacy"},
	} {
		request := httptest.NewRequest(http.MethodGet, test.path, nil)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusOK {
			t.Fatalf("%s status=%d body=%s", test.path, response.Code, response.Body.String())
		}
		var body PageListResponse[map[string]any]
		if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body.Total != 1 || len(body.Items) != 1 || body.Page != 1 || body.PageSize != 1 {
			t.Fatalf("%s body=%+v", test.path, body)
		}
	}
	for _, path := range []string{
		"/api/v1/rule-jobs?page=1&status=UNKNOWN",
		"/api/v1/rule-jobs?page=1&kind=UNKNOWN",
		"/api/v1/custom-rules?page=1&enabled=maybe",
		"/api/v1/custom-rules?page=1&sort=drop_table",
	} {
		request := httptest.NewRequest(http.MethodGet, path, strings.NewReader(""))
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("%s status=%d body=%s", path, response.Code, response.Body.String())
		}
	}
}
