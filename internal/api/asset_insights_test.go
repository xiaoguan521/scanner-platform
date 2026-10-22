package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"scanner-platform/internal/account"
	"scanner-platform/internal/assets"
	"scanner-platform/internal/repo"
	"scanner-platform/internal/taskflow"
)

func TestBuildAssetInsights(t *testing.T) {
	base := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	finished := base.Add(3 * time.Hour)
	findingItems := []taskflow.Finding{
		{ID: "low", AssetID: "asset-1", Severity: "LOW", Status: "OPEN", LastSeen: base.Add(2 * time.Hour)},
		{ID: "critical", AssetID: "asset-1", Severity: "CRITICAL", Status: "ACCEPTED_RISK", LastSeen: base},
		{ID: "high-new", AssetID: "asset-1", Severity: "HIGH", Status: "REOPENED", LastSeen: base.Add(time.Hour)},
		{ID: "high-old", AssetID: "asset-1", Severity: "HIGH", Status: "IN_PROGRESS", LastSeen: base},
		{ID: "fixed", AssetID: "asset-1", Severity: "CRITICAL", Status: "FIXED", LastSeen: base},
		{ID: "false-positive", AssetID: "asset-1", Severity: "HIGH", Status: "FALSE_POSITIVE", LastSeen: base},
		{ID: "other", AssetID: "asset-other", Severity: "HIGH", Status: "OPEN", LastSeen: base},
	}
	tasks := []taskflow.Task{
		{ID: "old-probe", AssetID: "asset-1", Engines: []string{"port-probe"}, Status: "COMPLETED", CreatedAt: base, PortProbeResults: []taskflow.PortProbeResult{{Port: 22}}},
		{ID: "new-auto", AssetID: "asset-1", Engines: []string{"auto"}, Status: "COMPLETED", CreatedAt: base.Add(2 * time.Hour), PortProbeResults: []taskflow.PortProbeResult{{Port: 80}, {Port: 443}}, Chunks: []taskflow.Chunk{{FinishedAt: &finished}}},
		{ID: "synthetic", AssetID: "asset-1", Engines: []string{"auto"}, Status: "RUNNING", CreatedAt: base.Add(time.Hour), Synthetic: true},
		{ID: "unrelated", AssetID: "asset-other", Engines: []string{"auto"}, Status: "RUNNING", CreatedAt: base.Add(5 * time.Hour)},
	}
	items := buildAssetInsights([]string{"asset-1", "asset-empty"}, findingItems, tasks)
	if len(items) != 2 || items[0].AssetID != "asset-1" || items[1].AssetID != "asset-empty" {
		t.Fatalf("insights must follow requested order: %+v", items)
	}
	first := items[0]
	if first.ActiveFindingCount != 4 {
		t.Fatalf("FIXED and FALSE_POSITIVE must not count as active: %+v", first)
	}
	order := []string{}
	for _, f := range first.ActiveFindings {
		order = append(order, f.ID)
	}
	if strings.Join(order, ",") != "critical,high-new,high-old,low" {
		t.Fatalf("active findings must sort by severity then lastSeen: %v", order)
	}
	if first.LatestProbe == nil || first.LatestProbe.ID != "new-auto" || len(first.LatestProbe.OpenPorts) != 2 {
		t.Fatalf("latest probe must be the newest auto/port-probe task: %+v", first.LatestProbe)
	}
	if len(first.RecentTasks) != 2 || first.RecentTasks[0].ID != "new-auto" || first.RecentTasks[0].FinishedAt == nil || first.RecentTasks[1].ID != "old-probe" {
		t.Fatalf("recent tasks must be newest first and skip synthetic tasks: %+v", first.RecentTasks)
	}
	if items[1].ActiveFindingCount != 0 || items[1].LatestProbe != nil || items[1].ActiveFindings == nil || items[1].RecentTasks == nil {
		t.Fatalf("empty asset must have empty, non-nil lists: %+v", items[1])
	}
}

func TestBuildAssetInsightsCapsLists(t *testing.T) {
	base := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	var findingItems []taskflow.Finding
	for i := 0; i < maxAssetInsightFindings+5; i++ {
		findingItems = append(findingItems, taskflow.Finding{ID: "f", AssetID: "asset-1", Severity: "LOW", Status: "OPEN", LastSeen: base})
	}
	var tasks []taskflow.Task
	for i := 0; i < maxAssetInsightTasks+5; i++ {
		tasks = append(tasks, taskflow.Task{ID: "t", AssetID: "asset-1", Engines: []string{"auto"}, Status: "COMPLETED", CreatedAt: base.Add(time.Duration(i) * time.Minute)})
	}
	item := buildAssetInsights([]string{"asset-1"}, findingItems, tasks)[0]
	if item.ActiveFindingCount != maxAssetInsightFindings+5 || len(item.ActiveFindings) != maxAssetInsightFindings || len(item.RecentTasks) != maxAssetInsightTasks {
		t.Fatalf("lists must be capped while the count stays exact: count=%d findings=%d tasks=%d", item.ActiveFindingCount, len(item.ActiveFindings), len(item.RecentTasks))
	}
}

func TestParseAssetInsightIDs(t *testing.T) {
	many := strings.TrimSuffix(strings.Repeat("a,", maxAssetInsightIDs), ",")
	tooMany := make([]string, 0, maxAssetInsightIDs+1)
	for i := 0; i <= maxAssetInsightIDs; i++ {
		tooMany = append(tooMany, fmt.Sprintf("asset-%d", i))
	}
	cases := []struct {
		query string
		want  []string
		ok    bool
	}{
		{"ids=a,b,a", []string{"a", "b"}, true},
		{"ids=" + many, []string{"a"}, true},
		{"", nil, false},
		{"ids=", nil, false},
		{"ids=a,,b", nil, false},
		{"ids=a&ids=b", nil, false},
		{"ids=a&extra=1", nil, false},
		{"ids=" + strings.Repeat("x", 161), nil, false},
		{"ids=" + strings.Join(tooMany, ","), nil, false},
	}
	for _, tc := range cases {
		request := httptest.NewRequest(http.MethodGet, "/api/v1/assets/insights?"+tc.query, nil)
		got, ok := parseAssetInsightIDs(request)
		if ok != tc.ok || strings.Join(got, ",") != strings.Join(tc.want, ",") {
			t.Fatalf("query %q: got %v %v, want %v %v", tc.query, got, ok, tc.want, tc.ok)
		}
	}
}

func TestAssetInsightsEndpointRequiresAuthAndValidatesQuery(t *testing.T) {
	accounts, err := account.New(filepath.Join(t.TempDir(), "platform.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer accounts.Close()
	if err := accounts.InitAdmin(context.Background(), "insightadmin", "Safe-Insight-Password-12"); err != nil {
		t.Fatal(err)
	}
	store, err := repo.NewRuntime(accounts.SQLDB())
	if err != nil {
		t.Fatal(err)
	}
	assetStore, err := assets.NewWithPinger(accounts.SQLDB(), func(context.Context, string) (bool, error) { return true, nil })
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(NewRuntimeHandler(store, NewDevelopmentHandler(accounts, assetStore), "", accounts))
	defer server.Close()

	get := func(path string, cookie *http.Cookie) *http.Response {
		t.Helper()
		request, err := http.NewRequest(http.MethodGet, server.URL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		if cookie != nil {
			request.AddCookie(cookie)
		}
		response, err := server.Client().Do(request)
		if err != nil {
			t.Fatal(err)
		}
		return response
	}
	if response := get("/api/v1/assets/insights?ids=asset-1", nil); response.StatusCode != http.StatusUnauthorized {
		response.Body.Close()
		t.Fatalf("anonymous insights: %d", response.StatusCode)
	} else {
		response.Body.Close()
	}

	loginRequest, err := http.NewRequest(http.MethodPost, server.URL+"/api/v1/auth/login", strings.NewReader(`{"username":"insightadmin","password":"Safe-Insight-Password-12"}`))
	if err != nil {
		t.Fatal(err)
	}
	loginRequest.Header.Set("Content-Type", "application/json")
	loginRequest.Header.Set("X-Requested-With", "XMLHttpRequest")
	login, err := server.Client().Do(loginRequest)
	if err != nil {
		t.Fatal(err)
	}
	login.Body.Close()
	if login.StatusCode != http.StatusOK {
		t.Fatalf("login: %d", login.StatusCode)
	}
	cookie := login.Cookies()[0]

	for _, path := range []string{"/api/v1/assets/insights", "/api/v1/assets/insights?ids=", "/api/v1/assets/insights?ids=a&q=b"} {
		response := get(path, cookie)
		response.Body.Close()
		if response.StatusCode != http.StatusBadRequest {
			t.Fatalf("invalid insight query %s: %d", path, response.StatusCode)
		}
	}
	response := get("/api/v1/assets/insights?ids=asset-1,asset-2", cookie)
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("insights: %d", response.StatusCode)
	}
	var body ListResponse[AssetInsight]
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.Total != 2 || body.Items[0].AssetID != "asset-1" || body.Items[1].ActiveFindingCount != 0 {
		t.Fatalf("unexpected insights: %+v", body)
	}
}
