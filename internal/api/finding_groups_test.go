package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	"scanner-platform/internal/account"
	"scanner-platform/internal/repo"
	"scanner-platform/internal/taskflow"
)

func groupFixtures() []taskflow.Finding {
	base := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	return []taskflow.Finding{
		{ID: "f1", Severity: "HIGH", Status: "OPEN", Engine: "trivy", TemplateOrCVE: "CVE-2099-0001", Title: "库溢出", Package: "libexample1", InstalledVersion: "1.0", FixedVersion: "1.1", AssetID: "asset-a", Target: "192.0.2.10", RiskType: "system", LastSeen: base},
		{ID: "f2", Severity: "HIGH", Status: "IN_PROGRESS", Engine: "trivy", TemplateOrCVE: "CVE-2099-0001", Title: "库溢出", Package: "libexample-bin", InstalledVersion: "1.0", FixedVersion: "1.1", AssetID: "asset-a", Target: "192.0.2.10", RiskType: "system", LastSeen: base.Add(time.Hour)},
		{ID: "f3", Severity: "CRITICAL", Status: "OPEN", Engine: "trivy", TemplateOrCVE: "CVE-2099-0002", Title: "远程执行", Package: "libexample1", InstalledVersion: "1.0", AssetID: "asset-b", Target: "192.0.2.11", RiskType: "system", LastSeen: base},
		{ID: "f4", Severity: "LOW", Status: "OPEN", Engine: "trivy", TemplateOrCVE: "CVE-2099-0003", Title: "信息泄露", Package: "tool", InstalledVersion: "2.0", FixedVersion: "2.1", AssetID: "asset-a", Target: "192.0.2.10", RiskType: "system", LastSeen: base},
		{ID: "f5", Severity: "MEDIUM", Status: "OPEN", Engine: "nuclei", TemplateOrCVE: "http-missing-security-headers", Title: "缺少响应头", Target: "192.0.2.10:80", AssetID: "asset-a", RiskType: "web", LastSeen: base},
	}
}

func TestGroupFindingsByCVE(t *testing.T) {
	groups, ungrouped := groupFindings(groupFixtures(), "cve")
	if ungrouped != 0 || len(groups) != 4 {
		t.Fatalf("groups=%d ungrouped=%d", len(groups), ungrouped)
	}
	if groups[0].Key != "CVE-2099-0002" || groups[1].Key != "CVE-2099-0001" || groups[3].Key != "CVE-2099-0003" {
		t.Fatalf("groups must sort by highest severity first: %v %v %v %v", groups[0].Key, groups[1].Key, groups[2].Key, groups[3].Key)
	}
	shared := groups[1]
	if shared.Count != 2 || shared.AssetCount != 1 || shared.Title != "库溢出" || len(shared.Packages) != 2 || shared.StatusCounts["OPEN"] != 1 || shared.StatusCounts["IN_PROGRESS"] != 1 {
		t.Fatalf("one CVE across two binary packages must be one group: %+v", shared)
	}
	if len(shared.FixedVersions) != 1 || shared.FixedVersions[0] != "1.1" || shared.InstalledVersions != nil || !shared.LastSeen.Equal(time.Date(2026, time.January, 1, 1, 0, 0, 0, time.UTC)) {
		t.Fatalf("versions and lastSeen: %+v", shared)
	}
}

func TestGroupFindingsByPackage(t *testing.T) {
	groups, ungrouped := groupFindings(groupFixtures(), "package")
	if ungrouped != 1 {
		t.Fatalf("findings without a package are reported as ungrouped: %d", ungrouped)
	}
	if len(groups) != 3 || groups[0].Key != "libexample1" {
		t.Fatalf("unexpected package groups: %+v", groups)
	}
	lib := groups[0]
	if lib.Count != 2 || lib.CVECount != 2 || lib.AssetCount != 2 || lib.MaxSeverity != "CRITICAL" || len(lib.InstalledVersions) != 1 || len(lib.FixedVersions) != 1 {
		t.Fatalf("package aggregate: %+v", lib)
	}
}

func TestParseFindingGroupQuery(t *testing.T) {
	by, page, size, query, ok := parseFindingGroupQuery(url.Values{"by": {"package"}, "page": {"2"}, "page_size": {"50"}, "severity": {"HIGH"}, "engine": {"trivy"}, "fixable": {"true"}, "q": {"lib"}})
	if !ok || by != "package" || page != 2 || size != 50 || query.Severity != "HIGH" || query.Engine != "trivy" || !query.FixableOnly || query.Search != "lib" || query.PageSize != 0 || query.Page != 1 {
		t.Fatalf("unexpected parse: %v %v %v %+v %v", by, page, size, query, ok)
	}
	if _, _, size, query, ok := parseFindingGroupQuery(url.Values{"by": {"cve"}}); !ok || size != 20 || query.PageSize != 0 {
		t.Fatalf("defaults: %v %+v %v", size, query, ok)
	}
	for name, values := range map[string]url.Values{
		"missing by":     {},
		"bad by":         {"by": {"asset"}},
		"duplicate by":   {"by": {"cve", "package"}},
		"page zero":      {"by": {"cve"}, "page": {"0"}},
		"page too large": {"by": {"cve"}, "page_size": {"101"}},
		"sort":           {"by": {"cve"}, "sort": {"-severity"}},
		"unknown filter": {"by": {"cve"}, "drop": {"1"}},
		"bad engine":     {"by": {"cve"}, "engine": {"sh"}},
		"bad fixable":    {"by": {"cve"}, "fixable": {"yes"}},
	} {
		if _, _, _, _, ok := parseFindingGroupQuery(values); ok {
			t.Fatalf("%s accepted", name)
		}
	}
}

func TestFindingGroupsAPI(t *testing.T) {
	ctx := context.Background()
	accounts, err := account.New(filepath.Join(t.TempDir(), "platform.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer accounts.Close()
	store, err := repo.NewRuntime(accounts.SQLDB())
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range groupFixtures() {
		task, err := store.CreateSyntheticTask(ctx)
		if err != nil {
			t.Fatal(err)
		}
		item.TaskID = task.ID
		data, err := json.Marshal(item)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := accounts.SQLDB().ExecContext(ctx, `INSERT INTO security_findings(id,task_id,data) VALUES(?,?,?)`, item.ID, task.ID, string(data)); err != nil {
			t.Fatal(err)
		}
	}
	handler := NewRuntimeHandler(store, nil, "")
	get := func(query string) (*httptest.ResponseRecorder, FindingGroupPage) {
		t.Helper()
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/v1/findings/groups?"+query, nil))
		var body FindingGroupPage
		if response.Code == http.StatusOK {
			if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
		}
		return response, body
	}
	response, body := get("by=cve&engine=trivy&page=1&page_size=2")
	if response.Code != http.StatusOK || body.Total != 3 || len(body.Items) != 2 || body.Findings != 4 || body.Items[0].Key != "CVE-2099-0002" || body.PageSize != 2 {
		t.Fatalf("cve groups: %d %+v", response.Code, body)
	}
	_, body = get("by=cve&engine=trivy&page=2&page_size=2")
	if len(body.Items) != 1 || body.Items[0].Key != "CVE-2099-0003" {
		t.Fatalf("second page: %+v", body)
	}
	_, body = get("by=package&fixable=true")
	if body.Total != 3 || body.Findings != 3 || body.Ungrouped != 0 || body.Items[0].Key != "libexample-bin" {
		t.Fatalf("fixable package groups: %+v", body)
	}
	_, body = get("by=package")
	if body.Ungrouped != 1 || body.Counts.Vulnerabilities != 5 {
		t.Fatalf("package groups report ungrouped findings and counts: %+v", body)
	}
	if response, _ := get("by=asset"); response.Code != http.StatusBadRequest {
		t.Fatalf("invalid dimension: %d", response.Code)
	}
	// The drill-down filter returns exactly the grouped findings.
	list := httptest.NewRecorder()
	handler.ServeHTTP(list, httptest.NewRequest(http.MethodGet, "/api/v1/findings?page=1&page_size=10&cve=CVE-2099-0001&sort=-severity", nil))
	var page FindingPageResponse
	if err := json.NewDecoder(list.Body).Decode(&page); err != nil || page.Total != 2 {
		t.Fatalf("drill-down: %+v err=%v", page, err)
	}
}
