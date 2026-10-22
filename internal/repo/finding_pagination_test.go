package repo

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"scanner-platform/internal/taskflow"
)

func TestRuntimeFindingListPageFiltersCountsAndSorts(t *testing.T) {
	ctx := context.Background()
	store, err := OpenRuntime(filepath.Join(t.TempDir(), "platform.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	base := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	fixtures := []taskflow.Finding{
		{ID: "finding-high", Severity: "HIGH", Status: "OPEN", Engine: "trivy", TemplateOrCVE: "CVE-2099-0001", Target: "192.0.2.10:22", Title: "包版本风险", Package: "apache2", InstalledVersion: "2.4.1", FixedVersion: "2.4.2", RiskType: "system", DetectMethod: "version", Confidence: "medium", BusinessGroup: "平台", AssetID: "asset-a", FirstSeen: base, LastSeen: base.Add(2 * time.Hour)},
		{ID: "finding-login", Severity: "MEDIUM", Status: "IN_PROGRESS", Engine: "nuclei", TemplateOrCVE: "login-panel", Target: "192.0.2.10:80", Title: "登录入口", RiskType: "login_entry", DetectMethod: "principle", Confidence: "high", BusinessGroup: "平台", AssetID: "asset-a", FirstSeen: base.Add(time.Hour), LastSeen: base.Add(3 * time.Hour)},
		{ID: "finding-config", Severity: "LOW", Status: "FIXED", Engine: "nuclei", TemplateOrCVE: "headers", Target: "192.0.2.11:80", Title: "安全响应头", RiskType: "web", DetectMethod: "configuration", Confidence: "high", BusinessGroup: "业务", AssetID: "asset-b", FirstSeen: base.Add(2 * time.Hour), LastSeen: base.Add(4 * time.Hour)},
	}
	for index := range fixtures {
		task, err := store.CreateSyntheticTask(ctx)
		if err != nil {
			t.Fatal(err)
		}
		fixtures[index].TaskID = task.ID
		data, err := json.Marshal(fixtures[index])
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.db.ExecContext(ctx, `INSERT INTO security_findings(id,task_id,data) VALUES(?,?,?)`, fixtures[index].ID, task.ID, string(data)); err != nil {
			t.Fatal(err)
		}
	}

	page, err := store.ListRuntimeFindingsPage(ctx, FindingListQuery{Page: 1, PageSize: 1, Severity: "HIGH", Sort: "-last_seen"})
	if err != nil {
		t.Fatal(err)
	}
	if page.Total != 1 || len(page.Items) != 1 || page.Items[0].ID != "finding-high" || page.Page != 1 || page.PageSize != 1 {
		t.Fatalf("unexpected severity page: %+v", page)
	}
	if page.Counts.Vulnerabilities != 1 || page.Counts.Version != 1 || page.Counts.Verified != 0 || page.Counts.LoginEntries != 0 {
		t.Fatalf("unexpected severity counts: %+v", page.Counts)
	}

	page, err = store.ListRuntimeFindingsPage(ctx, FindingListQuery{Page: 1, PageSize: 10, Search: "CVE-2099", BusinessGroup: "平台", AssetID: "asset-a", Sort: "last_seen"})
	if err != nil || page.Total != 1 || len(page.Items) != 1 || page.Items[0].ID != "finding-high" {
		t.Fatalf("search and ownership filter: %+v err=%v", page, err)
	}

	page, err = store.ListRuntimeFindingsPage(ctx, FindingListQuery{Page: 1, PageSize: 10, Risk: "login_entry"})
	if err != nil || page.Total != 1 || page.Counts.LoginEntries != 1 || page.Items[0].ID != "finding-login" {
		t.Fatalf("login-entry filter: %+v err=%v", page, err)
	}

	page, err = store.ListRuntimeFindingsPage(ctx, FindingListQuery{Page: 1, PageSize: 10, OnlyVerified: true})
	if err != nil || page.Total != 1 || page.Counts.Verified != 1 {
		t.Fatalf("verified filter: %+v err=%v", page, err)
	}
	for name, query := range map[string]FindingListQuery{
		"exact cve":     {Page: 1, PageSize: 10, CVE: "CVE-2099-0001"},
		"exact package": {Page: 1, PageSize: 10, Package: "apache2"},
		"engine":        {Page: 1, PageSize: 10, Engine: "trivy"},
		"fixable":       {Page: 1, PageSize: 10, FixableOnly: true},
	} {
		page, err = store.ListRuntimeFindingsPage(ctx, query)
		if err != nil || page.Total != 1 || page.Items[0].ID != "finding-high" {
			t.Fatalf("%s filter: %+v err=%v", name, page, err)
		}
	}
	page, err = store.ListRuntimeFindingsPage(ctx, FindingListQuery{Page: 1, PageSize: 10, CVE: "CVE-2099"})
	if err != nil || page.Total != 0 {
		t.Fatalf("cve filter must match exactly: %+v err=%v", page, err)
	}
	page, err = store.ListRuntimeFindingsPage(ctx, FindingListQuery{Page: 1, PageSize: 10, Engine: "nuclei", Sort: "-severity"})
	if err != nil || page.Total != 2 || page.Items[0].ID != "finding-login" {
		t.Fatalf("engine filter with severity sort: %+v err=%v", page, err)
	}
	if _, err := store.ListRuntimeFindingsPage(ctx, FindingListQuery{Page: 1, PageSize: 1, Engine: "sh"}); !errors.Is(err, ErrInvalidFindingListQuery) {
		t.Fatalf("unknown engine accepted: %v", err)
	}
	if _, err := store.ListRuntimeFindingsPage(ctx, FindingListQuery{Page: 1, PageSize: 1, Sort: "drop_table"}); !errors.Is(err, ErrInvalidFindingListQuery) {
		t.Fatalf("invalid sort accepted: %v", err)
	}
}

func TestRuntimeFindingListPageEmptyCountsAreZero(t *testing.T) {
	store, err := OpenRuntime(filepath.Join(t.TempDir(), "platform.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	page, err := store.ListRuntimeFindingsPage(context.Background(), FindingListQuery{Page: 1, PageSize: 20, Severity: "CRITICAL"})
	if err != nil {
		t.Fatal(err)
	}
	if page.Total != 0 || len(page.Items) != 0 || page.Counts != (FindingListCounts{}) {
		t.Fatalf("empty result should have zero counts: %+v", page)
	}
}

func FuzzNormalizeFindingListQuery(f *testing.F) {
	f.Add("CVE-2099", "HIGH", "-last_seen")
	f.Add("%_\\", "", "title")
	f.Fuzz(func(t *testing.T, search, severity, sort string) {
		query, err := NormalizeFindingListQuery(FindingListQuery{Page: 1, PageSize: 20, Search: search, Severity: severity, Sort: sort})
		if err == nil {
			if query.Page < 1 || query.PageSize != 20 {
				t.Fatalf("normalized query escaped bounds: %+v", query)
			}
		}
	})
}
