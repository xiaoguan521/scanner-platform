package repo

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"scanner-platform/internal/rules"
)

func TestRuleJobListPageFiltersSortsAndRejectsInvalidInput(t *testing.T) {
	store, _ := reportTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	for _, item := range []struct {
		id, kind, version, message, status string
	}{
		{"job-import", "IMPORT", "", "导入规则", "COMPLETED"},
		{"job-fetch", "FETCH", "20261021.01", "下载稳定包", "FAILED"},
	} {
		data, _ := json.Marshal(rules.Job{ID: item.id, Kind: item.kind, Version: item.version, Message: item.message, Status: item.status, CreatedAt: now})
		if _, err := store.db.ExecContext(ctx, "INSERT INTO rule_jobs(id,status,data,bundle,created_at) VALUES(?,?,?,?,?)", item.id, item.status, string(data), nil, now); err != nil {
			t.Fatal(err)
		}
	}
	page, err := store.ListRuleJobsPage(ctx, RuleJobListQuery{Page: 1, PageSize: 1, Sort: "-created_at"})
	if err != nil || page.Total != 2 || len(page.Items) != 1 || page.PageSize != 1 {
		t.Fatalf("unexpected rule job page: %+v err=%v", page, err)
	}
	page, err = store.ListRuleJobsPage(ctx, RuleJobListQuery{Page: 1, PageSize: 20, Status: "FAILED", Kind: "FETCH", Search: "稳定"})
	if err != nil || page.Total != 1 || len(page.Items) != 1 || page.Items[0].ID != "job-fetch" {
		t.Fatalf("filtered rule job page: %+v err=%v", page, err)
	}
	if _, err := store.ListRuleJobsPage(ctx, RuleJobListQuery{Page: 1, PageSize: 1, Sort: "drop_table"}); !errors.Is(err, ErrInvalidRuleJobListQuery) {
		t.Fatalf("invalid rule job sort accepted: %v", err)
	}
}

func TestCustomRuleListPageFiltersSortsAndRejectsInvalidInput(t *testing.T) {
	store, _ := reportTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	for _, item := range []struct {
		id, name, severity string
		enabled            bool
	}{
		{"legacy-console", "Legacy console", "medium", true},
		{"debug-header", "Debug header", "high", false},
	} {
		data, _ := json.Marshal(rules.CustomRule{ID: item.id, Name: item.name, Severity: item.severity, MatchType: "word", Part: "body", Values: []string{"marker"}, Enabled: item.enabled})
		if _, err := store.db.ExecContext(ctx, "INSERT INTO custom_rules(id,data,enabled,created_at,updated_at) VALUES(?,?,?,?,?)", item.id, string(data), item.enabled, now, now); err != nil {
			t.Fatal(err)
		}
	}
	page, err := store.ListCustomRulesPage(ctx, CustomRuleListQuery{Page: 1, PageSize: 1, Sort: "name"})
	if err != nil || page.Total != 2 || len(page.Items) != 1 || page.PageSize != 1 {
		t.Fatalf("unexpected custom rule page: %+v err=%v", page, err)
	}
	page, err = store.ListCustomRulesPage(ctx, CustomRuleListQuery{Page: 1, PageSize: 20, Severity: "high", Enabled: "false", Search: "debug"})
	if err != nil || page.Total != 1 || len(page.Items) != 1 || page.Items[0].ID != "debug-header" {
		t.Fatalf("filtered custom rule page: %+v err=%v", page, err)
	}
	if _, err := store.ListCustomRulesPage(ctx, CustomRuleListQuery{Page: 1, PageSize: 1, Enabled: "maybe"}); !errors.Is(err, ErrInvalidCustomRuleListQuery) {
		t.Fatalf("invalid custom rule enabled filter accepted: %v", err)
	}
}
