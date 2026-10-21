package repo

import (
	"context"
	"errors"
	"testing"

	"scanner-platform/internal/rules"
)

func TestNodeListPageSearchSortAndValidation(t *testing.T) {
	store, _ := reportTestStore(t)
	ctx := context.Background()
	if err := store.TouchNodeState(ctx, "node-alpha", "worker", "", "", "ONLINE"); err != nil {
		t.Fatal(err)
	}
	if err := store.TouchNodeState(ctx, "node-beta", "updater", "", "", "ONLINE"); err != nil {
		t.Fatal(err)
	}
	page, err := store.ListNodesPage(ctx, NodeListQuery{Page: 1, PageSize: 1, Sort: "id"})
	if err != nil || page.Total != 2 || len(page.Items) != 1 || page.PageSize != 1 || page.Items[0].ID != "node-alpha" {
		t.Fatalf("unexpected node page: %+v err=%v", page, err)
	}
	page, err = store.ListNodesPage(ctx, NodeListQuery{Page: 1, PageSize: 20, Search: "updater"})
	if err != nil || page.Total != 1 || len(page.Items) != 1 || page.Items[0].Kind != "updater" {
		t.Fatalf("filtered node page: %+v err=%v", page, err)
	}
	if _, err := store.ListNodesPage(ctx, NodeListQuery{Page: 1, PageSize: 1, Sort: "drop_table"}); !errors.Is(err, ErrInvalidNodeListQuery) {
		t.Fatalf("invalid node sort accepted: %v", err)
	}
}

func TestNodeListPageIncludesRegisteredLifecycleOnlyNode(t *testing.T) {
	store, _ := reportTestStore(t)
	ctx := context.Background()
	registered, err := store.RegisterNodeLifecycle(ctx, NodeLifecycle{ID: "registered-worker", Kind: "worker", HostID: "scan-host"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if registered.Status != "REGISTERED" {
		t.Fatalf("registered lifecycle=%+v", registered)
	}
	page, err := store.ListNodesPage(ctx, NodeListQuery{Page: 1, PageSize: 20, Search: "registered-worker"})
	if err != nil {
		t.Fatal(err)
	}
	if page.Total != 1 || len(page.Items) != 1 {
		t.Fatalf("registered-only node missing: %+v", page)
	}
	item := page.Items[0]
	if item.ID != "registered-worker" || item.Kind != "worker" || item.HostID != "scan-host" || item.LifecycleStatus != "REGISTERED" || item.Status != "UNKNOWN" {
		t.Fatalf("registered-only node projection=%+v", item)
	}
}

func TestRuleListPageSearchSortAndValidation(t *testing.T) {
	store, _ := reportTestStore(t)
	ctx := context.Background()
	if err := store.SyncRules(ctx, []rules.Bundle{
		{Version: "20261021.01", Channel: "stable", PublishedAt: "2026-10-21T00:00:00Z"},
		{Version: "20261020.01", Channel: "local", PublishedAt: "2026-10-20T00:00:00Z"},
	}); err != nil {
		t.Fatal(err)
	}
	page, err := store.ListRulesPage(ctx, RuleListQuery{Page: 1, PageSize: 1, Sort: "-version"})
	if err != nil || page.Total != 2 || len(page.Items) != 1 || page.PageSize != 1 || page.Items[0].Version != "20261021.01" {
		t.Fatalf("unexpected rule page: %+v err=%v", page, err)
	}
	page, err = store.ListRulesPage(ctx, RuleListQuery{Page: 1, PageSize: 20, Search: "local"})
	if err != nil || page.Total != 1 || len(page.Items) != 1 || page.Items[0].Channel != "local" {
		t.Fatalf("filtered rule page: %+v err=%v", page, err)
	}
	if _, err := store.ListRulesPage(ctx, RuleListQuery{Page: 1, PageSize: 1, Sort: "drop_table"}); !errors.Is(err, ErrInvalidRuleListQuery) {
		t.Fatalf("invalid rule sort accepted: %v", err)
	}
}
