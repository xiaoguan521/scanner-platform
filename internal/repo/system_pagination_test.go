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
