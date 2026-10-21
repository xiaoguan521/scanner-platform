package repo

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"scanner-platform/internal/scanplans"
)

func TestScanPlanCatalogAndCustomLifecycle(t *testing.T) {
	store, err := OpenRuntime(filepath.Join(t.TempDir(), "scan-plans.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()

	items, err := store.ListScanPlans(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 || items[0].ID != "quick" || items[1].ID != "standard" {
		t.Fatalf("unexpected initial catalog: %+v", items)
	}
	created, err := store.SaveScanPlan(ctx, "user-1", scanplans.Input{
		Title: "SSH 只读检查", Summary: "常见端口和 SSH", Detail: "只对明确授权的实验主机执行。",
		Defaults: scanplans.Defaults{PortPreset: "custom", Intensity: "gentle", PortRanges: "22,18080"}, SourceID: "quick",
	}, "", false)
	if err != nil {
		t.Fatal(err)
	}
	if created.Kind != "CUSTOM" || created.ReadOnly || created.CreatedBy != "user-1" || created.ID == "quick" {
		t.Fatalf("unexpected custom plan: %+v", created)
	}
	updated, err := store.SaveScanPlan(ctx, "user-2", scanplans.Input{
		Title: "SSH 与 Web 只读检查", Summary: "更新后的方案", Detail: "仍只处理已授权范围。",
		Defaults: scanplans.Defaults{PortPreset: "common-and-custom", Intensity: "standard", PortRanges: "18080"}, SourceID: "quick",
	}, created.ID, true)
	if err != nil {
		t.Fatal(err)
	}
	if updated.ID != created.ID || updated.Title != "SSH 与 Web 只读检查" || updated.CreatedBy != created.CreatedBy {
		t.Fatalf("unexpected update: %+v", updated)
	}
	items, err = store.ListScanPlans(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 3 {
		t.Fatalf("custom plan did not remain in catalog: %+v", items)
	}
	foundCustom, foundQuick := false, false
	for _, item := range items {
		foundCustom = foundCustom || item.ID == created.ID
		foundQuick = foundQuick || item.ID == "quick"
	}
	if !foundCustom || !foundQuick {
		t.Fatalf("custom plan or preset missing from catalog: %+v", items)
	}
	if err := store.DeleteScanPlan(ctx, "quick", "user-1"); !errors.Is(err, ErrScanPlanConflict) {
		t.Fatalf("deleting preset error=%v, want conflict", err)
	}
	if err := store.DeleteScanPlan(ctx, created.ID, "user-1"); err != nil {
		t.Fatal(err)
	}
	items, err = store.ListScanPlans(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 {
		t.Fatalf("deleted custom plan still listed: %+v", items)
	}
}

func TestScanPlanRejectsMissingCustomRule(t *testing.T) {
	store, err := OpenRuntime(filepath.Join(t.TempDir(), "scan-plans.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	_, err = store.SaveScanPlan(context.Background(), "user-1", scanplans.Input{
		Title: "方案", Summary: "摘要", Detail: "说明",
		Defaults: scanplans.Defaults{PortPreset: "common", Intensity: "gentle", CustomRuleIDs: []string{"missing"}},
	}, "", false)
	if !errors.Is(err, ErrInvalidScanPlan) {
		t.Fatalf("error=%v, want invalid scan plan", err)
	}
}
