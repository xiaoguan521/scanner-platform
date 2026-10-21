//go:build lab

package repo

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"scanner-platform/internal/findings"
	"scanner-platform/internal/portprobe"
	"scanner-platform/internal/rules"
	"scanner-platform/internal/scanplans"
)

func TestPostgresProductCatalogRoundTrip(t *testing.T) {
	dsnFile := os.Getenv("POSTGRES_DSN_FILE")
	if dsnFile == "" {
		t.Skip("set POSTGRES_DSN_FILE to an isolated PostgreSQL fixture")
	}
	ctx := context.Background()
	dsn, err := ReadPostgresDSNFile(filepath.Clean(dsnFile))
	if err != nil {
		t.Fatal(err)
	}
	db, err := OpenPostgres(ctx, PostgresConfig{DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := MigratePostgres(ctx, db); err != nil {
		t.Fatal(err)
	}

	const (
		actor       = "lab-pg-product-admin"
		ruleID      = "lab-pg-product-rule"
		planID      = "lab-pg-product-plan"
		knowledgeID = "LAB-PG-PRODUCT-KNOWLEDGE"
	)
	cleanup := func() {
		_, _ = db.ExecContext(ctx, `DELETE FROM audit_logs WHERE actor=$1`, actor)
		_, _ = db.ExecContext(ctx, `DELETE FROM custom_rules WHERE id=$1`, ruleID)
		_, _ = db.ExecContext(ctx, `DELETE FROM scan_plans WHERE id=$1`, planID)
		_, _ = db.ExecContext(ctx, `DELETE FROM vulnerability_knowledge WHERE id=$1`, knowledgeID)
		_, _ = db.ExecContext(ctx, `DELETE FROM product_settings WHERE id IN ('system-settings','scan-policy')`)
	}
	cleanup()
	defer cleanup()

	store, err := NewPostgresRuntime(db)
	if err != nil {
		t.Fatal(err)
	}

	settings, err := store.GetSystemSettings(ctx)
	if err != nil || settings.SessionDurationMinutes != 480 || settings.TimeZone != "Asia/Shanghai" {
		t.Fatalf("default system settings=%+v err=%v", settings, err)
	}
	if _, err := store.SaveSystemSettings(ctx, SystemSettings{TimeZone: "UTC", SessionDurationMinutes: 90}, actor); err != nil {
		t.Fatal(err)
	}
	settings, err = store.GetSystemSettings(ctx)
	if err != nil || settings.TimeZone != "UTC" || settings.SessionDurationMinutes != 90 {
		t.Fatalf("saved system settings=%+v err=%v", settings, err)
	}
	if _, err := store.SaveSystemSettings(ctx, SystemSettings{TimeZone: "Mars/Phobos", SessionDurationMinutes: 90}, actor); !errors.Is(err, ErrInvalidTask) {
		t.Fatalf("invalid system settings err=%v", err)
	}

	policy, err := store.GetScanPolicy(ctx)
	if err != nil || len(policy.CommonPorts) == 0 {
		t.Fatalf("default scan policy=%+v err=%v", policy, err)
	}
	policy.CommonPorts = []int{18080, 22}
	policy.Exclusions = []portprobe.Range{{Start: 443, End: 443}}
	policy.DiscoveryAttempts = 2
	policy.QuarantineThreshold = 3
	policy.FixedThreshold = 2
	if _, err := store.SaveScanPolicy(ctx, policy, actor); err != nil {
		t.Fatal(err)
	}
	policy, err = store.GetScanPolicy(ctx)
	if err != nil || len(policy.CommonPorts) != 2 || policy.CommonPorts[0] != 22 || policy.FixedThreshold != 2 {
		t.Fatalf("saved scan policy=%+v err=%v", policy, err)
	}

	rule, err := store.SaveCustomRule(ctx, actor, rules.CustomRule{
		ID: ruleID, Name: "fixture response marker", Severity: "low", Description: "fixture-only read-only check",
		MatchType: "word", Part: "body", Values: []string{"fixture-marker"}, Enabled: true,
	}, true)
	if err != nil || rule.Template == "" {
		t.Fatalf("saved custom rule=%+v err=%v", rule, err)
	}
	items, err := store.ListCustomRules(ctx)
	if err != nil || len(items) != 1 || items[0].ID != ruleID {
		t.Fatalf("custom rules=%+v err=%v", items, err)
	}
	page, err := store.ListCustomRulesPage(ctx, CustomRuleListQuery{Page: 1, PageSize: 10, Search: "fixture", Severity: "low", Enabled: "true"})
	if err != nil || page.Total != 1 || len(page.Items) != 1 {
		t.Fatalf("custom rule page=%+v err=%v", page, err)
	}
	if _, err := store.ListCustomRulesPage(ctx, CustomRuleListQuery{Enabled: "invalid"}); !errors.Is(err, ErrInvalidCustomRuleListQuery) {
		t.Fatalf("invalid custom rule query err=%v", err)
	}

	plan, err := store.SaveScanPlan(ctx, actor, scanplans.Input{
		Title: "fixture plan", Summary: "safe fixture plan", Detail: "read-only fixture plan",
		Defaults: scanplans.Defaults{PortPreset: "common", Intensity: "gentle", CustomRuleIDs: []string{ruleID}},
	}, planID, false)
	if err != nil {
		t.Fatal(err)
	}
	if plan.ID == planID {
		t.Fatalf("create path unexpectedly honored supplied id: %+v", plan)
	}
	createdPlanID := plan.ID
	defer func() { _, _ = db.ExecContext(ctx, `DELETE FROM scan_plans WHERE id=$1`, createdPlanID) }()
	plans, err := store.ListScanPlans(ctx)
	if err != nil || len(plans) < 3 {
		t.Fatalf("scan plans=%+v err=%v", plans, err)
	}
	if _, err := store.SaveScanPlan(ctx, actor, scanplans.Input{
		Title: "fixture update", Summary: "safe fixture update", Detail: "read-only fixture update",
		Defaults: scanplans.Defaults{PortPreset: "common", Intensity: "gentle", CustomRuleIDs: []string{ruleID}},
	}, createdPlanID, true); err != nil {
		t.Fatal(err)
	}
	if err := store.DeleteScanPlan(ctx, createdPlanID, actor); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SaveScanPlan(ctx, actor, scanplans.Input{
		Title: "invalid fixture", Summary: "safe fixture", Detail: "read-only fixture",
		Defaults: scanplans.Defaults{PortPreset: "common", Intensity: "gentle", CustomRuleIDs: []string{"missing-rule"}},
	}, planID, false); !errors.Is(err, ErrInvalidScanPlan) {
		t.Fatalf("missing custom rule err=%v", err)
	}

	knowledge := findings.KnowledgeEntry{
		ID: knowledgeID, Identifiers: map[string][]string{"CVE": {"CVE-2099-0001"}},
		Title: "fixture vulnerability", Description: "fixture-only knowledge", Impact: "fixture impact", Solution: "fixture fix",
		Category: "component", Component: "fixture-component", AffectedRanges: []findings.VersionRange{{Introduced: "1.0", Fixed: "2.0"}},
		Source: "fixture-source", Language: "original",
	}
	if _, err := store.SaveKnowledge(ctx, knowledge, actor); err != nil {
		t.Fatal(err)
	}
	knowledgePage, err := store.ListKnowledgePage(ctx, KnowledgeListQuery{Page: 1, PageSize: 10, Search: "fixture vulnerability"})
	if err != nil || knowledgePage.Total != 1 || len(knowledgePage.Items) != 1 {
		t.Fatalf("knowledge page=%+v err=%v", knowledgePage, err)
	}
	if err := store.ImportKnowledge(ctx, []findings.KnowledgeEntry{knowledge}, actor); err != nil {
		t.Fatal(err)
	}
	if err := store.DeleteKnowledge(ctx, knowledgeID, actor); err != nil {
		t.Fatal(err)
	}

	logs, total, err := store.ListAuditLogs(ctx, AuditLogQuery{Actor: actor, Limit: 100})
	if err != nil || total < 6 || len(logs) < 6 {
		t.Fatalf("audit logs total=%d logs=%+v err=%v", total, logs, err)
	}
	for _, item := range logs {
		if item.Actor != actor || item.CreatedAt == "" {
			t.Fatalf("unsafe audit projection=%+v", item)
		}
	}
}
