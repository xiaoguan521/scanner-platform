package approvals

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"scanner-platform/internal/account"
	"scanner-platform/internal/assets"
)

func TestRenewScopesResetsApprovalAtomically(t *testing.T) {
	ctx := context.Background()
	accounts, err := account.New(filepath.Join(t.TempDir(), "renewal.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer accounts.Close()
	if err := accounts.InitAdmin(ctx, "renewal-admin", "Safe-Sample-Password-12"); err != nil {
		t.Fatal(err)
	}
	admin, _, err := accounts.Authenticate(ctx, "renewal-admin", "Safe-Sample-Password-12")
	if err != nil {
		t.Fatal(err)
	}
	reviewer, err := accounts.Create(ctx, admin, "renewal-reviewer", "Safe-Other-Password-14", "ops_approver")
	if err != nil {
		t.Fatal(err)
	}
	assetStore, err := assets.New(accounts.SQLDB())
	if err != nil {
		t.Fatal(err)
	}
	asset, err := assetStore.Create(ctx, admin.ID, assets.Input{Kind: "host", Address: "192.0.2.81", BusinessGroup: "QA", Owner: "Owner"})
	if err != nil {
		t.Fatal(err)
	}
	store, err := New(accounts.SQLDB())
	if err != nil {
		t.Fatal(err)
	}
	request := func() Scope {
		t.Helper()
		item, err := store.RequestScope(ctx, admin.ID, ScopeInput{AssetID: asset.ID, TimeWindows: []TimeWindow{{Weekdays: []int{1}, Start: "09:00", End: "18:00", TimeZone: "UTC"}}, ExpiresAt: time.Now().Add(2 * time.Hour).UTC().Format(time.RFC3339)})
		if err != nil {
			t.Fatal(err)
		}
		item, err = store.ReviewScope(ctx, reviewer.ID, item.ID, Decision{Decision: "APPROVE", ApprovalTicket: "RENEW-1"})
		if err != nil {
			t.Fatal(err)
		}
		return item
	}
	first := request()
	second := request()
	newExpiry := time.Now().Add(4 * time.Hour).UTC().Format(time.RFC3339)
	items, err := store.RenewScopes(ctx, admin.ID, ScopeRenewalInput{IDs: []string{first.ID, second.ID}, ExpiresAt: newExpiry})
	if err != nil || len(items) != 2 {
		t.Fatalf("renewal items=%+v err=%v", items, err)
	}
	for _, item := range items {
		if item.Status != "PENDING" || item.IsActive || item.ApprovalTicket != "" {
			t.Fatalf("renewed scope retained approval: %+v", item)
		}
	}
	if _, err := store.ReviewScope(ctx, reviewer.ID, first.ID, Decision{Decision: "APPROVE", ApprovalTicket: "RENEW-2"}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.RenewScopes(ctx, admin.ID, ScopeRenewalInput{IDs: []string{first.ID, second.ID}, ExpiresAt: newExpiry}); !errors.Is(err, ErrConflict) {
		t.Fatalf("mixed approved/pending renewal error=%v, want conflict", err)
	}
	unchanged, err := store.ListScopes(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range unchanged {
		if item.ID == first.ID && item.Status != "APPROVED" {
			t.Fatalf("atomic renewal changed first scope after conflict: %+v", item)
		}
	}
}

func TestNormalizeScopeRenewalInputRejectsDuplicateAndInvalidExpiry(t *testing.T) {
	for name, input := range map[string]ScopeRenewalInput{
		"duplicate": {IDs: []string{"scope-a", "scope-a"}, ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339)},
		"past":      {IDs: []string{"scope-a"}, ExpiresAt: time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)},
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := normalizeScopeRenewalInput(input); !errors.Is(err, ErrInvalid) {
				t.Fatalf("normalize error=%v, want %v", err, ErrInvalid)
			}
		})
	}
}
