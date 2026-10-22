package approvals

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"scanner-platform/internal/account"
	"scanner-platform/internal/assets"
)

func TestScopeAndPortPaginationFiltersAndBounds(t *testing.T) {
	ctx := context.Background()
	accounts, err := account.New(filepath.Join(t.TempDir(), "pagination.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer accounts.Close()
	if err := accounts.InitAdmin(ctx, "paginationadmin", "Safe-Sample-Password-12"); err != nil {
		t.Fatal(err)
	}
	admin, _, err := accounts.Authenticate(ctx, "paginationadmin", "Safe-Sample-Password-12")
	if err != nil {
		t.Fatal(err)
	}
	ops, err := accounts.Create(ctx, admin, "paginationops", "Safe-Other-Password-14", "ops_approver")
	if err != nil {
		t.Fatal(err)
	}
	assetStore, err := assets.New(accounts.SQLDB())
	if err != nil {
		t.Fatal(err)
	}
	first, err := assetStore.Create(ctx, admin.ID, assets.Input{Kind: "host", Address: "192.0.2.31", BusinessGroup: "QA", Owner: "Owner", RequestedPorts: []int{22, 8080}})
	if err != nil {
		t.Fatal(err)
	}
	second, err := assetStore.Create(ctx, admin.ID, assets.Input{Kind: "host", Address: "192.0.2.32", BusinessGroup: "QA", Owner: "Owner", RequestedPorts: []int{443}})
	if err != nil {
		t.Fatal(err)
	}
	store, err := New(accounts.SQLDB())
	if err != nil {
		t.Fatal(err)
	}

	request := func(assetID string, expiry time.Time) Scope {
		t.Helper()
		item, err := store.RequestScope(ctx, admin.ID, ScopeInput{
			AssetID:     assetID,
			TimeWindows: []TimeWindow{{Weekdays: []int{1, 2, 3, 4, 5}, Start: "09:00", End: "18:00", TimeZone: "UTC"}},
			ExpiresAt:   expiry.UTC().Format(time.RFC3339),
		})
		if err != nil {
			t.Fatal(err)
		}
		item, err = store.ReviewScope(ctx, ops.ID, item.ID, Decision{Decision: "APPROVE", ApprovalTicket: "SEC-PAGE", Note: "test"})
		if err != nil {
			t.Fatal(err)
		}
		return item
	}
	expiring := request(first.ID, time.Now().Add(2*24*time.Hour))
	expired := request(second.ID, time.Now().Add(3*24*time.Hour))
	if _, err := accounts.SQLDB().ExecContext(ctx, "UPDATE authorized_scopes SET expires_at=? WHERE id=?", time.Now().Add(-time.Hour).UTC().Format(time.RFC3339), expired.ID); err != nil {
		t.Fatal(err)
	}

	all, err := store.ListScopesPage(ctx, ScopeListQuery{Page: 1, PageSize: 1})
	if err != nil || all.Total != 2 || len(all.Items) != 1 || all.ExpiringCount != 1 || all.ExpiredCount != 1 {
		t.Fatalf("all scope page=%+v err=%v", all, err)
	}
	expiringPage, err := store.ListScopesPage(ctx, ScopeListQuery{Page: 1, PageSize: 10, Expiry: "expiring"})
	if err != nil || expiringPage.Total != 1 || len(expiringPage.Items) != 1 || expiringPage.Items[0].ID != expiring.ID {
		t.Fatalf("expiring scope page=%+v err=%v", expiringPage, err)
	}
	expiredPage, err := store.ListScopesPage(ctx, ScopeListQuery{Page: 1, PageSize: 10, Expiry: "expired"})
	if err != nil || expiredPage.Total != 1 || len(expiredPage.Items) != 1 || expiredPage.Items[0].ID != expired.ID {
		t.Fatalf("expired scope page=%+v err=%v", expiredPage, err)
	}
	searchPage, err := store.ListScopesPage(ctx, ScopeListQuery{Page: 1, PageSize: 10, Search: "192.0.2.31"})
	if err != nil || searchPage.Total != 1 || searchPage.Items[0].ID != expiring.ID {
		t.Fatalf("scope address search page=%+v err=%v", searchPage, err)
	}
	searchPage, err = store.ListScopesPage(ctx, ScopeListQuery{Page: 1, PageSize: 10, Search: second.ID, Expiry: "expired"})
	if err != nil || searchPage.Total != 1 || searchPage.Items[0].ID != expired.ID {
		t.Fatalf("scope asset id search with expiry page=%+v err=%v", searchPage, err)
	}
	searchPage, err = store.ListScopesPage(ctx, ScopeListQuery{Page: 1, PageSize: 10, Search: "192.0.2.31", Expiry: "expired"})
	if err != nil || searchPage.Total != 0 {
		t.Fatalf("search and expiry must both apply page=%+v err=%v", searchPage, err)
	}
	searchPage, err = store.ListScopesPage(ctx, ScopeListQuery{Page: 1, PageSize: 10, Search: "%"})
	if err != nil || searchPage.Total != 0 {
		t.Fatalf("LIKE wildcards must be escaped page=%+v err=%v", searchPage, err)
	}
	if where, args := withScopeSearch(" WHERE status='APPROVED' AND expires_at <= $1", []any{"now"}, "x", func(n int) string { return fmt.Sprintf("$%d", n) }); len(args) != 3 || !strings.Contains(where, "LIKE $2") || !strings.Contains(where, "LIKE $3") {
		t.Fatalf("postgres search placeholders where=%q args=%v", where, args)
	}
	if _, err := store.ListScopesPage(ctx, ScopeListQuery{Search: string([]byte{'a', 0})}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("NUL search accepted: %v", err)
	}
	if _, err := store.ListScopesPage(ctx, ScopeListQuery{PageSize: 101}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid scope page size error=%v", err)
	}
	if _, err := store.ListScopesPage(ctx, ScopeListQuery{Expiry: "unknown"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid scope expiry error=%v", err)
	}

	portPage, err := store.ListPortRequestsPage(ctx, PortRequestListQuery{Page: 1, PageSize: 1, Status: "PENDING", Search: "192.0.2.31"})
	if err != nil || portPage.Total != 2 || len(portPage.Items) != 1 || portPage.Items[0].Address != "192.0.2.31" {
		t.Fatalf("pending port page=%+v err=%v", portPage, err)
	}
	if _, err := store.ReviewPort(ctx, ops.ID, first.ID, 22, Decision{Decision: "APPROVE", ApprovalTicket: "SEC-PORT", Note: "test", Kind: "NON_WEB"}); err != nil {
		t.Fatal(err)
	}
	approved, err := store.ListPortRequestsPage(ctx, PortRequestListQuery{Page: 1, PageSize: 10, Status: "APPROVED"})
	if err != nil || approved.Total != 1 || len(approved.Items) != 1 || approved.Items[0].Port != 22 {
		t.Fatalf("approved port page=%+v err=%v", approved, err)
	}
	if _, err := store.ListPortRequestsPage(ctx, PortRequestListQuery{Search: "%"}); err != nil {
		t.Fatalf("escaped port search error=%v", err)
	}
	if _, err := store.ListPortRequestsPage(ctx, PortRequestListQuery{Status: "UNKNOWN"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid port status error=%v", err)
	}
}
