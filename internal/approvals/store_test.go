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

func TestScopeEditResetsApprovalAndRevocationIsAudited(t *testing.T) {
	ctx := context.Background()
	accounts, err := account.New(filepath.Join(t.TempDir(), "approvals.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer accounts.Close()
	if err := accounts.InitAdmin(ctx, "testadmin", "Safe-Sample-Password-12"); err != nil {
		t.Fatal(err)
	}
	admin, _, err := accounts.Authenticate(ctx, "testadmin", "Safe-Sample-Password-12")
	if err != nil {
		t.Fatal(err)
	}
	ops, err := accounts.Create(ctx, admin, "opsreviewer", "Safe-Other-Password-14", "ops_approver")
	if err != nil {
		t.Fatal(err)
	}
	assetStore, err := assets.New(accounts.SQLDB())
	if err != nil {
		t.Fatal(err)
	}
	asset, err := assetStore.Create(ctx, admin.ID, assets.Input{Kind: "host", Address: "192.0.2.20", BusinessGroup: "QA", Owner: "Owner"})
	if err != nil {
		t.Fatal(err)
	}
	store, err := New(accounts.SQLDB())
	if err != nil {
		t.Fatal(err)
	}
	request := ScopeInput{
		AssetID:     asset.ID,
		TimeWindows: []TimeWindow{{Weekdays: []int{1, 2, 3, 4, 5}, Start: "09:00", End: "18:00", TimeZone: "Asia/Shanghai"}},
		ExpiresAt:   time.Now().Add(2 * time.Hour).UTC().Format(time.RFC3339),
	}
	scope, err := store.RequestScope(ctx, admin.ID, request)
	if err != nil {
		t.Fatal(err)
	}
	scope, err = store.ReviewScope(ctx, ops.ID, scope.ID, Decision{Decision: "APPROVE", ApprovalTicket: "SEC-100", Note: "approved"})
	if err != nil || scope.Status != "APPROVED" {
		t.Fatalf("approve scope=%+v err=%v", scope, err)
	}
	if err := assetStore.Delete(ctx, admin.ID, asset.ID); !errors.Is(err, assets.ErrInUse) {
		t.Fatalf("asset with authorization record deleted: %v", err)
	}
	if _, err := assetStore.Update(ctx, admin.ID, asset.ID, assets.Edit{Address: "192.0.2.21", BusinessGroup: "QA", Owner: "Owner"}); err != nil {
		t.Fatalf("change registered host IP: %v", err)
	}
	listed, err := store.ListScopes(ctx)
	if err != nil || len(listed) != 1 || listed[0].Status != "REVOKED" || listed[0].IsActive {
		t.Fatalf("IP change retained old authorization: %+v err=%v", listed, err)
	}
	if _, err := store.UpdateScope(ctx, admin.ID, scope.ID, request); !errors.Is(err, ErrConflict) {
		t.Fatalf("revoked scope was editable: %v", err)
	}
	if err := store.DeleteScope(ctx, admin.ID, scope.ID); err != nil {
		t.Fatalf("delete revoked authorization: %v", err)
	}
	request.ExpiresAt = time.Now().Add(2 * time.Hour).UTC().Format(time.RFC3339)
	scope, err = store.RequestScope(ctx, admin.ID, request)
	if err != nil {
		t.Fatal(err)
	}
	scope, err = store.ReviewScope(ctx, ops.ID, scope.ID, Decision{Decision: "APPROVE", ApprovalTicket: "SEC-100A", Note: "approved after IP change"})
	if err != nil {
		t.Fatal(err)
	}
	request.TimeWindows[0].End = "17:00"
	request.ExpiresAt = time.Now().Add(3 * time.Hour).UTC().Format(time.RFC3339)
	scope, err = store.UpdateScope(ctx, admin.ID, scope.ID, request)
	if err != nil || scope.Status != "PENDING" || scope.ApprovedBy != "" || scope.ApprovalTicket != "" || scope.TimeWindows[0].End != "17:00" {
		t.Fatalf("edited scope retained stale approval: %+v err=%v", scope, err)
	}
	scope, err = store.ReviewScope(ctx, ops.ID, scope.ID, Decision{Decision: "APPROVE", ApprovalTicket: "SEC-101", Note: "reapproved"})
	if err != nil {
		t.Fatal(err)
	}
	scope, err = store.RevokeScope(ctx, admin.ID, scope.ID)
	if err != nil || scope.Status != "REVOKED" || scope.IsActive {
		t.Fatalf("revoke scope=%+v err=%v", scope, err)
	}
	if err := store.DeleteScope(ctx, admin.ID, scope.ID); err != nil {
		t.Fatal(err)
	}
	if err := assetStore.Delete(ctx, admin.ID, asset.ID); err != nil {
		t.Fatalf("delete asset after removing scope: %v", err)
	}
	list, err := store.ListScopes(ctx)
	if err != nil || len(list) != 0 {
		t.Fatalf("deleted scope remains: %+v err=%v", list, err)
	}
}
