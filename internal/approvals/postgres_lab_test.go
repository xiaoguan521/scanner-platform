//go:build lab

package approvals

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"scanner-platform/internal/repo"
)

func TestPostgresApprovalRepositoryLab(t *testing.T) {
	dsnFile := os.Getenv("POSTGRES_DSN_FILE")
	if dsnFile == "" {
		t.Skip("set POSTGRES_DSN_FILE to an isolated PostgreSQL fixture")
	}
	dsn, err := repo.ReadPostgresDSNFile(filepath.Clean(dsnFile))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	db, err := repo.OpenPostgres(ctx, repo.PostgresConfig{DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := repo.MigratePostgres(ctx, db); err != nil {
		t.Fatal(err)
	}
	const (
		requesterID = "lab-postgres-approval-requester"
		reviewerID  = "lab-postgres-approval-reviewer"
		assetID     = "lab-postgres-approval-asset"
	)
	cleanup := func() {
		_, _ = db.ExecContext(ctx, "DELETE FROM authorized_scopes WHERE asset_id=$1", assetID)
		_, _ = db.ExecContext(ctx, "DELETE FROM assets WHERE id=$1", assetID)
		_, _ = db.ExecContext(ctx, "DELETE FROM audit_logs WHERE actor IN ($1,$2)", requesterID, reviewerID)
		_, _ = db.ExecContext(ctx, "DELETE FROM users WHERE id IN ($1,$2)", requesterID, reviewerID)
	}
	cleanup()
	defer cleanup()
	for _, user := range []struct{ id, name string }{{requesterID, "pg_approval_requester"}, {reviewerID, "pg_approval_reviewer"}} {
		if _, err := db.ExecContext(ctx, `INSERT INTO users(id,username,role,is_active,password_hash)
			VALUES ($1,$2,'admin',TRUE,'fixture-only')`, user.id, user.name); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO assets(id,kind,address,business_group,owner)
		VALUES ($1,'host','192.0.2.40','PG Approval','fixture-owner')`, assetID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO asset_port_requests(asset_id,port)
		VALUES ($1,22),($1,18080)`, assetID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO asset_port_request_authors(asset_id,port,requested_by)
		VALUES ($1,22,$2),($1,18080,$2)`, assetID, requesterID); err != nil {
		t.Fatal(err)
	}

	store, err := NewPostgres(db)
	if err != nil {
		t.Fatal(err)
	}
	expires := time.Now().Add(2 * time.Hour).UTC().Format(time.RFC3339)
	scope, err := store.RequestScope(ctx, requesterID, ScopeInput{
		AssetID:     assetID,
		TimeWindows: []TimeWindow{{Weekdays: []int{1, 2, 3, 4, 5}, Start: "09:00", End: "18:00", TimeZone: "UTC"}},
		ExpiresAt:   expires,
	})
	if err != nil {
		t.Fatal(err)
	}
	if scope.Status != "PENDING" || scope.CIDROrHost != "192.0.2.40" {
		t.Fatalf("requested scope=%+v", scope)
	}
	scope, err = store.ReviewScope(ctx, reviewerID, scope.ID, Decision{Decision: "APPROVE", ApprovalTicket: "PG-SCOPE-1", Note: "fixture approval"})
	if err != nil || scope.Status != "APPROVED" || !scope.IsActive {
		t.Fatalf("reviewed scope=%+v err=%v", scope, err)
	}
	page, err := store.ListScopesPage(ctx, ScopeListQuery{Page: 1, PageSize: 10, Expiry: "expiring"})
	foundScope := false
	for _, item := range page.Items {
		if item.ID == scope.ID && item.Status == "APPROVED" && item.IsActive {
			foundScope = true
		}
	}
	if err != nil || !foundScope {
		t.Fatalf("scope page=%+v err=%v", page, err)
	}
	if _, err := store.ReviewScope(ctx, requesterID, scope.ID, Decision{Decision: "APPROVE", ApprovalTicket: "PG-SCOPE-2"}); !errors.Is(err, ErrConflict) {
		t.Fatalf("second scope review error=%v, want conflict", err)
	}
	renewed, err := store.RenewScopes(ctx, requesterID, ScopeRenewalInput{IDs: []string{scope.ID}, ExpiresAt: time.Now().Add(3 * time.Hour).UTC().Format(time.RFC3339)})
	if err != nil || len(renewed) != 1 || renewed[0].Status != "PENDING" || renewed[0].IsActive {
		t.Fatalf("renewed scope=%+v err=%v", renewed, err)
	}
	if _, err := store.ReviewScope(ctx, reviewerID, scope.ID, Decision{Decision: "APPROVE", ApprovalTicket: "PG-SCOPE-3"}); err != nil {
		t.Fatal(err)
	}

	ports, err := store.ListPortRequestsPage(ctx, PortRequestListQuery{Page: 1, PageSize: 10, Status: "PENDING", Search: "192.0.2.40"})
	if err != nil || ports.Total != 2 || len(ports.Items) != 2 {
		t.Fatalf("port page=%+v err=%v", ports, err)
	}
	approved, err := store.ReviewPort(ctx, reviewerID, assetID, 22, Decision{Decision: "APPROVE", ApprovalTicket: "PG-PORT-1", Note: "fixture port", Kind: "NON_WEB"})
	if err != nil || approved.Status != "APPROVED" || approved.Kind != "NON_WEB" {
		t.Fatalf("approved port=%+v err=%v", approved, err)
	}
	if _, err := store.ReviewPort(ctx, reviewerID, assetID, 18080, Decision{Decision: "REJECT", ApprovalTicket: "PG-PORT-2"}); err != nil {
		t.Fatal(err)
	}
	approvedPage, err := store.ListPortRequestsPage(ctx, PortRequestListQuery{Page: 1, PageSize: 10, Status: "APPROVED"})
	if err != nil || approvedPage.Total != 1 || len(approvedPage.Items) != 1 || approvedPage.Items[0].Port != 22 {
		t.Fatalf("approved ports=%+v err=%v", approvedPage, err)
	}

	if _, err := store.RevokeScope(ctx, reviewerID, scope.ID); err != nil {
		t.Fatal(err)
	}
	if err := store.DeleteScope(ctx, requesterID, scope.ID); err != nil {
		t.Fatal(err)
	}
}
