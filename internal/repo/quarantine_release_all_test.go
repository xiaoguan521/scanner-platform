package repo

import (
	"context"
	"errors"
	"testing"
	"time"

	"scanner-platform/internal/assets"
)

func TestReleaseAllQuarantinesReleasesOnlyThatAssetInOneAudit(t *testing.T) {
	store, actor := localFixture(t)
	ctx := context.Background()
	var assetID, otherID string
	if err := store.db.QueryRowContext(ctx, "SELECT id FROM assets WHERE address=?", "192.0.2.20").Scan(&assetID); err != nil {
		t.Fatal(err)
	}
	registry, err := assets.New(store.db)
	if err != nil {
		t.Fatal(err)
	}
	other, err := registry.Create(ctx, actor, assets.Input{Kind: "host", Address: "192.0.2.21", BusinessGroup: "QA", Owner: "Example", RequestedPorts: []int{80}})
	if err != nil {
		t.Fatal(err)
	}
	otherID = other.ID
	now := time.Now().UTC().Format(time.RFC3339Nano)
	for _, row := range []struct {
		asset string
		port  int
	}{{assetID, 6379}, {assetID, 7777}, {assetID, 8080}, {otherID, 9999}} {
		if _, err := store.db.ExecContext(ctx, `INSERT INTO port_quarantine(asset_id,port,reason,detected_at,status) VALUES(?,?,?,?,'ACTIVE')`, row.asset, row.port, "fixture", now); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.ReleaseAllQuarantines(ctx, assetID, "", "admin"); !errors.Is(err, ErrInvalidTask) {
		t.Fatalf("a release without a reason must be rejected: %v", err)
	}
	released, err := store.ReleaseAllQuarantines(ctx, assetID, "误隔离的真实服务", "admin")
	if err != nil || released != 3 {
		t.Fatalf("expected 3 released ports, got %d %v", released, err)
	}
	var active int
	if err := store.db.QueryRowContext(ctx, `SELECT count(*) FROM port_quarantine WHERE asset_id=? AND status='ACTIVE'`, assetID).Scan(&active); err != nil || active != 0 {
		t.Fatalf("asset still has %d active quarantines (%v)", active, err)
	}
	if err := store.db.QueryRowContext(ctx, `SELECT count(*) FROM port_quarantine WHERE asset_id=? AND status='ACTIVE'`, otherID).Scan(&active); err != nil || active != 1 {
		t.Fatalf("another asset's quarantine must stay active, got %d (%v)", active, err)
	}
	if again, err := store.ReleaseAllQuarantines(ctx, assetID, "重复", "admin"); err != nil || again != 0 {
		t.Fatalf("releasing nothing must be a no-op, got %d %v", again, err)
	}
}
