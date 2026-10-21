//go:build lab

package assets_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"scanner-platform/internal/assets"
	"scanner-platform/internal/repo"
)

func TestPostgresAssetRepositoryLab(t *testing.T) {
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
	const actor = "lab-postgres-asset-user"
	const username = "pgassetuser"
	cleanup := func() {
		_, _ = db.ExecContext(ctx, `DELETE FROM assets WHERE address IN ($1,$2)`, "192.0.2.20", "192.0.2.21")
		_, _ = db.ExecContext(ctx, `DELETE FROM asset_business_groups WHERE name=$1`, "PG Lab")
		_, _ = db.ExecContext(ctx, `DELETE FROM audit_logs WHERE actor=$1`, actor)
		_, _ = db.ExecContext(ctx, `DELETE FROM users WHERE id=$1`, actor)
		_, _ = db.ExecContext(ctx, `DELETE FROM users WHERE username=$1`, username)
	}
	cleanup()
	defer cleanup()
	if _, err := db.ExecContext(ctx, `INSERT INTO users(id,username,role,is_active,password_hash)
		VALUES ($1,$2,'admin',TRUE,'fixture-only')`, actor, username); err != nil {
		t.Fatal(err)
	}
	pinger := func(context.Context, string) (bool, error) { return true, nil }
	store, err := assets.NewPostgresWithPinger(db, pinger)
	if err != nil {
		t.Fatal(err)
	}
	created, err := store.Create(ctx, actor, assets.Input{
		Kind: "host", Address: "192.0.2.20", BusinessGroup: "PG Lab", Owner: "fixture-owner",
		Name: "queue target", RequestedPorts: []int{8080, 22}, SkippedPorts: []int{443},
	})
	if err != nil {
		t.Fatal(err)
	}
	if created.Address != "192.0.2.20" || len(created.RequestedPorts) != 2 || len(created.SkippedPorts) != 1 {
		t.Fatalf("created asset=%+v", created)
	}
	if err := store.RequestPort(ctx, actor, created.ID, 8080); !errors.Is(err, assets.ErrPortRequested) {
		t.Fatalf("duplicate port error=%v, want %v", err, assets.ErrPortRequested)
	}
	if _, err := store.CheckReachability(ctx, actor, created.ID); err != nil {
		t.Fatal(err)
	}
	page, err := store.ListPage(ctx, assets.ListQuery{Page: 1, PageSize: 10, Search: "queue target"})
	if err != nil {
		t.Fatal(err)
	}
	if page.Total != 1 || len(page.Items) != 1 || page.Items[0].ReachabilityStatus != "REACHABLE" {
		t.Fatalf("asset page=%+v", page)
	}
	updated, err := store.Update(ctx, actor, created.ID, assets.Edit{
		Address: "192.0.2.21", BusinessGroup: "PG Lab", Owner: "fixture-owner", Name: "updated target",
		RequestedPorts: []int{22}, SkippedPorts: []int{8443},
	})
	if err != nil {
		t.Fatal(err)
	}
	if updated.Address != "192.0.2.21" || updated.ReachabilityStatus != "UNCHECKED" || len(updated.RequestedPorts) != 1 {
		t.Fatalf("updated asset=%+v", updated)
	}
	if err := store.Delete(ctx, actor, created.ID); err != nil {
		t.Fatal(err)
	}
	page, err = store.ListPage(ctx, assets.ListQuery{Page: 1, PageSize: 10, Search: "updated target"})
	if err != nil || page.Total != 0 {
		t.Fatalf("deleted asset search total=%d err=%v", page.Total, err)
	}
}
