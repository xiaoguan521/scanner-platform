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

func TestPostgresAssetManagementRepositoryLab(t *testing.T) {
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
	const actor = "lab-postgres-asset-management"
	cleanup := func() {
		_, _ = db.ExecContext(ctx, `DELETE FROM assets WHERE address IN ($1,$2)`, "192.0.2.50", "registry.example.com/pg/import")
		_, _ = db.ExecContext(ctx, "DELETE FROM asset_business_groups WHERE name=$1", "PG Management")
		_, _ = db.ExecContext(ctx, "DELETE FROM asset_import_history WHERE actor=$1", actor)
		_, _ = db.ExecContext(ctx, "DELETE FROM asset_import_previews WHERE actor=$1", actor)
		_, _ = db.ExecContext(ctx, "DELETE FROM audit_logs WHERE actor=$1", actor)
		_, _ = db.ExecContext(ctx, "DELETE FROM users WHERE id=$1", actor)
	}
	cleanup()
	defer cleanup()
	if _, err := db.ExecContext(ctx, `INSERT INTO users(id,username,role,is_active,password_hash)
		VALUES ($1,'pg_asset_management','admin',TRUE,'fixture-only')`, actor); err != nil {
		t.Fatal(err)
	}
	store, err := assets.NewPostgres(db)
	if err != nil {
		t.Fatal(err)
	}
	group, err := store.CreateBusinessGroup(ctx, actor, "PG Management")
	if err != nil || group.Name != "PG Management" || group.AssetCount != 0 {
		t.Fatalf("group=%+v err=%v", group, err)
	}
	if _, err := store.CreateBusinessGroup(ctx, actor, "PG Management"); !errors.Is(err, assets.ErrBusinessGroupExists) {
		t.Fatalf("duplicate group error=%v", err)
	}
	groups, err := store.ListBusinessGroupsPage(ctx, assets.BusinessGroupListQuery{Page: 1, PageSize: 10, Search: "PG Management"})
	if err != nil || groups.Total != 1 || len(groups.Items) != 1 {
		t.Fatalf("groups=%+v err=%v", groups, err)
	}

	data := []byte("kind,address,businessGroup,owner,name\nhost,192.0.2.50,PG Management,fixture-owner,imported host\nimage_repo,registry.example.com/pg/import,PG Management,fixture-owner,imported image\n")
	preview, err := store.PreviewImport(ctx, actor, data)
	if err != nil || preview.Valid != 2 || preview.Invalid != 0 || preview.PreviewID == "" {
		t.Fatalf("preview=%+v err=%v", preview, err)
	}
	result, err := store.ConfirmImport(ctx, actor, preview.PreviewID)
	if err != nil || result.Imported != 2 {
		t.Fatalf("import result=%+v err=%v", result, err)
	}
	if _, err := store.ConfirmImport(ctx, actor, preview.PreviewID); !errors.Is(err, assets.ErrImportUnavailable) {
		t.Fatalf("confirmed preview error=%v, want unavailable", err)
	}
	history, err := store.ListImportHistoryPage(ctx, assets.ImportHistoryListQuery{Page: 1, PageSize: 10, Search: actor})
	if err != nil || history.Total != 1 || len(history.Items) != 1 || history.Items[0].Imported != 2 {
		t.Fatalf("history=%+v err=%v", history, err)
	}
	assetPage, err := store.ListPage(ctx, assets.ListQuery{Page: 1, PageSize: 10, Search: "imported host"})
	if err != nil || assetPage.Total != 1 || len(assetPage.Items) != 1 {
		t.Fatalf("imported asset page=%+v err=%v", assetPage, err)
	}
}
