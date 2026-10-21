package assets

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestBusinessGroupsTrackAssetsAndRemainSafe(t *testing.T) {
	store, accounts, actor := importFixture(t)
	ctx := context.Background()
	groups, err := store.ListBusinessGroups(ctx)
	if err != nil || len(groups) != 0 {
		t.Fatalf("initial groups=%+v err=%v", groups, err)
	}
	created, err := store.CreateBusinessGroup(ctx, actor, "平台服务")
	if err != nil || created.Name != "平台服务" || created.AssetCount != 0 {
		t.Fatalf("create group=%+v err=%v", created, err)
	}
	if _, err := store.CreateBusinessGroup(ctx, actor, "平台服务"); !errors.Is(err, ErrBusinessGroupExists) {
		t.Fatalf("duplicate group err=%v", err)
	}
	if _, err := store.CreateBusinessGroup(ctx, actor, "bad\x00name"); !errors.Is(err, ErrBusinessGroupInvalid) {
		t.Fatalf("control group err=%v", err)
	}
	if _, err := store.Create(ctx, actor, Input{Kind: "host", Address: "192.0.2.30", BusinessGroup: "平台服务", Owner: "负责人"}); err != nil {
		t.Fatal(err)
	}
	groups, err = store.ListBusinessGroups(ctx)
	if err != nil || len(groups) != 1 || groups[0].AssetCount != 1 {
		t.Fatalf("counted groups=%+v err=%v", groups, err)
	}
	if _, err := store.Create(ctx, actor, Input{Kind: "host", Address: "192.0.2.31", BusinessGroup: "新业务", Owner: "负责人"}); err != nil {
		t.Fatal(err)
	}
	groups, err = store.ListBusinessGroups(ctx)
	if err != nil || len(groups) != 2 {
		t.Fatalf("automatic group=%+v err=%v", groups, err)
	}
	_ = accounts
}

func TestAssetImportHistoryContainsOnlySummary(t *testing.T) {
	store, _, actor := importFixture(t)
	ctx := context.Background()
	preview, err := store.PreviewImport(ctx, actor, []byte(ImportTemplate))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.ConfirmImport(ctx, actor, preview.PreviewID); err != nil {
		t.Fatal(err)
	}
	history, err := store.ListImportHistory(ctx)
	if err != nil || len(history) != 1 {
		t.Fatalf("history=%+v err=%v", history, err)
	}
	if history[0].Actor != actor || history[0].Imported != 2 || history[0].Total != 2 || history[0].ID == "" || history[0].CreatedAt == "" {
		t.Fatalf("history summary=%+v", history[0])
	}
	for _, field := range []string{history[0].Actor, history[0].ID, history[0].CreatedAt} {
		if field == "192.0.2.10" || field == "registry.example.com/team/image" {
			t.Fatalf("history leaked raw import data: %q", field)
		}
	}
}

func TestManagementListPagesBoundResultsAndEscapeSearch(t *testing.T) {
	store, accounts, actor := importFixture(t)
	ctx := context.Background()
	for _, name := range []string{"平台服务", "平台_legacy", "其他服务"} {
		if _, err := store.CreateBusinessGroup(ctx, actor, name); err != nil {
			t.Fatal(err)
		}
	}
	groups, ok := any(store).(BusinessGroupPageRepository)
	if !ok {
		t.Fatal("store does not implement business group paging")
	}
	page, err := groups.ListBusinessGroupsPage(ctx, BusinessGroupListQuery{Page: 1, PageSize: 1, Search: "平台_"})
	if err != nil || page.Total != 1 || len(page.Items) != 1 || page.Items[0].Name != "平台_legacy" {
		t.Fatalf("group page=%+v err=%v", page, err)
	}
	if _, err := groups.ListBusinessGroupsPage(ctx, BusinessGroupListQuery{Page: 1, PageSize: 101}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid group page size err=%v", err)
	}

	for i := 0; i < 3; i++ {
		if _, err := store.PreviewImport(ctx, actor, []byte(ImportTemplate)); err != nil {
			t.Fatal(err)
		}
		// Preview IDs are user-bound and the fixture replaces a pending preview;
		// create history rows directly to exercise the list projection.
		if _, err := store.db.ExecContext(ctx, `INSERT INTO asset_import_history(id,actor,imported,total,created_at) VALUES(?,?,?,?,?)`, "history-page-"+string(rune('0'+i)), actor, 1, 1, time.Now().UTC().Add(time.Duration(i)*time.Second).Format(time.RFC3339Nano)); err != nil {
			t.Fatal(err)
		}
	}
	history, ok := any(store).(ImportHistoryPageRepository)
	if !ok {
		t.Fatal("store does not implement import history paging")
	}
	historyPage, err := history.ListImportHistoryPage(ctx, ImportHistoryListQuery{Page: 2, PageSize: 2, Search: actor})
	if err != nil || historyPage.Total != 3 || len(historyPage.Items) != 1 || historyPage.Page != 2 {
		t.Fatalf("history page=%+v err=%v", historyPage, err)
	}
	_ = accounts
}
