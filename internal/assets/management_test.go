package assets

import (
	"context"
	"errors"
	"testing"
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
