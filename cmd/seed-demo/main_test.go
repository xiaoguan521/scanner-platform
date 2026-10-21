package main

import (
	"context"
	"io"
	"path/filepath"
	"testing"

	"scanner-platform/internal/account"
	"scanner-platform/internal/assets"
	"scanner-platform/internal/repo"
)

func TestSeedDemoIsIdempotentAndNeverNeedsNetwork(t *testing.T) {
	path := filepath.Join(t.TempDir(), "platform.sqlite")
	ctx := context.Background()
	if err := seedDemo(ctx, path, io.Discard); err != nil {
		t.Fatal(err)
	}
	if err := seedDemo(ctx, path, io.Discard); err != nil {
		t.Fatal(err)
	}
	accounts, err := account.New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer accounts.Close()
	assetStore, err := assets.New(accounts.SQLDB())
	if err != nil {
		t.Fatal(err)
	}
	items, err := assetStore.List(ctx)
	if err != nil || len(items) != 1 || items[0].Address != demoHost {
		t.Fatalf("seeded assets: %+v, %v", items, err)
	}
	runtime, err := repo.NewRuntime(accounts.SQLDB())
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	tasks, err := runtime.ListRuntimeTasks(ctx)
	if err != nil || len(tasks) != 1 || tasks[0].ID != "framework-demo" || tasks[0].Status != "COMPLETED" {
		t.Fatalf("seeded tasks: %+v, %v", tasks, err)
	}
	findings, err := runtime.ListRuntimeFindings(ctx)
	if err != nil || len(findings) != 1 || !findings[0].Synthetic {
		t.Fatalf("seeded findings: %+v, %v", findings, err)
	}
}
