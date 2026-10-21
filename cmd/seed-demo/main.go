// Command seed-demo writes a small, safe demonstration dataset into the local
// Server SQLite database. It never connects to a target or creates a scan
// authorization; all target data uses the documentation-only address range.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"scanner-platform/internal/account"
	"scanner-platform/internal/assets"
	"scanner-platform/internal/repo"
	"scanner-platform/internal/taskflow"
)

const demoHost = "192.0.2.10"

func seedDemo(ctx context.Context, dbPath string, out io.Writer) error {
	if dbPath == "" {
		return fmt.Errorf("database path is required")
	}
	abs, err := filepath.Abs(dbPath)
	if err != nil {
		return fmt.Errorf("resolve database path: %w", err)
	}
	accounts, err := account.New(abs)
	if err != nil {
		return fmt.Errorf("open account database: %w", err)
	}
	defer accounts.Close()
	assetStore, err := assets.New(accounts.SQLDB())
	if err != nil {
		return fmt.Errorf("initialize asset store: %w", err)
	}
	runtime, err := repo.NewRuntime(accounts.SQLDB())
	if err != nil {
		return fmt.Errorf("initialize runtime store: %w", err)
	}
	defer runtime.Close()

	items, err := assetStore.List(ctx)
	if err != nil {
		return fmt.Errorf("list assets: %w", err)
	}
	assetID := ""
	for _, item := range items {
		if item.Kind == "host" && item.Address == demoHost {
			assetID = item.ID
			break
		}
	}
	if assetID == "" {
		item, createErr := assetStore.Create(ctx, "seed-demo", assets.Input{
			Name:          "演示主机",
			Kind:          "host",
			Address:       demoHost,
			BusinessGroup: "示例业务组",
			Owner:         "示例负责人",
			OSName:        "Example Linux",
			OSFamily:      "linux",
			DeviceType:    "服务器",
		})
		if createErr != nil {
			return fmt.Errorf("create demo asset: %w", createErr)
		}
		assetID = item.ID
	}

	tasks, err := runtime.ListRuntimeTasks(ctx)
	if err != nil {
		return fmt.Errorf("list tasks: %w", err)
	}
	var demoTask *taskflow.Task
	for i := range tasks {
		if tasks[i].ID == "framework-demo" {
			demoTask = &tasks[i]
			break
		}
	}
	if demoTask == nil {
		if err := runtime.SeedSyntheticTask(ctx); err != nil {
			return fmt.Errorf("create demo task: %w", err)
		}
		tasks, err = runtime.ListRuntimeTasks(ctx)
		if err != nil {
			return fmt.Errorf("read demo task: %w", err)
		}
		for i := range tasks {
			if tasks[i].ID == "framework-demo" {
				demoTask = &tasks[i]
				break
			}
		}
	}
	if demoTask == nil {
		return fmt.Errorf("demo task was not persisted")
	}
	if demoTask.Status == "PENDING" {
		claimed, claimErr := runtime.ClaimRuntimeTask(ctx, "seed-demo-worker")
		if claimErr != nil {
			return fmt.Errorf("claim demo task: %w", claimErr)
		}
		if claimed == nil || len(claimed.Chunks) != 1 || len(claimed.Chunks[0].Targets) != 1 {
			return fmt.Errorf("demo task was not claimable")
		}
		if err := runtime.CompleteRuntimeTask(ctx, taskflow.Report{
			TaskID:   claimed.ID,
			WorkerID: "seed-demo-worker",
			Target:   claimed.Chunks[0].Targets[0],
			Title:    taskflow.SyntheticTitle,
		}); err != nil {
			return fmt.Errorf("complete demo task: %w", err)
		}
	}

	if out != nil {
		_, _ = fmt.Fprintf(out, "demo data ready: asset=%s task=%s database=%s at=%s\n", assetID, demoTask.ID, abs, time.Now().UTC().Format(time.RFC3339))
	}
	return nil
}

func main() {
	dbPath := flag.String("db", filepath.Join("runtime", "platform.db"), "Server SQLite database path")
	flag.Parse()
	if flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: seed-demo [--db path]")
		os.Exit(2)
	}
	if err := seedDemo(context.Background(), *dbPath, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
