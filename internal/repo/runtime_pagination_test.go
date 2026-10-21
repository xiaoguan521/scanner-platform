package repo

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
)

func TestRuntimeTaskListPageFiltersAndCounts(t *testing.T) {
	ctx := context.Background()
	store, err := OpenRuntime(filepath.Join(t.TempDir(), "platform.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	created := make([]string, 0, 3)
	for range 3 {
		task, err := store.CreateSyntheticTask(ctx)
		if err != nil {
			t.Fatal(err)
		}
		created = append(created, task.ID)
	}
	if _, err := store.db.ExecContext(ctx, "UPDATE scan_tasks SET status='FAILED' WHERE id=?", created[0]); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, "UPDATE scan_tasks SET status='COMPLETED' WHERE id=?", created[1]); err != nil {
		t.Fatal(err)
	}
	if err := store.SetTaskArchived(ctx, created[1], "test-actor", true); err != nil {
		t.Fatal(err)
	}

	page, err := store.ListRuntimeTasksPage(ctx, TaskListQuery{Page: 1, PageSize: 1, Archived: "false", Search: "192.0.2.10", Sort: "-created_at"})
	if err != nil {
		t.Fatal(err)
	}
	if page.Total != 2 || len(page.Items) != 1 || page.Page != 1 || page.PageSize != 1 {
		t.Fatalf("unexpected page: %+v", page)
	}
	if page.StatusCounts["FAILED"] != 1 || page.StatusCounts["PENDING"] != 1 {
		t.Fatalf("unexpected status counts: %+v", page.StatusCounts)
	}

	enginePage, err := store.ListRuntimeTasksPage(ctx, TaskListQuery{Page: 1, PageSize: 20, Engine: "synthetic", Archived: "all"})
	if err != nil || enginePage.Total != 3 {
		t.Fatalf("synthetic engine filter: %+v err=%v", enginePage, err)
	}
	if _, err := store.ListRuntimeTasksPage(ctx, TaskListQuery{Page: 1, PageSize: 1, Sort: "drop_table"}); !errors.Is(err, ErrInvalidTaskListQuery) {
		t.Fatalf("invalid sort accepted: %v", err)
	}
}
