package repo

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"scanner-platform/internal/reporting"
)

func TestReportListPageFiltersAndSorts(t *testing.T) {
	store, _ := reportTestStore(t)
	ctx := context.Background()
	jobs := make([]reporting.Job, 0, 3)
	for _, format := range []string{"html", "xlsx", "pdf"} {
		job, err := store.CreateReport(ctx, reporting.Request{Format: format}, "report-owner")
		if err != nil {
			t.Fatal(err)
		}
		jobs = append(jobs, job)
	}
	for index, job := range jobs {
		name := []string{"每日基线", "月度汇总", "专项报告"}[index]
		status := []string{"READY", "FAILED", "QUEUED"}[index]
		if _, err := store.db.ExecContext(ctx, `UPDATE report_jobs SET status=?,data=json_set(data,'$.name',?) WHERE id=?`, status, name, job.ID); err != nil {
			t.Fatal(err)
		}
	}

	page, err := store.ListReportsPage(ctx, ReportListQuery{Page: 1, PageSize: 1, Sort: "-created_at"})
	if err != nil || page.Total != 3 || len(page.Items) != 1 || page.Page != 1 || page.PageSize != 1 {
		t.Fatalf("unexpected report page: %+v err=%v", page, err)
	}
	page, err = store.ListReportsPage(ctx, ReportListQuery{Page: 1, PageSize: 10, Status: "READY", Format: "html", Search: "每日"})
	if err != nil || page.Total != 1 || len(page.Items) != 1 || page.Items[0].Format != "html" || page.Items[0].Status != "READY" {
		t.Fatalf("filtered report page: %+v err=%v", page, err)
	}
	if _, err := store.ListReportsPage(ctx, ReportListQuery{Page: 1, PageSize: 1, Sort: "drop_table"}); !errors.Is(err, ErrInvalidReportListQuery) {
		t.Fatalf("invalid report sort accepted: %v", err)
	}
}

func TestReportListPageEmptyResultHasStablePageSize(t *testing.T) {
	store, _ := reportTestStore(t)
	page, err := store.ListReportsPage(context.Background(), ReportListQuery{Page: 1, PageSize: 20, Status: "READY"})
	if err != nil || page.Total != 0 || len(page.Items) != 0 || page.PageSize != 20 {
		t.Fatalf("empty report page: %+v err=%v", page, err)
	}
}

func TestReportListPageKeepsStoredJobFields(t *testing.T) {
	store, _ := reportTestStore(t)
	job, err := store.CreateReport(context.Background(), reporting.Request{Format: "json"}, "report-owner")
	if err != nil {
		t.Fatal(err)
	}
	page, err := store.ListReportsPage(context.Background(), ReportListQuery{Page: 1, PageSize: 20})
	if err != nil || len(page.Items) != 1 {
		t.Fatalf("report page: %+v err=%v", page, err)
	}
	if got, _ := json.Marshal(page.Items[0]); len(got) == 0 || page.Items[0].ID != job.ID || page.Items[0].FilePath != "" {
		t.Fatalf("unexpected stored fields: %+v", page.Items[0])
	}
}
