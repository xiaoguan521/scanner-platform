package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"scanner-platform/internal/repo"
	"scanner-platform/internal/reporting"
)

func TestReportListPageAPI(t *testing.T) {
	ctx := context.Background()
	store, err := repo.OpenRuntime(filepath.Join(t.TempDir(), "reports.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	for _, format := range []string{"html", "pdf"} {
		if _, err := store.CreateReport(ctx, reporting.Request{Format: format}, "report-owner"); err != nil {
			t.Fatal(err)
		}
	}
	handler := NewRuntimeHandler(store, nil, "")
	request := httptest.NewRequest(http.MethodGet, "/api/v1/reports?page=1&page_size=1&format=pdf&sort=-created_at", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var body ReportPageResponse
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.Total != 1 || len(body.Items) != 1 || body.Page != 1 || body.PageSize != 1 || body.Items[0].Format != "pdf" {
		t.Fatalf("unexpected report page: %+v", body)
	}
	for _, query := range []string{
		"?page=0&page_size=1",
		"?page=1&page=2&page_size=1",
		"?page=1&page_size=101",
		"?page=1&unknown=x",
		"?page=1&status=UNKNOWN",
		"?page=1&format=zip",
	} {
		request := httptest.NewRequest(http.MethodGet, "/api/v1/reports"+query, strings.NewReader(""))
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("query %s status=%d body=%s", query, response.Code, response.Body.String())
		}
	}
}
