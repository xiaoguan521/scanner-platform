package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"scanner-platform/internal/account"
	"scanner-platform/internal/repo"
	"scanner-platform/internal/taskflow"
)

func TestFindingListPageAPI(t *testing.T) {
	ctx := context.Background()
	accounts, err := account.New(filepath.Join(t.TempDir(), "platform.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer accounts.Close()
	store, err := repo.NewRuntime(accounts.SQLDB())
	if err != nil {
		t.Fatal(err)
	}

	base := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	for index, item := range []taskflow.Finding{
		{ID: "finding-api-high", Severity: "HIGH", Status: "OPEN", Engine: "trivy", TemplateOrCVE: "CVE-2099-0001", Target: "192.0.2.10:22", Title: "包版本风险", RiskType: "system", DetectMethod: "version", FirstSeen: base, LastSeen: base.Add(time.Hour)},
		{ID: "finding-api-low", Severity: "LOW", Status: "FIXED", Engine: "nuclei", TemplateOrCVE: "headers", Target: "192.0.2.10:80", Title: "响应头检查", RiskType: "web", DetectMethod: "configuration", FirstSeen: base, LastSeen: base.Add(2 * time.Hour)},
	} {
		task, err := store.CreateSyntheticTask(ctx)
		if err != nil {
			t.Fatal(err)
		}
		item.TaskID = task.ID
		data, err := json.Marshal(item)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := accounts.SQLDB().ExecContext(ctx, `INSERT INTO security_findings(id,task_id,data) VALUES(?,?,?)`, item.ID, task.ID, string(data)); err != nil {
			t.Fatalf("insert finding %d: %v", index, err)
		}
	}

	handler := NewRuntimeHandler(store, nil, "")
	request := httptest.NewRequest(http.MethodGet, "/api/v1/findings?page=1&page_size=1&severity=HIGH&sort=-last_seen", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var body FindingPageResponse
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.Total != 1 || len(body.Items) != 1 || body.Page != 1 || body.PageSize != 1 || body.Items[0].ID != "finding-api-high" || body.Counts.Version != 1 {
		t.Fatalf("unexpected finding page: %+v", body)
	}

	for _, query := range []string{
		"?page=0&page_size=1",
		"?page=1&page=2&page_size=1",
		"?page=1&page_size=101",
		"?page=1&unknown=x",
		"?page=1&severity=UNKNOWN",
		"?page=1&onlyVerified=maybe",
	} {
		request := httptest.NewRequest(http.MethodGet, "/api/v1/findings"+query, strings.NewReader(""))
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("query %s status=%d body=%s", query, response.Code, response.Body.String())
		}
	}
}
