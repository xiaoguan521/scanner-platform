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
)

func TestRuntimeTaskListPageAPI(t *testing.T) {
	ctx := context.Background()
	store, err := repo.OpenRuntime(filepath.Join(t.TempDir(), "platform.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	for range 2 {
		if _, err := store.CreateSyntheticTask(ctx); err != nil {
			t.Fatal(err)
		}
	}
	handler := NewRuntimeHandler(store, nil, "")
	request := httptest.NewRequest(http.MethodGet, "/api/v1/tasks?page=1&page_size=1&archived=false&sort=-created_at", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var body TaskPageResponse
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.Total != 2 || len(body.Items) != 1 || body.Page != 1 || body.PageSize != 1 || body.StatusCounts["PENDING"] != 2 {
		t.Fatalf("unexpected task page: %+v", body)
	}
	for _, query := range []string{
		"?page=0&page_size=1",
		"?page=1&page=2&page_size=1",
		"?page=1&page_size=101",
		"?page=1&unknown=x",
		"?page=1&status=UNKNOWN",
	} {
		request := httptest.NewRequest(http.MethodGet, "/api/v1/tasks"+query, strings.NewReader(""))
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("query %s status=%d body=%s", query, response.Code, response.Body.String())
		}
	}
}
