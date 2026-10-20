package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"scanner-platform/internal/account"
	"scanner-platform/internal/assets"
	"scanner-platform/internal/repo"
	"scanner-platform/internal/taskflow"
)

func TestScheduleRunHistoryAPIIsPaginatedAndReadOnly(t *testing.T) {
	accounts, err := account.New(filepath.Join(t.TempDir(), "schedule.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer accounts.Close()
	ctx := context.Background()
	if err := accounts.InitAdmin(ctx, "schedule-admin", "Example-schedule-password"); err != nil {
		t.Fatal(err)
	}
	admin, _, err := accounts.Authenticate(ctx, "schedule-admin", "Example-schedule-password")
	if err != nil {
		t.Fatal(err)
	}
	registry, err := assets.New(accounts.SQLDB())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Create(ctx, admin.ID, assets.Input{Kind: "host", Address: "192.0.2.20", BusinessGroup: "QA", Owner: "Example", RequestedPorts: []int{80}}); err != nil {
		t.Fatal(err)
	}
	store, err := repo.NewRuntime(accounts.SQLDB())
	if err != nil {
		t.Fatal(err)
	}
	due := time.Now().Add(time.Minute).Truncate(time.Second)
	schedule, err := store.SaveSchedule(ctx, taskflow.Schedule{
		Name:      "Synthetic history",
		TaskInput: taskflow.TaskInput{Synthetic: true, Targets: []string{"192.0.2.20:80"}},
		NextRun:   due.Format(time.RFC3339),
	}, "local-test")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Tick(ctx, due); err != nil {
		t.Fatal(err)
	}
	handler := NewRuntimeHandler(store, nil, "")
	request := httptest.NewRequest(http.MethodGet, "/api/v1/schedules/"+schedule.ID+"/runs?limit=1", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("history status=%d body=%s", response.Code, response.Body.String())
	}
	var body struct {
		Items []taskflow.ScheduleRun `json:"items"`
		Total int                    `json:"total"`
	}
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.Total != 1 || len(body.Items) != 1 || body.Items[0].TaskID == "" || body.Items[0].Status != "PENDING" {
		t.Fatalf("unexpected history response: %+v", body)
	}
	invalid := httptest.NewRequest(http.MethodGet, "/api/v1/schedules/"+schedule.ID+"/runs?limit=0", nil)
	invalidResponse := httptest.NewRecorder()
	handler.ServeHTTP(invalidResponse, invalid)
	if invalidResponse.Code != http.StatusBadRequest {
		t.Fatalf("invalid pagination status=%d", invalidResponse.Code)
	}
}
