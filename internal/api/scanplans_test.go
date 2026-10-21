package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"scanner-platform/internal/repo"
	"scanner-platform/internal/scanplans"
)

func TestScanPlansExposeOnlyProductReadOnlyPresets(t *testing.T) {
	store, err := repo.OpenRuntime(filepath.Join(t.TempDir(), "scan-plans.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	handler := NewRuntimeHandler(store, nil, "")
	request := httptest.NewRequest(http.MethodGet, "/api/v1/scan-plans", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("scan plan status=%d body=%s", response.Code, response.Body.String())
	}
	var body ListResponse[scanplans.Plan]
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.Total != 2 || len(body.Items) != 2 || body.Items[0].ID != "quick" || body.Items[1].ID != "standard" {
		t.Fatalf("unexpected scan plan catalog: %+v", body)
	}
	for _, plan := range body.Items {
		if plan.Kind != "PRESET" || !plan.ReadOnly || plan.Defaults.PortPreset == "" || plan.Defaults.Intensity == "" {
			t.Fatalf("incomplete or writable scan plan: %+v", plan)
		}
	}
}
