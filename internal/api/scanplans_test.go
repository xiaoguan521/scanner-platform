package api

import (
	"bytes"
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

	createBody := `{"title":"实验主机只读","summary":"常见端口与 SSH","detail":"仅在明确授权范围内执行。","defaults":{"portPreset":"custom","intensity":"gentle","portRanges":"22,18080","portExclusions":"","customRuleIds":[]},"sourceId":"quick"}`
	createRequest := httptest.NewRequest(http.MethodPost, "/api/v1/scan-plans", bytes.NewBufferString(createBody))
	createResponse := httptest.NewRecorder()
	handler.ServeHTTP(createResponse, createRequest)
	if createResponse.Code != http.StatusCreated {
		t.Fatalf("create scan plan status=%d body=%s", createResponse.Code, createResponse.Body.String())
	}
	var created scanplans.Plan
	if err := json.NewDecoder(createResponse.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}
	if created.Kind != "CUSTOM" || created.ReadOnly || created.ID == "" {
		t.Fatalf("unexpected created plan: %+v", created)
	}
	updateBody := `{"title":"实验主机只读（更新）","summary":"更新摘要","detail":"更新说明。","defaults":{"portPreset":"common","intensity":"standard","portRanges":"","portExclusions":"443","customRuleIds":[]},"sourceId":"standard"}`
	updateRequest := httptest.NewRequest(http.MethodPut, "/api/v1/scan-plans/"+created.ID, bytes.NewBufferString(updateBody))
	updateResponse := httptest.NewRecorder()
	handler.ServeHTTP(updateResponse, updateRequest)
	if updateResponse.Code != http.StatusOK {
		t.Fatalf("update scan plan status=%d body=%s", updateResponse.Code, updateResponse.Body.String())
	}
	deleteRequest := httptest.NewRequest(http.MethodDelete, "/api/v1/scan-plans/"+created.ID, nil)
	deleteResponse := httptest.NewRecorder()
	handler.ServeHTTP(deleteResponse, deleteRequest)
	if deleteResponse.Code != http.StatusOK {
		t.Fatalf("delete scan plan status=%d body=%s", deleteResponse.Code, deleteResponse.Body.String())
	}
	presetDelete := httptest.NewRequest(http.MethodDelete, "/api/v1/scan-plans/quick", nil)
	presetDeleteResponse := httptest.NewRecorder()
	handler.ServeHTTP(presetDeleteResponse, presetDelete)
	if presetDeleteResponse.Code != http.StatusConflict {
		t.Fatalf("preset delete status=%d body=%s, want conflict", presetDeleteResponse.Code, presetDeleteResponse.Body.String())
	}
}
