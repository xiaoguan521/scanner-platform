package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"scanner-platform/internal/account"
	"scanner-platform/internal/assets"
	"scanner-platform/internal/repo"
	"scanner-platform/internal/taskflow"
)

func TestDashboardSummaryRequiresAuthAndAggregatesLocalState(t *testing.T) {
	accounts, err := account.New(filepath.Join(t.TempDir(), "platform.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer accounts.Close()
	if err := accounts.InitAdmin(context.Background(), "dashboardadmin", "Safe-Dashboard-Password-12"); err != nil {
		t.Fatal(err)
	}
	store, err := repo.NewRuntime(accounts.SQLDB())
	if err != nil {
		t.Fatal(err)
	}
	assetStore, err := assets.NewWithPinger(accounts.SQLDB(), func(context.Context, string) (bool, error) { return true, nil })
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SeedSyntheticTask(context.Background()); err != nil {
		t.Fatal(err)
	}
	handler := NewRuntimeHandler(store, NewDevelopmentHandler(accounts, assetStore), "", accounts)
	server := httptest.NewServer(handler)
	defer server.Close()

	if response, err := server.Client().Get(server.URL + "/api/v1/dashboard/summary"); err != nil {
		t.Fatal(err)
	} else if response.StatusCode != http.StatusUnauthorized {
		response.Body.Close()
		t.Fatalf("anonymous summary: %d", response.StatusCode)
	} else {
		response.Body.Close()
	}

	loginRequest, err := http.NewRequest(http.MethodPost, server.URL+"/api/v1/auth/login", strings.NewReader(`{"username":"dashboardadmin","password":"Safe-Dashboard-Password-12"}`))
	if err != nil {
		t.Fatal(err)
	}
	loginRequest.Header.Set("Content-Type", "application/json")
	loginRequest.Header.Set("X-Requested-With", "XMLHttpRequest")
	login, err := server.Client().Do(loginRequest)
	if err != nil {
		t.Fatal(err)
	}
	if login.StatusCode != http.StatusOK {
		login.Body.Close()
		t.Fatalf("login: %d", login.StatusCode)
	}
	cookie := login.Cookies()[0]
	login.Body.Close()

	createRequest, err := http.NewRequest(http.MethodPost, server.URL+"/api/v1/assets", bytes.NewBufferString(`{"kind":"host","address":"192.0.2.70","businessGroup":"示例业务组","owner":"示例负责人"}`))
	if err != nil {
		t.Fatal(err)
	}
	createRequest.Header.Set("Content-Type", "application/json")
	createRequest.Header.Set("X-Requested-With", "XMLHttpRequest")
	createRequest.AddCookie(cookie)
	created, err := server.Client().Do(createRequest)
	if err != nil {
		t.Fatal(err)
	}
	if created.StatusCode != http.StatusCreated {
		created.Body.Close()
		t.Fatalf("create asset: %d", created.StatusCode)
	}
	created.Body.Close()

	request, err := http.NewRequest(http.MethodGet, server.URL+"/api/v1/dashboard/summary?days=7", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.AddCookie(cookie)
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("summary: %d", response.StatusCode)
	}
	var summary DashboardSummary
	if err := json.NewDecoder(response.Body).Decode(&summary); err != nil {
		t.Fatal(err)
	}
	if summary.AssetCount != 1 || summary.TaskCount != 1 || summary.HasNonSyntheticTask || summary.HasCompletedScan || len(summary.Trend) != 7 {
		t.Fatalf("unexpected summary: %+v", summary)
	}
	if summary.FindingCount != 0 || summary.PendingCount != 0 || summary.RiskScore != 0 || summary.CurrentRule != nil {
		t.Fatalf("empty findings/rules were not represented safely: %+v", summary)
	}

	for _, path := range []string{"/api/v1/dashboard/summary?days=14", "/api/v1/dashboard/summary?days=7&days=30"} {
		badRequest, err := http.NewRequest(http.MethodGet, server.URL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		badRequest.AddCookie(cookie)
		result, err := server.Client().Do(badRequest)
		if err != nil {
			t.Fatal(err)
		}
		result.Body.Close()
		if result.StatusCode != http.StatusBadRequest {
			t.Fatalf("invalid dashboard query %s: %d", path, result.StatusCode)
		}
	}
}

func TestDashboardSummaryRiskAndPendingProjection(t *testing.T) {
	firstSeen := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	lastSeen := time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC)
	items := []taskflow.Finding{
		{ID: "critical", RiskType: "web", Severity: "CRITICAL", Status: "OPEN", Target: "192.0.2.70:80", AssetID: "asset-1", BusinessGroup: "示例业务组", FirstSeen: firstSeen, LastSeen: lastSeen},
		{ID: "accepted", RiskType: "system", Severity: "HIGH", Status: "ACCEPTED_RISK", Target: "192.0.2.71:22", AssetID: "asset-2", BusinessGroup: "示例业务组", FirstSeen: firstSeen, LastSeen: lastSeen},
		{ID: "fixed", RiskType: "web", Severity: "HIGH", Status: "FIXED", Target: "192.0.2.72:443", AssetID: "asset-3", BusinessGroup: "历史", FirstSeen: firstSeen, LastSeen: lastSeen},
	}
	summary := DashboardSummary{
		RiskScore:       dashboardRiskScore(items),
		RiskyAssetCount: dashboardRiskAssetCount(items),
		PendingCount:    dashboardPendingCount(items),
		PendingFindings: dashboardPendingFindings(items, 5),
		Trend:           dashboardTrend(items, 7, time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)),
	}
	if summary.RiskScore != 35 || summary.RiskyAssetCount != 2 || summary.PendingCount != 1 || len(summary.PendingFindings) != 1 || summary.PendingFindings[0].ID != "critical" {
		t.Fatalf("risk summary mismatch: %+v", summary)
	}
	if len(summary.Trend) != 7 || summary.Trend[len(summary.Trend)-1].Count != 2 {
		t.Fatalf("trend mismatch: %+v", summary.Trend)
	}
}
