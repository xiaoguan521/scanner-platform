package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"testing"

	"scanner-platform/internal/account"
	"scanner-platform/internal/repo"
)

func TestCapabilitiesListOnlyHarborAsUnavailable(t *testing.T) {
	accounts, err := account.New(filepath.Join(t.TempDir(), "platform.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer accounts.Close()
	store, err := repo.NewRuntime(accounts.SQLDB())
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	NewRuntimeHandler(store, nil, "").ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/v1/system/capabilities", nil))
	var body struct{ Enabled, Unavailable []string }
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(body.Unavailable, []string{"harbor"}) {
		t.Fatalf("unavailable=%v; only the Harbor integration is missing", body.Unavailable)
	}
	for _, want := range []string{"rule-signatures", "engine-validation", "rule-activation"} {
		if !slices.Contains(body.Enabled, want) {
			t.Fatalf("%s missing from enabled %v", want, body.Enabled)
		}
	}
}
