package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestScaffoldContractReadOnlyAndNotReady(t *testing.T) {
	h := NewScaffoldHandler("sec-server")
	cases := []struct {
		method string
		path   string
		want   int
	}{
		{"GET", "/healthz", http.StatusOK},
		{"GET", "/readyz", http.StatusServiceUnavailable},
		{"GET", "/api/v1/system/status", http.StatusOK},
		{"GET", "/api/v1/system/capabilities", http.StatusOK},
		{"GET", "/api/v1/users", http.StatusNotImplemented},
		{"GET", "/api/v1/assets", http.StatusNotImplemented},
		{"GET", "/api/v1/port-quarantines", http.StatusNotImplemented},
		{"GET", "/api/v1/scopes", http.StatusNotImplemented},
		{"GET", "/api/v1/tasks", http.StatusNotImplemented},
		{"GET", "/api/v1/findings", http.StatusNotImplemented},
		{"GET", "/api/v1/nodes", http.StatusNotImplemented},
		{"GET", "/api/v1/rules", http.StatusNotImplemented},
		{"POST", "/api/v1/users", http.StatusMethodNotAllowed},
		{"PATCH", "/api/v1/users", http.StatusMethodNotAllowed},
		{"POST", "/api/v1/tasks", http.StatusMethodNotAllowed},
		{"POST", "/api/v1/rules", http.StatusMethodNotAllowed},
		{"PATCH", "/api/v1/findings", http.StatusMethodNotAllowed},
	}
	for _, tc := range cases {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			response := httptest.NewRecorder()
			h.ServeHTTP(response, httptest.NewRequest(tc.method, tc.path, nil))
			if response.Code != tc.want {
				t.Fatalf("status=%d want=%d body=%s", response.Code, tc.want, response.Body.String())
			}
			if response.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("unsafe caching header: %v", response.Header())
			}
		})
	}
}

func TestScaffoldStatusCannotClaimReady(t *testing.T) {
	out := httptest.NewRecorder()
	NewScaffoldHandler("sec-server").ServeHTTP(out, httptest.NewRequest("GET", "/api/v1/system/status", nil))
	var body Status
	if err := json.Unmarshal(out.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Ready || body.State != "SCAFFOLD" {
		t.Fatalf("scaffold cannot claim ready: %+v", body)
	}
	requiredUnavailable := []string{"authentication", "user-management", "rbac"}
	for _, required := range requiredUnavailable {
		found := false
		for _, listed := range body.Unavailable {
			if listed == required {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("unavailable capability %q was not declared", required)
		}
	}
	for _, capability := range body.Enabled {
		if capability == "scanning" || capability == "rule-activation" || capability == "database" {
			t.Fatalf("unsafe enabled capability: %s", capability)
		}
	}
}
