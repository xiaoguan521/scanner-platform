package executor

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func TestReadOnlyConfigurationChecksWithSafeEvidence(t *testing.T) {
	var mu sync.Mutex
	calls := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls = append(calls, r.Method+" "+r.URL.RequestURI())
		mu.Unlock()
		if r.Header.Get("Authorization") != "" || r.ContentLength > 0 {
			t.Error("sent credentials or body")
		}
		switch r.URL.Path {
		case "/":
			w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			if r.Method == http.MethodOptions {
				w.Header().Set("Allow", "GET, PUT, DELETE, OPTIONS")
				return
			}
			w.Write([]byte("<title>Welcome to nginx!</title>"))
		case "/actuator/env":
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"propertySources":[{"name":"fixture","properties":{"sensitive-fixture":{"value":"not-for-evidence"}}}]}`))
		case "/server-status":
			w.Write([]byte("Total Accesses: 3\nBusyWorkers: 1\n"))
		}
	}))
	defer server.Close()
	target := strings.TrimPrefix(server.URL, "http://")
	findings, err := checkWebConfiguration(context.Background(), "http", []string{target}, 250, 1)
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]bool{}
	for _, f := range findings {
		ids[f.TemplateID] = true
		if f.DetectMethod != "configuration" || f.Confidence != "high" || f.RiskType != "web" || f.CVSSScore != nil {
			t.Fatalf("missing metadata %+v", f)
		}
		data, _ := json.Marshal(f)
		if strings.Contains(string(data), "not-for-evidence") {
			t.Fatal("retained sensitive value")
		}
	}
	for _, id := range []string{"baseline-nosniff", "baseline-csp", "baseline-frame-options", "web-cors-credentials", "web-default-page", "web-methods-advertised", "web-actuator-env", "web-server-status"} {
		if !ids[id] {
			t.Errorf("missing %s: %v", id, ids)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if len(calls) != 4 {
		t.Fatal(calls)
	}
	for _, call := range calls {
		if !strings.HasPrefix(call, "GET ") && !strings.HasPrefix(call, "OPTIONS ") {
			t.Fatal(call)
		}
	}
}

func TestReadOnlyChecksNeverFollowRedirectsOrConnectExcludedTargets(t *testing.T) {
	var remoteCalls atomic.Int32
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { remoteCalls.Add(1) }))
	defer remote.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, remote.URL+"/actuator/env", 302) }))
	defer server.Close()
	if _, err := checkWebConfiguration(context.Background(), "http", []string{strings.TrimPrefix(server.URL, "http://")}, 250, 1); err != nil {
		t.Fatal(err)
	}
	if remoteCalls.Load() != 0 {
		t.Fatal("redirect reached another target")
	}
	// Validation is completed before connecting to any target, even if a later item is invalid.
	if _, err := checkWebConfiguration(context.Background(), "http", []string{strings.TrimPrefix(remote.URL, "http://"), "example.test:80"}, 250, 1); err == nil {
		t.Fatal("hostname accepted")
	}
	if remoteCalls.Load() != 0 {
		t.Fatal("connected before validating full endpoint list")
	}
	for _, request := range []struct{ method, path string }{{"POST", "/"}, {"DELETE", "/"}, {"GET", "/login"}, {"OPTIONS", "/actuator/env"}, {"GET", "http://example.test/"}} {
		if _, err := fetchReadOnlyWeb(context.Background(), http.DefaultClient, "http", strings.TrimPrefix(server.URL, "http://"), request.method, request.path); err == nil {
			t.Fatalf("allowed %+v", request)
		}
	}
}

func TestNoUnauthorizedFindingForGenericJSONOrHealth(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
		w.Write([]byte(`{"status":"UP"}`))
	}))
	defer server.Close()
	findings, err := checkWebConfiguration(context.Background(), "http", []string{strings.TrimPrefix(server.URL, "http://")}, 250, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatal(findings)
	}
}
