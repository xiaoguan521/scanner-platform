//go:build lab

package executor

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"scanner-platform/internal/rules"
	"scanner-platform/internal/taskflow"
)

// This lab uses only an ephemeral loopback HTTP fixture and operator-local files.
// It never reads registered assets or connects to a real server.
func TestInstalledEnginesOnLoopbackFixture(t *testing.T) {
	if os.Getenv("LAB_ENV") != "isolated" {
		t.Skip("set LAB_ENV=isolated for the local fixture")
	}
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	manager := rules.Manager{Root: filepath.Join(dir, "rules")}
	bundle, err := manager.PrepareDefault(context.Background(), "20261016.01", "", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.ActivatePreparedLocal(context.Background(), bundle.Version); err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int32
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Method == "OPTIONS" && r.URL.Path == "/" {
			w.Header().Set("Allow", "GET, HEAD, OPTIONS")
			w.WriteHeader(204)
			return
		}
		if r.Method != "GET" || (r.URL.Path != "/" && r.URL.Path != "/actuator/env" && r.URL.Path != "/server-status") {
			t.Error("request outside fixed read-only allowlist")
			w.WriteHeader(400)
			return
		}
		if r.URL.Path != "/" {
			w.WriteHeader(404)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Server", "local-fixture")
		_, _ = w.Write([]byte("<html><title>Local fixture</title><body>baseline fixture</body></html>"))
	})
	fixture := httptest.NewServer(handler)
	secureFixture := httptest.NewTLSServer(handler)
	defer secureFixture.Close()
	defer fixture.Close()
	runner := Runner{BinDir: filepath.Join(root, "bin"), RulesDir: manager.Root, RuntimeDir: filepath.Join(dir, "runtime"), InputsDir: filepath.Join(dir, "inputs"), Rate: 5, Timeout: 5}
	tests := []struct{ engine, scheme, url string }{{"nuclei", "http", fixture.URL}, {"nuclei", "https", secureFixture.URL}}
	if os.Getenv("SCANNER_EXPECT_ZAP") == "1" {
		tests = append(tests, struct{ engine, scheme, url string }{"zap", "http", fixture.URL}, struct{ engine, scheme, url string }{"zap", "https", secureFixture.URL})
	} else {
		t.Log("SKIP ZAP: optional passive engine is not required (set SCANNER_EXPECT_ZAP=1 to require it)")
	}
	for _, test := range tests {
		engine := test.engine
		t.Run(test.scheme+"/"+engine, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			task := taskflow.Task{ID: "fixture-" + engine, Engines: []string{engine}, Scheme: test.scheme, RuleVersion: bundle.Version, Chunks: []taskflow.Chunk{{Targets: []string{strings.TrimPrefix(test.url, test.scheme+"://")}}}}
			detections, err := runner.Execute(ctx, task)
			if err != nil {
				filepath.WalkDir(runner.RuntimeDir, func(path string, entry os.DirEntry, e error) error {
					if e == nil && !entry.IsDir() && strings.HasSuffix(path, ".log") {
						data, _ := os.ReadFile(path)
						if len(data) > 12000 {
							data = data[len(data)-12000:]
						}
						t.Logf("%s: %s", path, data)
					}
					return nil
				})
				t.Fatalf("engine fixture: %v (runtime %s)", err, runner.RuntimeDir)
			}
			if len(detections) == 0 {
				t.Fatal("baseline findings expected")
			}
			t.Logf("%s produced %d findings on loopback fixture", engine, len(detections))
		})
	}
	t.Logf("fixture received %d bounded read-only requests", requests.Load())
}

func TestInstalledTrivyOnLocalDependencyFixture(t *testing.T) {
	if os.Getenv("LAB_ENV") != "isolated" {
		t.Skip("requires operator-local Trivy DB")
	}
	root, _ := filepath.Abs("../..")
	dir := t.TempDir()
	input := filepath.Join(dir, "inputs", "deps")
	if err := os.MkdirAll(input, 0700); err != nil {
		t.Fatal(err)
	}
	// A small historical test dependency, not a downloaded package or a real asset.
	lock := `{"name":"local-fixture","version":"1.0.0","lockfileVersion":2,"requires":true,"packages":{"":{"name":"local-fixture","version":"1.0.0","dependencies":{"lodash":"4.17.20"}},"node_modules/lodash":{"version":"4.17.20"}},"dependencies":{"lodash":{"version":"4.17.20"}}}`
	if err := os.WriteFile(filepath.Join(input, "package-lock.json"), []byte(lock), 0600); err != nil {
		t.Fatal(err)
	}
	runner := Runner{BinDir: filepath.Join(root, "bin"), RulesDir: filepath.Join(root, "vuln-data"), RuntimeDir: filepath.Join(dir, "runtime"), InputsDir: filepath.Join(dir, "inputs"), Rate: 5, Timeout: 5}
	current, err := os.ReadFile(filepath.Join(runner.RulesDir, "CURRENT"))
	if err != nil {
		t.Fatal(err)
	}
	task := taskflow.Task{ID: "trivy-fixture", Engines: []string{"trivy"}, InputKind: "filesystem", InputPath: "deps", RuleVersion: strings.TrimSpace(string(current)), Chunks: []taskflow.Chunk{{Targets: []string{"deps"}}}}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	detections, err := runner.Execute(ctx, task)
	if err != nil {
		t.Fatal(err)
	}
	if len(detections) == 0 {
		t.Fatal("fixture should produce vulnerability findings")
	}
	t.Logf("Trivy produced %d findings on a local dependency lock", len(detections))
}
