package executor

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"scanner-platform/internal/executor/engineflags"
	"scanner-platform/internal/rules"
)

func TestBaselineTemplatePolicy(t *testing.T) {
	for _, data := range rules.BaselineTemplates() {
		if _, err := ValidateTemplate(data); err != nil {
			t.Fatal(err)
		}
		for _, change := range []func(map[string]any){
			func(v map[string]any) { v["code"] = []any{} },
			func(v map[string]any) { v["http"].([]any)[0].(map[string]any)["method"] = "POST" },
			func(v map[string]any) {
				v["http"].([]any)[0].(map[string]any)["path"] = []string{"https://example.com/"}
			},
			func(v map[string]any) { v["http"].([]any)[0].(map[string]any)["raw"] = []string{"GET / HTTP/1.1"} },
		} {
			var value map[string]any
			_ = json.Unmarshal(data, &value)
			change(value)
			bad, _ := json.Marshal(value)
			if _, err := ValidateTemplate(bad); err == nil {
				t.Fatal("unsafe template accepted")
			}
		}
	}
}

func TestScopeProxyRejectsUnlistedAuthorities(t *testing.T) {
	called := 0
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called++; w.WriteHeader(204) }))
	defer target.Close()
	allowed := strings.TrimPrefix(target.URL, "http://")
	proxy, err := startScopeProxy(context.Background(), []string{allowed})
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	proxyURL, _ := url.Parse(proxy.URL())
	transport := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport}
	for _, test := range []struct {
		raw  string
		code int
	}{{target.URL, 204}, {"http://192.0.2.12:80/", 403}, {"http://example.com:80/", 403}, {target.URL + "/other", 403}} {
		response, err := client.Get(test.raw)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, response.Body)
		response.Body.Close()
		if response.StatusCode != test.code {
			t.Fatalf("status %d for %s", response.StatusCode, test.raw)
		}
	}
	if called != 1 {
		t.Fatalf("unexpected target calls: %d", called)
	}
}

func TestFetchRootDoesNotFollowRedirects(t *testing.T) {
	outsideCalls := 0
	outside := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { outsideCalls++ }))
	defer outside.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, outside.URL, 302) }))
	defer origin.Close()
	result, err := fetchRoot(context.Background(), origin.URL, 2)
	if err != nil || result.Status != 302 || outsideCalls != 0 {
		t.Fatalf("redirect followed: %+v %v calls=%d", result, err, outsideCalls)
	}
	for _, raw := range []string{"http://example.com:80", "http://192.0.2.1", "http://192.0.2.1:80/path"} {
		if _, err := fetchRoot(context.Background(), raw, 1); err == nil {
			t.Fatal("invalid root accepted")
		}
	}
}

func TestEngineOutputNormalization(t *testing.T) {
	nuclei := []byte(`{"template-id":"test","matched-at":"http://192.0.2.10:8080/?nonce=one","info":{"name":"header test","severity":"low"}}`)
	detections, err := ParseNuclei(nuclei, []string{"192.0.2.10:8080"})
	if err != nil || len(detections) != 1 || detections[0].MatchedPath != "/" {
		t.Fatalf("normalization: %+v %v", detections, err)
	}
	if _, err := ParseNuclei(nuclei, []string{"192.0.2.10:8443"}); err == nil {
		t.Fatal("unlisted result accepted")
	}
	trivy := []byte(`{"Results":[{"Target":"package-lock.json","Vulnerabilities":[{"VulnerabilityID":"CVE-2099-0001","PkgName":"fixture","InstalledVersion":"1.0","FixedVersion":"2.0","Severity":"HIGH"}]}]}`)
	detections, err = ParseTrivy(trivy, "fixture")
	if err != nil || len(detections) != 1 || detections[0].Package != "fixture" || detections[0].FixedVersion != "2.0" {
		t.Fatal(detections, err)
	}
	zap := []byte(`{"site":[{"alerts":[{"pluginid":"10001","name":"fixture header","riskcode":"1","instances":[{"uri":"http://192.0.2.10:8080/"}]}]}]}`)
	detections, err = ParseZAP(zap, []string{"192.0.2.10:8080"})
	if err != nil || len(detections) != 1 {
		t.Fatal(detections, err)
	}
	if _, err := ParseZAP(zap, []string{"192.0.2.10:80"}); err == nil {
		t.Fatal("unlisted ZAP result accepted")
	}
}

func TestTrivyLocalInputAndArguments(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "deps"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := localInput(root, "deps", "filesystem"); err != nil {
		t.Fatal(err)
	}
	if _, err := localInput(root, "deps", "rootfs"); err != nil {
		t.Fatal(err)
	}
	for _, relative := range []string{"../elsewhere", "/absolute", "http://example.com", "--flag"} {
		if _, err := localInput(root, relative, "filesystem"); err == nil {
			t.Fatal("unsafe input accepted")
		}
	}
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "deps", "link")); err == nil {
		if _, err := localInput(root, "deps", "filesystem"); err == nil {
			t.Fatal("symlink input accepted")
		}
	}
	args := strings.Join(engineflags.TrivyArgs("image-archive", "/input/archive.tar", "/cache", "/out"), " ")
	for _, flag := range []string{"--input", "--offline-scan", "--skip-db-update", "--skip-java-db-update", "--disable-telemetry", "--config  "} {
		if !strings.Contains(args, flag) {
			t.Fatalf("missing %s", flag)
		}
	}
	args = strings.Join(engineflags.TrivyArgs("rootfs", "/input/os", "/cache", "/out"), " ")
	if !strings.HasPrefix(args, "rootfs ") || !strings.Contains(args, "--pkg-types os") || strings.Contains(args, "--input") {
		t.Fatal("rootfs must use only OS package analysis", args)
	}
	args = strings.Join(engineflags.TrivyArgs("artifact", "/input/apps", "/cache", "/out"), " ")
	if !strings.HasPrefix(args, "rootfs ") || !strings.Contains(args, "--pkg-types library") || !strings.Contains(args, "--file-patterns gobinary:.*") {
		t.Fatal("deployed artifacts require library analysis independent of executable permissions", args)
	}
	plan, _ := json.Marshal(ZAPPlan("fixture.har", "output", []string{"http://192.0.2.1:80"}))
	if strings.Contains(string(plan), "spider") || strings.Contains(string(plan), "activeScan") || strings.Contains(string(plan), `"type":"requestor"`) {
		t.Fatal("ZAP plan must only import responses")
	}
}

func TestTrivyRootfsRejectsUnanalyzedOS(t *testing.T) {
	for _, report := range []string{`{}`, `{"Results":[]}`, `{"Results":[{"Class":"lang-pkgs","Target":"package-lock.json"}]}`} {
		if _, err := parseTrivy([]byte(report), "lab-a/os", true); err == nil {
			t.Fatal("missing OS package analysis reported as success", report)
		}
	}
	// A supported OS package analysis may legitimately have no known CVEs.
	if got, err := parseTrivy([]byte(`{"Results":[{"Class":"os-pkgs","Target":"Debian 12"}]}`), "lab-a/os", true); err != nil || len(got) != 0 {
		t.Fatal(got, err)
	}
}

func TestJavaInputDetectionDoesNotRequireAnIndexForNodeInputs(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "package-lock.json"), []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}
	if java, artifacts, err := inspectApplicationInput(context.Background(), root, false); err != nil || java || artifacts {
		t.Fatal(java, artifacts, err)
	}
	if _, _, err := inspectApplicationInput(context.Background(), root, true); err == nil {
		t.Fatal("lockfiles accepted as deployed artifacts")
	}
	if err := os.WriteFile(filepath.Join(root, "fixture.jar"), []byte("metadata fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	if java, artifacts, err := inspectApplicationInput(context.Background(), root, false); err != nil || !java || !artifacts {
		t.Fatal(java, artifacts, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := inspectApplicationInput(ctx, root, false); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func FuzzParsers(f *testing.F) {
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"Results":[]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			t.Skip()
		}
		_, _ = ValidateTemplate(data)
		_, _ = ParseNuclei(data, []string{"192.0.2.1:80"})
		_, _ = ParseTrivy(data, "fixture")
		_, _ = ParseZAP(data, []string{"192.0.2.1:80"})
	})
}

func TestEngineProcessHelper(t *testing.T) {
	if len(os.Args) == 0 || os.Args[len(os.Args)-1] != "engine-deadline-helper" {
		return
	}
	time.Sleep(time.Hour)
}

func TestEngineSubprocessIsKilledAtDeadline(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	start := time.Now()
	err = runProcess(ctx, executable, []string{"-test.run=^TestEngineProcessHelper$", "--", "engine-deadline-helper"}, t.TempDir(), io.Discard)
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > 3*time.Second {
		t.Fatalf("deadline did not terminate subprocess: %v elapsed %s", err, time.Since(start))
	}
}
