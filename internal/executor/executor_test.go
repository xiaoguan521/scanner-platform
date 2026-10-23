package executor

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"scanner-platform/internal/executor/engineflags"
	"scanner-platform/internal/portprobe"
	"scanner-platform/internal/rules"
)

func TestProbePlanAllowsOnlyServerNarrowing(t *testing.T) {
	config := portprobe.Config{Preset: portprobe.PresetCustom, Ranges: []portprobe.Range{{Start: 8000, End: 8100}}, OpsApproved: true}
	if !validProbePortPlan(config, []int{8000, 8002, 8100}) {
		t.Fatal("server-filtered subset should be accepted")
	}
	for _, ports := range [][]int{
		{7999, 8000},
		{8000, 8000},
		{8002, 8001},
		{},
	} {
		if validProbePortPlan(config, ports) {
			t.Errorf("invalid or expanded port plan accepted: %v", ports)
		}
	}
}

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
	}{{target.URL, 204}, {"http://192.0.2.12:80/", 403}, {"http://example.com:80/", 403}, {target.URL + "/other", 204}} {
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
	// A non-GET method is still denied as request_not_allowed.
	post, err := client.Post(target.URL, "text/plain", strings.NewReader(""))
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, post.Body)
	post.Body.Close()
	if post.StatusCode != 403 {
		t.Fatalf("non-GET method not denied: %d", post.StatusCode)
	}
	if called != 2 {
		t.Fatalf("unexpected target calls: %d", called)
	}
	blocked, failed, summary := proxy.blockedSummary()
	if blocked != 3 || failed != 0 || summary != "invalid_authority=1,endpoint_not_authorized=1,request_not_allowed=1" {
		t.Fatalf("unexpected redacted proxy diagnostics: blocked=%d failed=%d summary=%q", blocked, failed, summary)
	}
	if strings.Contains(summary, "192.0.2.12") || strings.Contains(summary, "example.com") {
		t.Fatalf("proxy diagnostics leaked an authority: %q", summary)
	}
}

func TestScopeProxyCanonicalizesDefaultPortsWithoutConnecting(t *testing.T) {
	tests := []struct {
		name       string
		target     string
		allowed    string
		wantTarget string
		wantReason string
	}{
		{name: "http default port", target: "http://192.0.2.20/", allowed: "192.0.2.20:80", wantTarget: "192.0.2.20:80"},
		{name: "https default port", target: "https://[2001:db8::20]/", allowed: "[2001:db8::20]:443", wantTarget: "[2001:db8::20]:443"},
		{name: "explicit port retained", target: "http://192.0.2.20:8080/", allowed: "192.0.2.20:8080", wantTarget: "192.0.2.20:8080"},
		{name: "default does not widen port scope", target: "http://192.0.2.20/", allowed: "192.0.2.20:8080", wantReason: "endpoint_not_authorized"},
		{name: "hostname rejected", target: "http://audit.example.test/", allowed: "192.0.2.20:80", wantReason: "invalid_authority"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, test.target, nil)
			proxy := &scopeProxy{allowed: map[string]bool{test.allowed: true}}
			got, reason := proxy.authorizeRequest(request)
			if got != test.wantTarget || reason != test.wantReason {
				t.Fatalf("authorizeRequest() = (%q, %q), want (%q, %q)", got, reason, test.wantTarget, test.wantReason)
			}
		})
	}
}

func TestScopeProxyForwardsDefaultHTTPPortToExactEndpoint(t *testing.T) {
	const endpoint = "192.0.2.20:80"
	proxy, err := startScopeProxy(context.Background(), []string{endpoint})
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	dialed := make(chan string, 1)
	proxy.transport.DialContext = func(_ context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" {
			return nil, fmt.Errorf("unexpected network %q", network)
		}
		dialed <- address
		clientConn, serverConn := net.Pipe()
		go func() {
			defer serverConn.Close()
			request, readErr := http.ReadRequest(bufio.NewReader(serverConn))
			if readErr != nil {
				return
			}
			if request.Body != nil {
				_, _ = io.Copy(io.Discard, request.Body)
				_ = request.Body.Close()
			}
			_, _ = io.WriteString(serverConn, "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
		}()
		return clientConn, nil
	}
	proxyURL, err := url.Parse(proxy.URL())
	if err != nil {
		t.Fatal(err)
	}
	transport := &http.Transport{Proxy: http.ProxyURL(proxyURL), DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport}
	response, err := client.Get("http://192.0.2.20/")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("unexpected response status: %d", response.StatusCode)
	}
	if got := <-dialed; got != endpoint {
		t.Fatalf("proxy dialed %q, want exact authorized endpoint %q", got, endpoint)
	}
	blocked, failed, summary := proxy.blockedSummary()
	if blocked != 0 || failed != 0 || summary != "" {
		t.Fatalf("default-port request was rejected: blocked=%d failed=%d summary=%q", blocked, failed, summary)
	}
}

func TestScopeProxyRequiresExplicitConnectPort(t *testing.T) {
	for _, authority := range []string{"192.0.2.20", "[2001:db8::20]"} {
		if _, err := canonicalProxyTarget(authority, "https", true); err == nil {
			t.Fatalf("CONNECT authority without a port was accepted: %q", authority)
		}
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
