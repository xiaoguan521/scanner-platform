package portable

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"net/http/cookiejar"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"scanner-platform/internal/webui"
)

func TestResolveLayoutUsesHome(t *testing.T) {
	home := t.TempDir()
	layout, err := ResolveLayout(home)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"bin": layout.Bin, "vuln-data": layout.Rules, "config": layout.Config,
		filepath.Join("runtime", "platform.db"): layout.Database, filepath.Join("runtime", "portable.lock"): layout.LockFile,
		filepath.Join("config", "ssh-config.json"): layout.SSHConfig, filepath.Join("config", "trusted-rule-keys"): layout.TrustedRuleKeysDir,
	}
	for relative, got := range want {
		if got != filepath.Join(home, relative) {
			t.Fatalf("%s resolved to %s", relative, got)
		}
	}
}

func TestPrepareCreatesOwnerOnlyRuntime(t *testing.T) {
	layout, _ := ResolveLayout(t.TempDir())
	if err := os.MkdirAll(layout.Runtime, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := layout.Prepare(); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{layout.Rules, layout.WorkerRuntime, layout.Inputs, layout.Logs, layout.Reports} {
		if info, err := os.Stat(dir); err != nil || !info.IsDir() {
			t.Fatalf("%s missing: %v", dir, err)
		}
	}
	if runtime.GOOS == "windows" {
		return
	}
	if info, _ := os.Stat(layout.Runtime); info.Mode().Perm() != 0o700 {
		t.Fatalf("runtime mode %v, want 0700 even when it already existed", info.Mode().Perm())
	}
	if _, err := os.Stat(layout.Bin); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("Prepare must not create bin/; engines come with the package")
	}
}

func TestLockRefusesSecondInstance(t *testing.T) {
	path := filepath.Join(t.TempDir(), "portable.lock")
	release, err := acquireLock(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := acquireLock(path); !errors.Is(err, errAlreadyRunning) {
		t.Fatalf("second lock: %v", err)
	}
	release()
	again, err := acquireLock(path)
	if err != nil {
		t.Fatalf("lock not released: %v", err)
	}
	again()
}

func TestLoopbackAddressOnly(t *testing.T) {
	for _, ok := range []string{"127.0.0.1:8080", "127.0.0.1:0", "[::1]:8080"} {
		if err := loopbackAddress(ok); err != nil {
			t.Fatalf("%s rejected: %v", ok, err)
		}
	}
	for _, bad := range []string{"0.0.0.0:8080", ":8080", "192.0.2.10:8080", "localhost:8080", "[::]:8080", "127.0.0.1"} {
		if err := loopbackAddress(bad); err == nil {
			t.Fatalf("%s accepted", bad)
		}
	}
}

func TestTokensAreRandomAndURLSafe(t *testing.T) {
	first, err := newToken()
	if err != nil {
		t.Fatal(err)
	}
	second, _ := newToken()
	if first == second || len(first) != 43 || strings.ContainsAny(first, "+/=") {
		t.Fatalf("tokens %q %q", first, second)
	}
}

// TestRunStartsAllComponents starts the real Server, Worker and Updater in a
// temporary directory, without engines or network access beyond loopback.
func TestRunStartsAllComponents(t *testing.T) {
	home := t.TempDir()
	uiDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(uiDir, "index.html"), []byte("<!doctype html><title>portable-test</title>"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var issuedMu sync.Mutex
	var issued []string
	tokenSource = func() (string, error) {
		token, err := newToken()
		issuedMu.Lock()
		issued = append(issued, token)
		issuedMu.Unlock()
		return token, err
	}
	defer func() { tokenSource = newToken }()
	ready := make(chan string, 1)
	var stdout, stderr lockedBuffer
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, Options{Home: home, Listen: "127.0.0.1:0", UIDir: uiDir, ReadyTimeout: 20 * time.Second, Ready: func(url string) { ready <- url }}, &stdout, &stderr)
	}()
	var base string
	select {
	case base = <-ready:
	case err := <-done:
		t.Fatalf("Run ended early: %v\n%s", err, stderr.String())
	case <-time.After(30 * time.Second):
		t.Fatal("Run did not become ready")
	}
	base = strings.TrimSuffix(base, "/")
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Timeout: 5 * time.Second, Jar: jar}

	if body := get(t, client, base+"/"); !strings.Contains(body, "portable-test") {
		t.Fatalf("UI not served: %q", body)
	}
	// Node API needs this run's token, even from the same machine.
	request, _ := http.NewRequest(http.MethodPost, base+"/api/v1/worker/claim", strings.NewReader("{}"))
	request.Header.Set("X-Node-ID", workerID)
	request.Header.Set("Authorization", "Bearer guessed")
	request.Header.Set("Content-Type", "application/json")
	if response, err := client.Do(request); err != nil || response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated node request: %v %v", response, err)
	}

	// A second copy on the same directory must refuse to start.
	if err := Run(context.Background(), Options{Home: home, Listen: "127.0.0.1:0", UIDir: uiDir}, io.Discard, io.Discard); !errors.Is(err, errAlreadyRunning) {
		t.Fatalf("second instance: %v", err)
	}

	// The in-process Worker and Updater authenticate with their tokens.
	post(t, client, base+"/api/v1/auth/setup", `{"username":"portable_admin","password":"portable-test-password-1"}`, http.StatusCreated)
	post(t, client, base+"/api/v1/auth/login", `{"username":"portable_admin","password":"portable-test-password-1"}`, http.StatusOK)
	deadline := time.Now().Add(15 * time.Second)
	for {
		var nodes struct {
			Items []struct {
				ID string `json:"id"`
			} `json:"items"`
		}
		_ = json.Unmarshal([]byte(get(t, client, base+"/api/v1/nodes")), &nodes)
		seen := map[string]bool{}
		for _, node := range nodes.Items {
			seen[node.ID] = true
		}
		if seen[workerID] && seen[updaterID] {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("nodes did not report in: %+v\n%s", nodes, stderr.String())
		}
		time.Sleep(200 * time.Millisecond)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned %v\n%s", err, stderr.String())
		}
	case <-time.After(15 * time.Second):
		t.Fatal("Run did not stop after cancel")
	}
	issuedMu.Lock()
	defer issuedMu.Unlock()
	if len(issued) != 2 || issued[0] == issued[1] {
		t.Fatalf("want two distinct tokens, got %d", len(issued))
	}
	assertNoTokensOnDisk(t, home, issued, stdout.String()+stderr.String())
}

// assertNoTokensOnDisk checks that no file under home (database and log
// included) and no console output contains a token issued for this run.
func assertNoTokensOnDisk(t *testing.T, home string, tokens []string, console string) {
	t.Helper()
	_ = filepath.WalkDir(home, func(path string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return nil
		}
		data, _ := os.ReadFile(path)
		for _, token := range tokens {
			if bytes.Contains(data, []byte(token)) {
				t.Fatalf("%s contains a node token", path)
			}
		}
		return nil
	})
	for _, token := range tokens {
		if strings.Contains(console, token) {
			t.Fatal("console output contains a node token")
		}
	}
	log, _ := os.ReadFile(filepath.Join(home, "runtime", "logs", "portable.log"))
	if !bytes.Contains(log, []byte("portable started")) {
		t.Fatalf("log file not written: %q", log)
	}
}

func get(t *testing.T, client *http.Client, url string) string {
	t.Helper()
	response, err := client.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	return string(body)
}

func post(t *testing.T, client *http.Client, url, body string, want int) {
	t.Helper()
	request, _ := http.NewRequest(http.MethodPost, url, strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Requested-With", "XMLHttpRequest")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != want {
		data, _ := io.ReadAll(response.Body)
		t.Fatalf("POST %s: %d %s", url, response.StatusCode, data)
	}
}

type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func TestStatusReportsLayoutWithoutStarting(t *testing.T) {
	home := t.TempDir()
	var stdout, stderr bytes.Buffer
	if code := Main([]string{"--status", "--home", home}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	var status map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &status); err != nil {
		t.Fatal(err)
	}
	if status["mode"] != "portable" || status["home"] != home || status["networkFence"] != false || status["rulesActivated"] != false {
		t.Fatalf("status %v", status)
	}
	if _, err := os.Stat(filepath.Join(home, "runtime")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("--status must not create directories")
	}
}

func TestRunRejectsNonLoopbackAndMissingUI(t *testing.T) {
	if err := Run(context.Background(), Options{Home: t.TempDir(), Listen: "0.0.0.0:8080"}, io.Discard, io.Discard); err == nil || !strings.Contains(err.Error(), "loopback") {
		t.Fatalf("non-loopback: %v", err)
	}
	if code := Main([]string{"--home", t.TempDir(), "--listen", "192.0.2.10:8080", "--no-browser"}, io.Discard, io.Discard); code != 1 {
		t.Fatalf("Main accepted a non-loopback address: %d", code)
	}
	if _, embedded := webuiEmbedded(); embedded {
		t.Skip("binary was built with the embedded UI")
	}
	err := Run(context.Background(), Options{Home: t.TempDir(), Listen: "127.0.0.1:0"}, io.Discard, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "make portable") {
		t.Fatalf("missing UI: %v", err)
	}
}

func webuiEmbedded() (http.FileSystem, bool) { return webui.FileSystem() }

func TestSupervisorIgnoresErrorsAfterShutdown(t *testing.T) {
	// A request cut off by Ctrl+C must not turn a clean stop into a failure.
	ctx, cancel := context.WithCancel(context.Background())
	group := newSupervisor(ctx, cancel)
	stopping := make(chan struct{})
	group.start("worker", func() error {
		<-stopping
		return errors.New("call task API: interrupt signal received")
	})
	cancel()
	close(stopping)
	if err := group.wait(); err != nil {
		t.Fatalf("clean stop reported %v", err)
	}

	// An exit before shutdown stops everything and is reported once.
	ctx, cancel = context.WithCancel(context.Background())
	group = newSupervisor(ctx, cancel)
	group.start("updater", func() error { return errors.New("rule directory unreadable") })
	group.start("worker", func() error { <-ctx.Done(); return ctx.Err() })
	err := group.wait()
	if err == nil || !strings.Contains(err.Error(), "updater: rule directory unreadable") || ctx.Err() == nil {
		t.Fatalf("failure not propagated: %v", err)
	}
}
