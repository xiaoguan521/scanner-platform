package executor

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"scanner-platform/internal/inventory"
	"scanner-platform/internal/portprobe"
)

func TestHTTPInventoryAndSameEndpointLoginLinks(t *testing.T) {
	var requests atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1) }))
	defer other.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.24.0")
		w.Header().Set("X-Powered-By", "PHP/8.2.1")
		fmt.Fprintf(w, `<title>Example &amp; login</title><form><input type="password"></form><a href="/login">Login</a><a href="%s/login">Other</a>`, other.URL)
	}))
	defer server.Close()
	host, rawPort, _ := net.SplitHostPort(server.Listener.Addr().String())
	port, _ := strconv.Atoi(rawPort)
	result := identifyService(context.Background(), host, port, time.Second, 2, 2, &identificationBudget{remaining: 2})
	if result.Kind != "HTTP" || result.Software != "nginx" || result.Version != "1.24.0" || result.Language != "PHP" || result.Title != "Example & login" || len(result.LoginEntries) != 2 || result.Quarantined {
		t.Fatalf("inventory=%+v", result)
	}
	for _, entry := range result.LoginEntries {
		if !strings.HasPrefix(entry.URL, server.URL) || entry.Captcha != nil || entry.AntiBruteForce != nil {
			t.Fatalf("login entry=%+v", entry)
		}
	}
	if requests.Load() != 0 {
		t.Fatal("followed external link")
	}
}

func TestInventoryRedirectDoesNotConnectElsewhere(t *testing.T) {
	var calls atomic.Int32
	external := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }))
	defer external.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, external.URL+"/login", 302) }))
	defer server.Close()
	host, p, _ := net.SplitHostPort(server.Listener.Addr().String())
	port, _ := strconv.Atoi(p)
	result := identifyService(context.Background(), host, port, time.Second, 2, 2, &identificationBudget{remaining: 2})
	if result.Kind != "HTTP" || calls.Load() != 0 || len(result.LoginEntries) != 0 {
		t.Fatal(result, calls.Load())
	}
}

func TestBannerInventoryUsesOneConnectionAndDoesNotLogin(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan string, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		fmt.Fprint(conn, "SSH-2.0-OpenSSH_9.6p1\r\n")
		conn.SetReadDeadline(time.Now().Add(time.Second))
		buf := make([]byte, 128)
		n, _ := conn.Read(buf)
		done <- string(buf[:n])
	}()
	host, p, _ := net.SplitHostPort(listener.Addr().String())
	port, _ := strconv.Atoi(p)
	budget := &identificationBudget{remaining: 2}
	result := identifyService(context.Background(), host, port, time.Second, 2, 2, budget)
	if result.ServiceName != "ssh" || result.Version != "9.6p1" || len(result.LoginEntries) != 1 || result.LoginEntries[0].Type != "system" || budget.remaining != 1 {
		t.Fatal(result, budget.remaining)
	}
	if sent := <-done; sent != "" {
		t.Fatalf("sent application data to SSH: %q", sent)
	}
}

func TestUnknownServiceIsNotAutomaticallyQuarantined(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			fmt.Fprint(conn, "CUSTOM protocol ready\r\n")
			conn.Close()
		}
	}()
	host, p, _ := net.SplitHostPort(listener.Addr().String())
	port, _ := strconv.Atoi(p)
	result := identifyService(context.Background(), host, port, 100*time.Millisecond, 2, 2, &identificationBudget{remaining: 2})
	if result.Kind != "OTHER" || result.Quarantined {
		t.Fatal(result)
	}
}

func TestServiceIdentificationBudgetAndLargePortList(t *testing.T) {
	ports := make([]int, 300)
	for i := range ports {
		ports[i] = i + 1
	}
	results := identifyServices(context.Background(), "192.0.2.20", ports, portprobe.Config{IdentificationMaxAttempts: 1})
	if len(results) != len(ports) {
		t.Fatalf("ports truncated at %d", len(results))
	}
	budget := &identificationBudget{remaining: 0}
	result := identifyService(context.Background(), "192.0.2.20", 80, time.Second, 2, 2, budget)
	if result.State != "unidentified" || result.Quarantined {
		t.Fatal(result)
	}
}

func TestProfileFromCollectedMetadata(t *testing.T) {
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "etc"), 0700)
	os.WriteFile(filepath.Join(root, "etc", "os-release"), []byte("ID=example\nPRETTY_NAME=\"Example Linux 1\"\n"), 0600)
	p := profileFromRootfs(root)
	if p.OSFamily != "Linux" || p.OSName != "Example Linux 1" {
		t.Fatal(p)
	}
	if p := inferProfile([]inventory.Service{{Software: "openssh", Version: "9.6"}}); p.OSFamily != "" {
		t.Fatal("guessed OS from SSH", p)
	}
}

func FuzzHTTPInventory(f *testing.F) {
	f.Add("<title>hello</title>", "nginx/1.24.0")
	f.Fuzz(func(t *testing.T, body, server string) {
		if len(body) > 64<<10 || len(server) > 4096 {
			return
		}
		s := inventory.Service{Port: 80}
		applyHTTPInventory(&s, capturedResponse{URL: "http://192.0.2.20:80/", Headers: http.Header{"Server": []string{server}}, Body: []byte(body)})
		if len(s.LoginEntries) > 10 || len(s.Title) > 1200 {
			t.Fatal("unbounded inventory")
		}
	})
}

func TestExplicitProxyProtocolBannerIsQuarantined(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		fmt.Fprint(conn, "ERROR: proxy protocol required\r\n")
	}()
	host, p, _ := net.SplitHostPort(listener.Addr().String())
	port, _ := strconv.Atoi(p)
	budget := &identificationBudget{remaining: 2}
	result := identifyService(context.Background(), host, port, time.Second, 2, 2, budget)
	if !result.Quarantined || result.Scheme != "" || result.QuarantineReason == "" || budget.remaining != 1 {
		t.Fatal(result, budget.remaining)
	}
}
