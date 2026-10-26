package executor

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestSharedBudgetStopsPreflightBeforeAnotherConnection(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); _, _ = w.Write([]byte("example")) }))
	defer server.Close()
	ctx := withHTTPBudget(context.Background(), 250, 1)
	if _, err := fetchRoot(ctx, server.URL, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := fetchRoot(ctx, server.URL, 1); err == nil {
		t.Fatal("budget exhaustion did not stop preflight")
	}
	if requests.Load() != 1 {
		t.Fatal("request crossed the budget")
	}
}

// Each template sends one GET per target, on top of the nuclei preflight root
// GET, the ZAP root fetch and the four native web configuration checks. A
// budget below that would fail every full-size rule bundle; the remaining
// headroom covers same-host redirects that nuclei follows with -fhr.
func TestHTTPBudgetCoversTemplateLimit(t *testing.T) {
	const fixedRequestsPerTarget = 1 + 1 + 4
	if maxBundledTemplates > maxTemplatesPerTask {
		t.Fatalf("bundled limit %d exceeds per-task limit %d", maxBundledTemplates, maxTemplatesPerTask)
	}
	if need := maxTemplatesPerTask + fixedRequestsPerTarget; maxHTTPRequestsPerTarget < need {
		t.Fatalf("HTTP budget %d cannot cover %d templates plus %d fixed requests", maxHTTPRequestsPerTarget, maxTemplatesPerTask, fixedRequestsPerTarget)
	}
}
func TestSilentOpenPortStaysUnidentifiedAfterBoundedIdentification(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var count atomic.Int64
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			count.Add(1)
			go func() { defer conn.Close(); <-ctx.Done() }()
		}
	}()
	port, _ := strconv.Atoi(strings.Split(listener.Addr().String(), ":")[1])
	service := identifyService(ctx, "127.0.0.1", port, 35*time.Millisecond, 2, 2, &identificationBudget{remaining: 2})
	// A silent service (XMPP, Redis, SOCKS...) fails an HTTP probe like a forwarder
	// does, so identification stays bounded but must not quarantine it persistently.
	if service.Quarantined || service.State != "unidentified" || count.Load() != 2 {
		t.Fatalf("silent open service must stay bounded, unidentified and not quarantined: %+v count=%d", service, count.Load())
	}
}

func TestTrivyMetadataKeepsEvidenceAndRealPublishedScore(t *testing.T) {
	raw := []byte(`{"Results":[{"Class":"lang-pkgs","Target":"package-lock.json","Vulnerabilities":[{"VulnerabilityID":"CVE-2099-0001","PkgName":"example","InstalledVersion":"1.0","FixedVersion":"2.0","Severity":"HIGH","Description":"Public advisory text","References":["https://example.org/advisory"],"CVSS":{"nvd":{"V3Score":9.1}}}]}]}`)
	detections, err := ParseTrivy(raw, "example-app")
	if err != nil || len(detections) != 1 {
		t.Fatal(detections, err)
	}
	d := detections[0]
	if d.CVSSScore == nil || *d.CVSSScore != 9.1 || d.DetectMethod != "version" || d.Description != "Public advisory text" || d.Solution == "" || len(d.References) != 1 || d.Evidence == "" {
		t.Fatalf("missing published metadata: %+v", d)
	}
}
