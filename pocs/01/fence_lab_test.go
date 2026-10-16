//go:build linux && lab

package poc01

import (
	"context"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"scanner-platform/internal/scope"
	"scanner-platform/internal/workerfence"
)

// TestIsolatedFenceInstall is opt-in. Parent enters a BRAND NEW network
// namespace with unshare before applying any firewall changes.
// This intentionally does not contact a real network or run Nuclei/Trivy.
func TestIsolatedFenceInstall(t *testing.T) {
	if os.Getenv("LAB_ENV") != "isolated" {
		t.Skip("requires an explicitly approved isolated lab")
	}
	if os.Getenv("_POC01_UNSHARE_CHILD") != "1" {
		parentNS, err := os.Open("/proc/self/ns/net")
		if err != nil {
			t.Fatal(err)
		}
		defer parentNS.Close()
		child := exec.Command("unshare", "--user", "--map-root-user", "--net", os.Args[0], "-test.run=^TestIsolatedFenceInstall$", "-test.v")
		child.ExtraFiles = []*os.File{parentNS}
		child.Env = append(os.Environ(), "_POC01_UNSHARE_CHILD=1")
		out, err := child.CombinedOutput()
		if err != nil {
			t.Fatalf("unshare isolated lab child failed: %v: %s", err, out)
		}
		return
	}

	// fd 3 can only be trusted after the installer validates it as nsfs
	// AND different from the current namespace (see nft_linux.go).
	parentNS := os.NewFile(3, "parent-network-namespace")
	if parentNS == nil {
		t.Fatal("parent namespace fd unavailable")
	}
	defer parentNS.Close()
	p := workerfence.Plan{
		Decision: scope.Decision{
			Status:       "READY",
			HardDeadline: time.Now().Add(time.Minute),
			Targets:      []scope.Endpoint{{IP: netip.MustParseAddr("192.0.2.10"), Port: 443}},
		},
		Infrastructure: []workerfence.Permit{{
			Endpoint: scope.Endpoint{IP: netip.MustParseAddr("198.51.100.7"), Port: 8443},
			Protocol: workerfence.TCP,
		}},
	}
	rules, err := workerfence.Rules(p, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	nft := os.Getenv("LAB_NFT_PATH")
	if nft == "" {
		nft = "/usr/sbin/nft"
	}
	if err := workerfence.NewConfigurator(nft, parentNS).Apply(context.Background(), rules); err != nil {
		t.Fatalf("nft atomic installation failed in new netns: %v", err)
	}
	result, err := exec.Command(nft, "list", "chain", "inet", "sec_scan_fence", "egress").CombinedOutput()
	if err != nil {
		t.Fatalf("nft policy readback failed: %v", err)
	}
	for _, required := range []string{"policy drop", "192.0.2.10", "198.51.100.7", "counter packets"} {
		if !strings.Contains(string(result), required) {
			t.Errorf("nft readback is missing %q", required)
		}
	}
}
