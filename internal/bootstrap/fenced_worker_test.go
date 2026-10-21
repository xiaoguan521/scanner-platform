package bootstrap

import (
	"strings"
	"testing"
	"time"

	"scanner-platform/internal/scope"
	"scanner-platform/internal/taskflow"
	"scanner-platform/internal/workerfence"
)

func fenceInfraFixture(t *testing.T) []workerfence.Permit {
	t.Helper()
	permits, err := parseFenceInfrastructure("198.51.100.10:8443", "udp://198.51.100.53:53")
	if err != nil {
		t.Fatal(err)
	}
	return permits
}

func TestFenceInfrastructureParsesExactIPPortsAndDeduplicates(t *testing.T) {
	permits, err := parseFenceInfrastructure("198.51.100.10:8443", "198.51.100.10:8443,udp://198.51.100.53:53")
	if err != nil {
		t.Fatal(err)
	}
	if len(permits) != 2 || permits[0].Protocol != workerfence.TCP || permits[1].Protocol != workerfence.UDP {
		t.Fatalf("permits = %#v", permits)
	}
	for _, input := range []string{"server.example:8443", "192.0.2.0/24:443", "198.51.100.10:0", "0.0.0.0:443"} {
		if _, err := parseFencePermit(input); err == nil {
			t.Fatalf("unsafe infrastructure permit accepted: %q", input)
		}
	}
}

func TestFencePlanUsesOnlyServerResolvedTaskTargets(t *testing.T) {
	task := taskflow.Task{
		HardDeadline:   time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano),
		Engines:        []string{"auto"},
		Chunks:         []taskflow.Chunk{{Targets: []string{"192.0.2.10"}}},
		PortProbePorts: []int{22, 18080},
	}
	plan, err := fencePlanForTask(task, fenceInfraFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Decision.Targets) != 2 || plan.Decision.Targets[0].String() != "192.0.2.10:22" || plan.Decision.Targets[1].String() != "192.0.2.10:18080" {
		t.Fatalf("target permits = %#v", plan.Decision.Targets)
	}
	if plan.Offline {
		t.Fatal("network task marked offline")
	}
	for _, target := range plan.Decision.Targets {
		if strings.Contains(target.String(), "192.0.2.0/24") {
			t.Fatal("CIDR expanded into fence plan")
		}
	}
}

func TestFencePlanRejectsUnresolvedTargetsAndAllowsOfflineTrivy(t *testing.T) {
	bad := taskflow.Task{
		HardDeadline: time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano),
		Engines:      []string{"nuclei"},
		Chunks:       []taskflow.Chunk{{Targets: []string{"target.example:443"}}},
	}
	if _, err := fencePlanForTask(bad, fenceInfraFixture(t)); err == nil {
		t.Fatal("hostname target accepted")
	}
	offline := taskflow.Task{
		HardDeadline: time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano),
		Engines:      []string{"trivy"},
		InputKind:    "rootfs",
		InputPath:    "fixture/rootfs",
		Chunks:       []taskflow.Chunk{{}},
	}
	plan, err := fencePlanForTask(offline, fenceInfraFixture(t))
	if err != nil || !plan.Offline || len(plan.Decision.Targets) != 0 {
		t.Fatalf("offline plan = %#v err=%v", plan, err)
	}
	if _, err := fencePlanForTask(taskflow.Task{Engines: []string{"trivy"}, InputKind: "rootfs", InputPath: "fixture/rootfs"}, fenceInfraFixture(t)); err == nil {
		t.Fatal("missing hard deadline accepted")
	}
}

func TestFencePlanUsesNumericScopeEndpointParser(t *testing.T) {
	if _, err := scope.ParseEndpoint("192.0.2.10:443"); err != nil {
		t.Fatal(err)
	}
}
