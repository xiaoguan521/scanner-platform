package executor

import (
	"context"
	"net"
	"os"
	"testing"

	"scanner-platform/internal/portprobe"
	"scanner-platform/internal/taskflow"
)

func TestAutoScanEndsEarlyWhenNoPortIsOpen(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("scanning Worker must not run as root")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close() // the port is now closed

	var phases []string
	ctx := taskflow.WithProgressReporter(context.Background(), func(p taskflow.TaskProgress) { phases = append(phases, p.Phase) })
	task := taskflow.Task{
		Engines: []string{"auto"}, AssetID: "asset-1",
		Chunks:             []taskflow.Chunk{{Targets: []string{"127.0.0.1"}}},
		PortProbeConfig:    portprobe.Config{Preset: "custom", Ranges: []portprobe.Range{{Start: port, End: port}}, OpsApproved: true},
		PortProbePorts:     []int{port},
		VulnerabilityPorts: []int{port},
	}
	result, err := (&Runner{}).AutoScan(ctx, task)
	if err != nil {
		t.Fatalf("AutoScan: %v", err)
	}
	if len(result.Ports) != 0 || len(result.Findings) != 0 || len(result.ExecutedEngines) != 0 {
		t.Fatalf("expected an empty result, got %+v", result)
	}
	if result.SystemStatus != taskflow.SystemScanNotConfigured || result.ApplicationStatus != taskflow.ApplicationScanNotConfigured {
		t.Fatalf("statuses = %q / %q", result.SystemStatus, result.ApplicationStatus)
	}
	for _, phase := range phases {
		switch phase {
		case "http_scan", "ssh_collection", "trivy_scan", "application_scan":
			t.Fatalf("later phase %q started although no port was open", phase)
		}
	}
}
