package bootstrap

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"scanner-platform/internal/scope"
	"scanner-platform/internal/taskflow"
	"scanner-platform/internal/workerfence"
)

// fencePermitWire is deliberately narrower than workerfence.Permit so the
// child protocol cannot receive arbitrary nft syntax or a raw address type.
type fencePermitWire struct {
	IP       string               `json:"ip"`
	Port     uint16               `json:"port"`
	Protocol workerfence.Protocol `json:"protocol"`
}

type fencedRunnerConfig struct {
	Executable     string
	NftPath        string
	SetprivPath    string
	ParentNetNSFD  int
	CgroupRoot     string
	CgroupPath     string
	Infrastructure []workerfence.Permit `json:"-"`
	BinDir         string
	RulesDir       string
	RuntimeDir     string
	InputsDir      string
	SSHConfigPath  string
	Rate           int
	Timeout        int
}

type fencedTaskRunner struct{ config fencedRunnerConfig }

type fencedTaskInput struct {
	Operation string             `json:"operation"`
	Task      taskflow.Task      `json:"task"`
	Config    fencedRunnerConfig `json:"config"`
	Infra     []fencePermitWire  `json:"infrastructure"`
}

type fencedTaskOutput struct {
	Status      string                     `json:"status"`
	FenceStatus string                     `json:"fenceStatus,omitempty"`
	DropCount   uint64                     `json:"dropCount,omitempty"`
	Detections  []taskflow.Detection       `json:"detections,omitempty"`
	Ports       []taskflow.PortProbeResult `json:"ports,omitempty"`
	Auto        taskflow.AutoResult        `json:"auto,omitempty"`
}

func (r *fencedTaskRunner) Execute(ctx context.Context, task taskflow.Task) ([]taskflow.Detection, error) {
	out, err := r.run(ctx, "execute", task)
	return out.Detections, err
}

func (r *fencedTaskRunner) ProbePorts(ctx context.Context, task taskflow.Task) ([]taskflow.PortProbeResult, error) {
	out, err := r.run(ctx, "probe-ports", task)
	return out.Ports, err
}

func (r *fencedTaskRunner) AutoScan(ctx context.Context, task taskflow.Task) (taskflow.AutoResult, error) {
	out, err := r.run(ctx, "auto", task)
	return out.Auto, err
}

func permitWire(permit workerfence.Permit) fencePermitWire {
	return fencePermitWire{IP: permit.Endpoint.IP.String(), Port: permit.Endpoint.Port, Protocol: permit.Protocol}
}

func permitsWire(permits []workerfence.Permit) []fencePermitWire {
	out := make([]fencePermitWire, len(permits))
	for i, permit := range permits {
		out[i] = permitWire(permit)
	}
	return out
}

func parseFencePermit(raw string) (workerfence.Permit, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return workerfence.Permit{}, fmt.Errorf("empty infrastructure permit")
	}
	protocol := workerfence.TCP
	address := raw
	for _, prefix := range []struct {
		name  string
		value workerfence.Protocol
	}{
		{name: "tcp://", value: workerfence.TCP},
		{name: "udp://", value: workerfence.UDP},
	} {
		if strings.HasPrefix(raw, prefix.name) {
			protocol, address = prefix.value, strings.TrimPrefix(raw, prefix.name)
			break
		}
	}
	endpoint, err := scope.ParseEndpoint(address)
	if err != nil {
		return workerfence.Permit{}, fmt.Errorf("invalid infrastructure permit %q: %w", raw, err)
	}
	return workerfence.Permit{Endpoint: endpoint, Protocol: protocol}, nil
}

func parseFenceInfrastructure(serverAddress, extra string) ([]workerfence.Permit, error) {
	values := []string{serverAddress}
	if strings.TrimSpace(extra) != "" {
		values = append(values, strings.Split(extra, ",")...)
	}
	permits := make([]workerfence.Permit, 0, len(values))
	seen := make(map[string]bool, len(values))
	for _, raw := range values {
		permit, err := parseFencePermit(raw)
		if err != nil {
			return nil, err
		}
		key := permit.Endpoint.String() + "/" + string(permit.Protocol)
		if seen[key] {
			continue
		}
		seen[key] = true
		permits = append(permits, permit)
	}
	return permits, nil
}

func endpointForHost(host string, port int) (scope.Endpoint, error) {
	ip, err := netip.ParseAddr(strings.TrimSpace(host))
	if err != nil || !ip.IsValid() || ip.IsUnspecified() || ip.IsMulticast() || port < 1 || port > 65535 {
		return scope.Endpoint{}, fmt.Errorf("numeric target and valid port required")
	}
	return scope.Endpoint{IP: ip.Unmap(), Port: uint16(port)}, nil
}

// fencePlanForTask converts only the already Server-resolved task projection
// into exact permits. It never expands a hostname, CIDR or port range.
func fencePlanForTask(task taskflow.Task, infrastructure []workerfence.Permit) (workerfence.Plan, error) {
	if len(task.Engines) != 1 || len(task.Chunks) != 1 || len(infrastructure) == 0 {
		return workerfence.Plan{}, fmt.Errorf("fence requires one engine, one task chunk and infrastructure permits")
	}
	deadline, err := time.Parse(time.RFC3339Nano, task.HardDeadline)
	if err != nil || !deadline.After(time.Now()) {
		return workerfence.Plan{}, fmt.Errorf("task hard deadline is missing or expired")
	}
	decision := scope.Decision{Status: "READY", HardDeadline: deadline}
	engine := task.Engines[0]
	switch engine {
	case "port-probe", "auto":
		if len(task.Chunks[0].Targets) != 1 {
			return workerfence.Plan{}, fmt.Errorf("single-host task target required")
		}
		for _, port := range task.PortProbePorts {
			endpoint, err := endpointForHost(task.Chunks[0].Targets[0], port)
			if err != nil {
				return workerfence.Plan{}, fmt.Errorf("invalid task target: %w", err)
			}
			decision.Targets = append(decision.Targets, endpoint)
		}
	case "trivy":
		// Trivy runs against an offline rootfs/image/artifact input. It does
		// not need a target permit; the trusted adapter marks this plan offline.
		if task.InputPath == "" || task.InputKind == "" {
			return workerfence.Plan{}, fmt.Errorf("offline Trivy input required")
		}
	case "nuclei", "zap":
		for _, target := range task.Chunks[0].Targets {
			endpoint, err := scope.ParseEndpoint(target)
			if err != nil {
				return workerfence.Plan{}, fmt.Errorf("invalid task target %q: %w", target, err)
			}
			decision.Targets = append(decision.Targets, endpoint)
		}
	default:
		return workerfence.Plan{}, fmt.Errorf("engine %q is not fence-enabled", engine)
	}
	if len(decision.Targets) == 0 && engine != "trivy" {
		return workerfence.Plan{}, fmt.Errorf("network task has no exact target permits")
	}
	return workerfence.Plan{Decision: decision, Infrastructure: infrastructure, Offline: engine == "trivy"}, nil
}

func parseWirePermits(values []fencePermitWire) ([]workerfence.Permit, error) {
	permits := make([]workerfence.Permit, 0, len(values))
	for _, value := range values {
		endpoint, err := scope.ParseEndpoint(net.JoinHostPort(value.IP, strconv.Itoa(int(value.Port))))
		if err != nil {
			return nil, fmt.Errorf("invalid serialized infrastructure permit: %w", err)
		}
		if value.Protocol != workerfence.TCP && value.Protocol != workerfence.UDP {
			return nil, fmt.Errorf("invalid serialized infrastructure protocol")
		}
		permits = append(permits, workerfence.Permit{Endpoint: endpoint, Protocol: value.Protocol})
	}
	return permits, nil
}
