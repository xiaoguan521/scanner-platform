// Package workerfence constructs a fail-closed, per-worker Linux egress
// allowlist. Nothing in this package discovers or scans network assets.
package workerfence

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"scanner-platform/internal/scope"
)

type Protocol string

const (
	TCP Protocol = "tcp"
	UDP Protocol = "udp"
	// A single explicitly authorized full-TCP-port task contains up to 65535
	// target permits. Keep room for the fixed infrastructure allowlist while
	// retaining a hard upper bound on generated rule size.
	maxPermits = 65535 + 512
)

// Permit is a precise protocol+numeric-IP+port authorization.
// Infrastructure permits must be set by trusted operator configuration.
type Permit struct {
	Endpoint scope.Endpoint
	Protocol Protocol
}

// Plan is passed only after a Server-approved scope.Admit decision.
// No raw domain name, CIDR, port range or default DNS permit is supported.
type Plan struct {
	Decision       scope.Decision
	Infrastructure []Permit
	// Offline permits a local, non-network engine task to run with only the
	// control-plane/infrastructure allowlist. It is set by the trusted worker
	// adapter, never by task JSON received from the Server.
	Offline bool
}

func checkedEndpoint(e scope.Endpoint) (netip.Addr, error) {
	ip := e.IP
	if !ip.IsValid() || ip.IsUnspecified() || ip.IsMulticast() || ip.Is4In6() || ip.Zone() != "" || e.Port == 0 {
		return netip.Addr{}, errors.New("invalid numeric IP:port")
	}
	return ip, nil
}

// RuleSet can only contain generated, validated rules. Its script field is
// unexported so consumers cannot pass arbitrary nft commands to a configurator.
type RuleSet struct{ script string }

// String is intended for audits and read-only testing, never arbitrary input.
func (r RuleSet) String() string { return r.script }

// Rules validates all permits before rendering. The nft transaction is
// exclusive to the worker's network namespace; never run it on a host netns.
func Rules(p Plan, now time.Time) (RuleSet, error) {
	if p.Decision.Status != "READY" || !p.Decision.HardDeadline.After(now) {
		return RuleSet{}, errors.New("worker was not admitted or deadline expired")
	}
	if len(p.Infrastructure) == 0 {
		return RuleSet{}, errors.New("explicit infrastructure permits required")
	}
	if len(p.Decision.Targets) == 0 && !p.Offline {
		return RuleSet{}, errors.New("targets required for network task")
	}
	if len(p.Decision.Targets)+len(p.Infrastructure) > maxPermits {
		return RuleSet{}, errors.New("permit count exceeds fixed safety limit")
	}

	permits := make(map[string]Permit, len(p.Decision.Targets)+len(p.Infrastructure))
	add := func(permit Permit) error {
		ip, err := checkedEndpoint(permit.Endpoint)
		if err != nil {
			return err
		}
		if permit.Protocol != TCP && permit.Protocol != UDP {
			return errors.New("protocol must be exactly tcp or udp")
		}
		key := fmt.Sprintf("%s/%s", netip.AddrPortFrom(ip, permit.Endpoint.Port), permit.Protocol)
		if _, exists := permits[key]; exists {
			return errors.New("duplicate target/infrastructure permit")
		}
		permits[key] = permit
		return nil
	}
	for _, target := range p.Decision.Targets {
		if err := add(Permit{Endpoint: target, Protocol: TCP}); err != nil {
			return RuleSet{}, fmt.Errorf("invalid worker target: %w", err)
		}
	}
	for _, infra := range p.Infrastructure {
		if err := add(infra); err != nil {
			return RuleSet{}, fmt.Errorf("invalid infrastructure permit: %w", err)
		}
	}
	keys := make([]string, 0, len(permits))
	for k := range permits {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var out strings.Builder
	// A single nft -f batch is applied atomically. The fixed table name
	// intentionally fails if this namespace was already configured.
	out.WriteString("add table inet sec_scan_fence\n")
	out.WriteString("add chain inet sec_scan_fence egress { type filter hook output priority -150; policy drop; }\n")
	out.WriteString("add chain inet sec_scan_fence forward { type filter hook forward priority -150; policy drop; }\n")
	out.WriteString("add rule inet sec_scan_fence egress oifname \"lo\" counter accept\n")
	for _, key := range keys {
		permit := permits[key]
		family := "ip"
		if permit.Endpoint.IP.Is6() {
			family = "ip6"
		}
		// Address comes from netip, port from uint16, and protocol from enum:
		// no command/shell expressions or caller-defined nft syntax.
		fmt.Fprintf(&out, "add rule inet sec_scan_fence egress %s daddr %s %s dport %d counter accept\n",
			family, permit.Endpoint.IP, permit.Protocol, permit.Endpoint.Port)
	}
	out.WriteString("add rule inet sec_scan_fence egress counter drop\n")
	out.WriteString("add rule inet sec_scan_fence forward counter drop\n")
	return RuleSet{script: out.String()}, nil
}
