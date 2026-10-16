// Package scope provides fail-closed, network-free scan admission validation.
// Worker input is exclusively preapproved numeric IP:port endpoints.
package scope

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

type PortKind string

const (
	Web           PortKind = "WEB"
	NonWeb        PortKind = "NON_WEB"
	ExcludedProxy PortKind = "EXCLUDED_PROXY"
)

type Endpoint struct {
	IP   netip.Addr
	Port uint16
}

func (e Endpoint) String() string {
	return netip.AddrPortFrom(e.IP, e.Port).String()
}

// ParseEndpoint rejects hostnames, port ranges and CIDR expansion.
func ParseEndpoint(s string) (Endpoint, error) {
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		return Endpoint{}, fmt.Errorf("numeric IP:port required: %w", err)
	}
	ip := ap.Addr().Unmap()
	if !ip.IsValid() || ip.IsUnspecified() || ip.IsMulticast() || ap.Port() == 0 {
		return Endpoint{}, errors.New("prohibited address or port")
	}
	return Endpoint{IP: ip, Port: ap.Port()}, nil
}

type PortGrant struct {
	Endpoint    string
	Kind        PortKind
	Quarantined bool
}

type Window struct {
	Weekdays []time.Weekday
	Start    string // HH:MM inclusive
	End      string // HH:MM exclusive
	TimeZone string
}

type Policy struct {
	Approved       bool
	ApprovedBy     string
	ApprovalTicket string
	ExpiresAt      time.Time
	CIDRs          []netip.Prefix
	MaxTargets     int
	Ports          []PortGrant
	Windows        []Window
}

type Decision struct {
	// Only READY permits scheduling; WAITING_WINDOW never permits execution.
	Status       string
	Targets      []Endpoint
	HardDeadline time.Time
}

func inScope(prefixes []netip.Prefix, ip netip.Addr) bool {
	for _, p := range prefixes {
		if p.Contains(ip.Unmap()) {
			return true
		}
	}
	return false
}

// Admit atomically rejects a request containing even one unauthorized target.
// The function neither resolves DNS nor opens any network connection.
func Admit(ctx context.Context, p Policy, raw []string, now time.Time) (Decision, error) {
	if err := ctx.Err(); err != nil {
		return Decision{}, fmt.Errorf("admission canceled: %w", err)
	}
	if !p.Approved || strings.TrimSpace(p.ApprovedBy) == "" || strings.TrimSpace(p.ApprovalTicket) == "" {
		return Decision{}, errors.New("approval and change ticket required")
	}
	if !p.ExpiresAt.IsZero() && !now.Before(p.ExpiresAt) {
		return Decision{}, errors.New("scope expired")
	}
	if p.MaxTargets < 1 || len(p.CIDRs) == 0 || len(p.Ports) == 0 || len(p.Windows) == 0 {
		return Decision{}, errors.New("scope limits, ports and windows required")
	}
	if len(raw) == 0 || len(raw) > p.MaxTargets {
		return Decision{}, errors.New("target count outside approved limit")
	}
	for _, prefix := range p.CIDRs {
		if !prefix.IsValid() || prefix.Addr().Is4In6() {
			return Decision{}, errors.New("invalid scope prefix")
		}
	}
	grants := make(map[string]PortGrant, len(p.Ports))
	for _, grant := range p.Ports {
		endpoint, err := ParseEndpoint(grant.Endpoint)
		if err != nil {
			return Decision{}, fmt.Errorf("invalid port grant: %w", err)
		}
		if !inScope(p.CIDRs, endpoint.IP) {
			return Decision{}, errors.New("grant outside scope")
		}
		if grant.Kind != Web && grant.Kind != NonWeb && grant.Kind != ExcludedProxy {
			return Decision{}, errors.New("invalid port classification")
		}
		if _, exists := grants[endpoint.String()]; exists {
			return Decision{}, errors.New("duplicate port grant")
		}
		grants[endpoint.String()] = grant
	}
	targets := make([]Endpoint, 0, len(raw))
	seen := make(map[string]bool, len(raw))
	for _, value := range raw {
		if err := ctx.Err(); err != nil {
			return Decision{}, fmt.Errorf("admission canceled: %w", err)
		}
		target, err := ParseEndpoint(value)
		if err != nil {
			return Decision{}, fmt.Errorf("invalid target: %w", err)
		}
		if !inScope(p.CIDRs, target.IP) {
			return Decision{}, fmt.Errorf("out of scope: %s", target)
		}
		if seen[target.String()] {
			return Decision{}, errors.New("duplicate target")
		}
		seen[target.String()] = true
		grant, ok := grants[target.String()]
		if !ok {
			return Decision{}, fmt.Errorf("unregistered port: %s", target)
		}
		if grant.Kind == ExcludedProxy || grant.Quarantined {
			return Decision{}, fmt.Errorf("excluded or quarantined port: %s", target)
		}
		targets = append(targets, target)
	}
	deadline, allowed, err := ActiveDeadline(p.Windows, now)
	if err != nil {
		return Decision{}, fmt.Errorf("invalid scan window: %w", err)
	}
	if !allowed {
		return Decision{Status: "WAITING_WINDOW", Targets: targets}, nil
	}
	if !p.ExpiresAt.IsZero() && p.ExpiresAt.Before(deadline) {
		deadline = p.ExpiresAt
	}
	if !deadline.After(now) {
		return Decision{}, errors.New("deadline expired")
	}
	return Decision{Status: "READY", Targets: targets, HardDeadline: deadline}, nil
}

func parseClock(s string) (int, int, error) {
	if len(s) != 5 || s[2] != ':' {
		return 0, 0, fmt.Errorf("invalid HH:MM: %q", s)
	}
	h, err := strconv.Atoi(s[:2])
	if err != nil {
		return 0, 0, fmt.Errorf("hour: %w", err)
	}
	m, err := strconv.Atoi(s[3:])
	if err != nil {
		return 0, 0, fmt.Errorf("minute: %w", err)
	}
	if h > 23 || h < 0 || m > 59 || m < 0 {
		return 0, 0, errors.New("clock outside 24-hour range")
	}
	return h, m, nil
}

func includes(days []time.Weekday, day time.Weekday) bool {
	for _, d := range days {
		if d == day {
			return true
		}
	}
	return false
}

// ActiveDeadline assigns a cross-midnight window to its starting weekday.
// An invalid window always fails closed, even if a different window is open.
func ActiveDeadline(windows []Window, now time.Time) (time.Time, bool, error) {
	if len(windows) == 0 {
		return time.Time{}, false, errors.New("time windows required")
	}
	var latest time.Time
	for _, w := range windows {
		if len(w.Weekdays) == 0 || w.TimeZone == "" {
			return time.Time{}, false, errors.New("window weekdays/timezone required")
		}
		for _, day := range w.Weekdays {
			if day < time.Sunday || day > time.Saturday {
				return time.Time{}, false, errors.New("invalid weekday")
			}
		}
		loc, err := time.LoadLocation(w.TimeZone)
		if err != nil {
			return time.Time{}, false, fmt.Errorf("timezone: %w", err)
		}
		sh, sm, err := parseClock(w.Start)
		if err != nil {
			return time.Time{}, false, err
		}
		eh, em, err := parseClock(w.End)
		if err != nil {
			return time.Time{}, false, err
		}
		if sh == eh && sm == em {
			return time.Time{}, false, errors.New("ambiguous zero-length time window")
		}
		local := now.In(loc)
		for _, delta := range []int{-1, 0} {
			base := time.Date(local.Year(), local.Month(), local.Day()+delta, 0, 0, 0, 0, loc)
			if !includes(w.Weekdays, base.Weekday()) {
				continue
			}
			start := time.Date(base.Year(), base.Month(), base.Day(), sh, sm, 0, 0, loc)
			extra := 0
			if eh < sh || (eh == sh && em < sm) {
				extra = 1
			}
			end := time.Date(base.Year(), base.Month(), base.Day()+extra, eh, em, 0, 0, loc)
			if !now.Before(start) && now.Before(end) && end.After(latest) {
				latest = end
			}
		}
	}
	return latest, !latest.IsZero(), nil
}
