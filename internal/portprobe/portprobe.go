// Package portprobe provides a bounded TCP connect probe for one registered IP.
// It sends no application data and performs no service fingerprinting.
package portprobe

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"sync"
	"time"
)

var (
	ErrInvalidTarget = errors.New("invalid port probe target")
	ErrInvalidConfig = errors.New("invalid port probe configuration")
)

const (
	PresetCommon          = "common"
	PresetCustom          = "custom"
	PresetRegistered      = "registered"
	PresetFull            = "full"
	IntensityGentle       = "gentle"
	IntensityStandard     = "standard"
	IntensityAggressive   = "aggressive"
	PresetCommonAndCustom = "common-and-custom"
	MaxPorts              = 65535
	MaxRanges             = 128
	ProbeTimeout          = 700 * time.Millisecond
	ProbeConcurrency      = 64
)

type Range struct {
	Start int `json:"start"`
	End   int `json:"end"`
}

type Config struct {
	Preset                    string  `json:"preset"`
	Ranges                    []Range `json:"ranges,omitempty"`
	Exclusions                []Range `json:"exclusions,omitempty"`
	OpsApproved               bool    `json:"opsApproved,omitempty"`
	CommonPorts               []int   `json:"commonPorts,omitempty"`
	RegisteredPorts           []int   `json:"registeredPorts,omitempty"`
	Intensity                 string  `json:"intensity,omitempty"`
	FullConfirmed             bool    `json:"fullConfirmed,omitempty"`
	IdentificationMaxAttempts int     `json:"identificationMaxAttempts,omitempty"`
	QuarantineThreshold       int     `json:"quarantineThreshold,omitempty"`
	IdentificationBudget      int     `json:"identificationBudget,omitempty"`
}

// CommonPorts is a curated TCP list for the platform's common Linux web,
// middleware, and database services. The returned slice is a copy.
func CommonPorts() []int {
	return []int{
		21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 389, 443, 445, 465, 587, 636, 993, 995, 1433, 1521, 2181, 2888, 3000, 3306, 3888, 5000,
		5222, 5236, 5258, 5432, 5672, 6379, 6443, 7001, 7002, 7070, 7474, 7687, 7777, 8000, 8001, 8080, 8081,
		8088, 8090, 8118, 8161, 8200, 8443, 8848, 9000, 9042, 9080, 9090, 9092, 9200, 9300, 9443, 10000, 11211, 15672, 18080, 18888, 27017, 28017, 50000, 9848, 9849,
		54321,
	}
}

// SelectPorts validates a configuration, applies exclusions, and returns a
// sorted TCP port list. Ranges are inclusive and may cover the full port space.
func SelectPorts(config Config) ([]int, error) {
	preset := config.Preset
	if preset == "" {
		preset = PresetCommon
	}
	if len(config.Ranges) > MaxRanges || len(config.Exclusions) > MaxRanges {
		return nil, ErrInvalidConfig
	}
	if _, err := PolicyFor(config); err != nil {
		return nil, err
	}
	if config.IdentificationMaxAttempts < 0 || config.IdentificationMaxAttempts > 3 || config.QuarantineThreshold < 0 || config.QuarantineThreshold > 3 || config.IdentificationBudget < 0 || config.IdentificationBudget > MaxPorts*3 {
		return nil, ErrInvalidConfig
	}
	common := CommonPorts()
	if len(config.CommonPorts) > 0 {
		common = config.CommonPorts
	}
	for _, list := range [][]int{common, config.RegisteredPorts} {
		if len(list) > MaxPorts {
			return nil, ErrInvalidConfig
		}
		for _, p := range list {
			if p < 1 || p > 65535 {
				return nil, ErrInvalidConfig
			}
		}
	}
	selected := make(map[int]struct{}, MaxPorts)
	switch preset {
	case PresetCommon:
		if len(config.Ranges) != 0 {
			return nil, ErrInvalidConfig
		}
		for _, port := range common {
			selected[port] = struct{}{}
		}
	case PresetRegistered:
		if len(config.Ranges) != 0 || len(config.RegisteredPorts) == 0 {
			return nil, ErrInvalidConfig
		}
		for _, p := range config.RegisteredPorts {
			selected[p] = struct{}{}
		}
	case PresetFull:
		if len(config.Ranges) != 0 {
			return nil, ErrInvalidConfig
		}
		for p := 1; p <= MaxPorts; p++ {
			selected[p] = struct{}{}
		}
	case PresetCustom, PresetCommonAndCustom:
		if len(config.Ranges) == 0 {
			return nil, ErrInvalidConfig
		}
		if preset == PresetCommonAndCustom {
			for _, port := range common {
				selected[port] = struct{}{}
			}
		}
		for _, portRange := range config.Ranges {
			if !validRange(portRange) {
				return nil, ErrInvalidConfig
			}
			for port := portRange.Start; port <= portRange.End; port++ {
				selected[port] = struct{}{}
				if len(selected) > MaxPorts {
					return nil, ErrInvalidConfig
				}
			}
		}
	default:
		return nil, ErrInvalidConfig
	}
	if len(selected) == MaxPorts && !config.FullConfirmed {
		return nil, ErrInvalidConfig
	}
	if len(selected) == 0 || len(selected) > MaxPorts {
		return nil, ErrInvalidConfig
	}
	for _, exclusion := range config.Exclusions {
		if !validRange(exclusion) {
			return nil, ErrInvalidConfig
		}
		for port := range selected {
			if port >= exclusion.Start && port <= exclusion.End {
				delete(selected, port)
			}
		}
	}
	if len(selected) == 0 {
		return nil, ErrInvalidConfig
	}
	ports := make([]int, 0, len(selected))
	for port := range selected {
		ports = append(ports, port)
	}
	sort.Ints(ports)
	return ports, nil
}

func validRange(value Range) bool {
	return value.Start >= 1 && value.Start <= value.End && value.End <= 65535
}

type dialer interface {
	DialContext(context.Context, string, string) (net.Conn, error)
}

// ScanProgressFunc receives completed connection attempts, including refused
// and timed-out ports. It must not be used to infer open-port results.
type ScanProgressFunc func(completed, total int)

// Scan validates a numeric IP and probes the provided TCP port list by
// connecting and immediately closing. It never sends protocol data.
func Scan(ctx context.Context, target string, ports []int) ([]int, error) {
	return scanWithPolicy(ctx, target, ports, &net.Dialer{}, Policy{Concurrency: ProbeConcurrency, Timeout: ProbeTimeout})
}

func scanWithDialer(ctx context.Context, target string, ports []int, d dialer) ([]int, error) {
	return scanWithPolicy(ctx, target, ports, d, Policy{Concurrency: ProbeConcurrency, Timeout: ProbeTimeout})
}

func scanWithPolicy(ctx context.Context, target string, ports []int, d dialer, policy Policy) ([]int, error) {
	return scanWithPolicyProgress(ctx, target, ports, d, policy, nil)
}

func scanWithPolicyProgress(ctx context.Context, target string, ports []int, d dialer, policy Policy, reportProgress ScanProgressFunc) ([]int, error) {
	address, err := netip.ParseAddr(target)
	if err != nil || address.Zone() != "" || address.IsUnspecified() || address.IsMulticast() || len(ports) == 0 || len(ports) > MaxPorts || d == nil {
		return nil, ErrInvalidTarget
	}
	seen := make(map[int]struct{}, len(ports))
	for _, port := range ports {
		if port < 1 || port > 65535 {
			return nil, ErrInvalidConfig
		}
		if _, ok := seen[port]; ok {
			return nil, ErrInvalidConfig
		}
		seen[port] = struct{}{}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	address = address.Unmap()
	workers := policy.Concurrency
	if len(ports) < workers {
		workers = len(ports)
	}
	jobs := make(chan int)
	open := make(chan int, len(ports))
	var done sync.WaitGroup
	var progressMu sync.Mutex
	progressCompleted, lastProgress := 0, 0
	progressStep := max(1, len(ports)/1000)
	for range workers {
		done.Add(1)
		go func() {
			defer done.Done()
			for port := range jobs {
				probeCtx, cancel := context.WithTimeout(ctx, policy.Timeout)
				conn, err := d.DialContext(probeCtx, "tcp", net.JoinHostPort(address.String(), strconv.Itoa(port)))
				cancel()
				if conn != nil {
					_ = conn.Close()
				}
				if err == nil {
					open <- port
				}
				if reportProgress != nil {
					progressMu.Lock()
					progressCompleted++
					if progressCompleted-lastProgress >= progressStep || progressCompleted == len(ports) {
						lastProgress = progressCompleted
						reportProgress(progressCompleted, len(ports))
					}
					progressMu.Unlock()
				}
			}
		}()
	}
	var ticker *time.Ticker
	if policy.Rate > 0 {
		ticker = time.NewTicker(time.Second / time.Duration(policy.Rate))
		defer ticker.Stop()
	}
	for _, port := range ports {
		if ticker != nil {
			select {
			case <-ticker.C:
			case <-ctx.Done():
				close(jobs)
				done.Wait()
				return nil, ctx.Err()
			}
		}
		select {
		case jobs <- port:
		case <-ctx.Done():
			close(jobs)
			done.Wait()
			return nil, ctx.Err()
		}
	}
	close(jobs)
	done.Wait()
	close(open)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	result := make([]int, 0, len(open))
	for port := range open {
		result = append(result, port)
	}
	sort.Ints(result)
	if suspiciousOpenSet(len(result), len(ports)) {
		return dropAcceptThenClose(ctx, address, result, d, policy)
	}
	return result, nil
}

const (
	// A host answering most of a large port list is almost always a middlebox that
	// completes the handshake for every port, not thousands of real listeners.
	wildcardMinOpen = 256
	// settleWait is how long a connected port may stay silent before it counts as
	// a real listener: servers keep the connection and wait for the client or send
	// a banner, while a middlebox closes it within a round trip.
	settleWait = 400 * time.Millisecond
)

func suspiciousOpenSet(open, probed int) bool {
	return open >= wildcardMinOpen && open*2 >= probed
}

// dropAcceptThenClose re-checks an implausibly large open set and keeps only the
// ports whose connection stays open or sends data. It sends no data, so it stays
// a passive connect-and-read check against the same authorized IP and ports.
func dropAcceptThenClose(ctx context.Context, address netip.Addr, open []int, d dialer, policy Policy) ([]int, error) {
	workers := min(max(policy.Concurrency, 1), len(open))
	jobs := make(chan int)
	var mu sync.Mutex
	kept := make([]int, 0, 64)
	var done sync.WaitGroup
	for range workers {
		done.Add(1)
		go func() {
			defer done.Done()
			for port := range jobs {
				if settlesOpen(ctx, address, port, d, policy.Timeout) {
					mu.Lock()
					kept = append(kept, port)
					mu.Unlock()
				}
			}
		}()
	}
	var ticker *time.Ticker
	if policy.Rate > 0 {
		ticker = time.NewTicker(time.Second / time.Duration(policy.Rate))
		defer ticker.Stop()
	}
feed:
	for _, port := range open {
		if ticker != nil {
			select {
			case <-ticker.C:
			case <-ctx.Done():
				break feed
			}
		}
		select {
		case jobs <- port:
		case <-ctx.Done():
			break feed
		}
	}
	close(jobs)
	done.Wait()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	sort.Ints(kept)
	return kept, nil
}

func settlesOpen(ctx context.Context, address netip.Addr, port int, d dialer, timeout time.Duration) bool {
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := d.DialContext(dialCtx, "tcp", net.JoinHostPort(address.String(), strconv.Itoa(port)))
	if conn != nil {
		defer conn.Close()
	}
	if err != nil {
		return false
	}
	_ = conn.SetReadDeadline(time.Now().Add(settleWait))
	var buf [1]byte
	n, err := conn.Read(buf[:])
	if n > 0 {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

// Policy is a bounded per-target connection policy.
type Policy struct {
	Concurrency int
	Rate        int
	Timeout     time.Duration
}

func PolicyFor(config Config) (Policy, error) {
	intensity := config.Intensity
	if intensity == "" {
		intensity = IntensityStandard
		if config.Preset == PresetFull {
			intensity = IntensityGentle
		}
	}
	switch intensity {
	case IntensityGentle:
		return Policy{8, 20, 1500 * time.Millisecond}, nil
	case IntensityStandard:
		return Policy{32, 100, 1000 * time.Millisecond}, nil
	case IntensityAggressive:
		return Policy{64, 250, 700 * time.Millisecond}, nil
	default:
		return Policy{}, ErrInvalidConfig
	}
}
func ScanConfigured(ctx context.Context, target string, ports []int, config Config) ([]int, error) {
	return ScanConfiguredWithProgress(ctx, target, ports, config, nil)
}

// ScanConfiguredWithProgress probes the Server-approved port list and reports
// completed attempts at a bounded cadence. Progress does not expose results.
func ScanConfiguredWithProgress(ctx context.Context, target string, ports []int, config Config, reportProgress ScanProgressFunc) ([]int, error) {
	policy, err := PolicyFor(config)
	if err != nil {
		return nil, err
	}
	selected, err := SelectPorts(config)
	if err != nil {
		return nil, err
	}
	allowed := make(map[int]bool, len(selected))
	for _, p := range selected {
		allowed[p] = true
	}
	for _, p := range ports {
		if !allowed[p] {
			return nil, ErrInvalidConfig
		}
	}
	return scanWithPolicyProgress(ctx, target, ports, &net.Dialer{}, policy, reportProgress)
}
