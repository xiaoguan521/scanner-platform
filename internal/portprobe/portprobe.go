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
	"sync/atomic"
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

// Result separates ports that run a service from ports that completed the TCP
// handshake but ended the connection without sending or keeping anything. The
// latter are what nmap reports as tcpwrapped; a large number of them usually means
// a firewall or load balancer answers on the host's behalf.
type Result struct {
	Open       []int
	TCPWrapped []int
}

func scanWithPolicyProgress(ctx context.Context, target string, ports []int, d dialer, policy Policy, reportProgress ScanProgressFunc) ([]int, error) {
	result, err := scanDetailed(ctx, target, ports, d, policy, reportProgress)
	return result.Open, err
}

func scanDetailed(ctx context.Context, target string, ports []int, d dialer, policy Policy, reportProgress ScanProgressFunc) (Result, error) {
	address, err := netip.ParseAddr(target)
	if err != nil || address.Zone() != "" || address.IsUnspecified() || address.IsMulticast() || len(ports) == 0 || len(ports) > MaxPorts || d == nil {
		return Result{}, ErrInvalidTarget
	}
	seen := make(map[int]struct{}, len(ports))
	for _, port := range ports {
		if port < 1 || port > 65535 {
			return Result{}, ErrInvalidConfig
		}
		if _, ok := seen[port]; ok {
			return Result{}, ErrInvalidConfig
		}
		seen[port] = struct{}{}
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	address = address.Unmap()
	workers := policy.Concurrency
	if len(ports) < workers {
		workers = len(ports)
	}
	jobs := make(chan int)
	open := make(chan int, len(ports))
	wrapped := make(chan int, len(ports))
	wildcard := &wildcardDetector{}
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
				if err == nil {
					if !wildcard.strict.Load() || connectionStaysOpen(conn, settleWait) {
						open <- port
					} else {
						wrapped <- port
					}
				}
				if conn != nil {
					_ = conn.Close()
				}
				wildcard.observe(err == nil)
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
				return Result{}, ctx.Err()
			}
		}
		select {
		case jobs <- port:
		case <-ctx.Done():
			close(jobs)
			done.Wait()
			return Result{}, ctx.Err()
		}
	}
	close(jobs)
	done.Wait()
	close(open)
	close(wrapped)
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	result := Result{Open: make([]int, 0, len(open))}
	for port := range open {
		result.Open = append(result.Open, port)
	}
	for port := range wrapped {
		result.TCPWrapped = append(result.TCPWrapped, port)
	}
	sort.Ints(result.Open)
	if wildcard.strict.Load() || suspiciousOpenSet(len(result.Open), len(ports)) {
		// The in-pass check used a short window and skipped the earliest ports; verify
		// every survivor again with the longer window. Fake ports close at once, so
		// only the few real listeners wait for the full period.
		kept, dropped, err := dropAcceptThenClose(ctx, address, result.Open, d, policy)
		if err != nil {
			return Result{}, err
		}
		result.Open = kept
		result.TCPWrapped = append(result.TCPWrapped, dropped...)
	}
	sort.Ints(result.TCPWrapped)
	return result, nil
}

const (
	wildcardSampleSize = 200
	wildcardOpenRatio  = 0.9
)

// wildcardDetector watches the first connection attempts. When nearly all of them
// succeed the target is answering every port, so the rest of the same pass keeps a
// port only if its connection also stays open; this avoids a second full pass.
type wildcardDetector struct {
	strict            atomic.Bool
	completed, opened atomic.Int64
}

func (w *wildcardDetector) observe(connected bool) {
	completed := w.completed.Add(1)
	opened := w.opened.Load()
	if connected {
		opened = w.opened.Add(1)
	}
	if completed >= wildcardSampleSize && float64(opened) >= wildcardOpenRatio*float64(completed) {
		w.strict.Store(true)
	}
}

// connectionStaysOpen reports whether the peer keeps an established connection
// silent or sends data, as a real listener does. It sends nothing.
func connectionStaysOpen(conn net.Conn, wait time.Duration) bool {
	if conn == nil {
		return false
	}
	_ = conn.SetReadDeadline(time.Now().Add(wait))
	var buf [1]byte
	n, err := conn.Read(buf[:])
	if n > 0 {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
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

// finalSettleWait matches nmap's tcpwrapped rule (a connection that ends within
// about three seconds without data is not a service). It is the quiet period a surviving port must keep in the low-load
// re-check. A middlebox that is slow under scan load can miss the short window
// above, but it still closes an idle connection within milliseconds when probed
// alone. A variable so tests can shorten it.
var finalSettleWait = 3 * time.Second

func suspiciousOpenSet(open, probed int) bool {
	return open >= wildcardMinOpen && open*2 >= probed
}

// dropAcceptThenClose re-checks an implausibly large open set and keeps only the
// ports whose connection stays open or sends data. It sends no data, so it stays
// a passive connect-and-read check against the same authorized IP and ports.
func dropAcceptThenClose(ctx context.Context, address netip.Addr, open []int, d dialer, policy Policy) (kept, dropped []int, err error) {
	workers := min(max(policy.Concurrency, 1), len(open))
	jobs := make(chan int)
	var mu sync.Mutex
	kept = make([]int, 0, 64)
	var done sync.WaitGroup
	for range workers {
		done.Add(1)
		go func() {
			defer done.Done()
			for port := range jobs {
				stays := settlesOpen(ctx, address, port, d, policy.Timeout)
				mu.Lock()
				if stays {
					kept = append(kept, port)
				} else {
					dropped = append(dropped, port)
				}
				mu.Unlock()
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
		return nil, nil, err
	}
	sort.Ints(kept)
	sort.Ints(dropped)
	return kept, dropped, nil
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
	return connectionStaysOpen(conn, finalSettleWait)
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
	result, err := ScanConfiguredDetailed(ctx, target, ports, config, reportProgress)
	return result.Open, err
}

// ScanConfiguredDetailed is ScanConfiguredWithProgress that also returns the ports
// that answered the handshake without running a service.
func ScanConfiguredDetailed(ctx context.Context, target string, ports []int, config Config, reportProgress ScanProgressFunc) (Result, error) {
	policy, err := PolicyFor(config)
	if err != nil {
		return Result{}, err
	}
	selected, err := SelectPorts(config)
	if err != nil {
		return Result{}, err
	}
	allowed := make(map[int]bool, len(selected))
	for _, p := range selected {
		allowed[p] = true
	}
	for _, p := range ports {
		if !allowed[p] {
			return Result{}, ErrInvalidConfig
		}
	}
	return scanDetailed(ctx, target, ports, &net.Dialer{}, policy, reportProgress)
}
