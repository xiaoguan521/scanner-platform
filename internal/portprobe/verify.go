package portprobe

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"sync"
	"time"
)

// maxVerdictLogs bounds how many per-port verification lines one pass writes.
const maxVerdictLogs = 400

func verdictName(v verdict) string {
	switch v {
	case verdictOpen:
		return "open"
	case verdictClosed:
		return "tcpwrapped"
	default:
		return "unconfirmed"
	}
}

const (
	// Verification stops as soon as two observations agree, and gives up after this many.
	maxObservations = 4
	// auditSampleSize is how many in-pass tcpwrapped ports are re-checked to decide
	// whether the in-pass rule can be trusted on this host.
	auditSampleSize = 200
)

type observation int

const (
	observedOpen observation = iota
	observedClosed
	// observedUnknown means no connection could be made, which proves nothing
	// about whether the port keeps or ends connections.
	observedUnknown
)

type verdict int

const (
	verdictOpen verdict = iota
	verdictClosed
	verdictUnconfirmed
)

// observePort makes one fresh connection and reads passively for finalSettleWait:
// data or silence means the peer keeps the connection (a service), an early close
// or reset means it does not. Nothing is sent.
func observePort(ctx context.Context, address netip.Addr, port int, d dialer, timeout time.Duration) observation {
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	conn, err := d.DialContext(dialCtx, "tcp", net.JoinHostPort(address.String(), strconv.Itoa(port)))
	cancel()
	if conn != nil {
		defer conn.Close()
	}
	if err != nil {
		return observedUnknown
	}
	if connectionStaysOpen(conn, finalSettleWait) {
		return observedOpen
	}
	return observedClosed
}

// judgePort decides by consensus instead of a single observation. Two agreeing
// observations settle a port only when the other kind was never seen: a port that
// ever kept a connection is not a pure accept-then-close fake, so mixed evidence
// is Unconfirmed rather than tcpwrapped. The history ("O" open, "C" closed, "U"
// could not connect) is returned so the decision can be audited.
func judgePort(ctx context.Context, address netip.Addr, port int, d dialer, timeout time.Duration) (verdict, string) {
	opened, closed := 0, 0
	history := make([]byte, 0, maxObservations)
	for attempt := 1; attempt <= maxObservations; attempt++ {
		if ctx.Err() != nil {
			return verdictUnconfirmed, string(history)
		}
		switch observePort(ctx, address, port, d, timeout) {
		case observedOpen:
			opened++
			history = append(history, 'O')
		case observedClosed:
			closed++
			history = append(history, 'C')
		default:
			history = append(history, 'U')
			select {
			case <-time.After(time.Duration(attempt) * 200 * time.Millisecond):
			case <-ctx.Done():
				return verdictUnconfirmed, string(history)
			}
		}
		if opened >= 2 && closed == 0 {
			return verdictOpen, string(history)
		}
		if closed >= 2 && opened == 0 {
			return verdictClosed, string(history)
		}
	}
	return verdictUnconfirmed, string(history)
}

// judgePorts runs judgePort for each port with the scan's concurrency and rate.
func judgePorts(ctx context.Context, address netip.Addr, ports []int, d dialer, policy Policy) (open, closed, unconfirmed []int, err error) {
	if len(ports) == 0 {
		return nil, nil, nil, nil
	}
	workers := min(max(policy.Concurrency, 1), len(ports))
	jobs := make(chan int)
	var mu sync.Mutex
	var done sync.WaitGroup
	logged := 0
	for range workers {
		done.Add(1)
		go func() {
			defer done.Done()
			for port := range jobs {
				v, history := judgePort(ctx, address, port, d, policy.Timeout)
				mu.Lock()
				if logged < maxVerdictLogs {
					logged++
					slog.Info("port verification", "port", port, "history", history, "verdict", verdictName(v))
				}
				switch v {
				case verdictOpen:
					open = append(open, port)
				case verdictClosed:
					closed = append(closed, port)
				default:
					unconfirmed = append(unconfirmed, port)
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
	for _, port := range ports {
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
		return nil, nil, nil, err
	}
	sort.Ints(open)
	sort.Ints(closed)
	sort.Ints(unconfirmed)
	return open, closed, unconfirmed, nil
}

// verifyWildcardResult turns the first-pass result of a host that answers (almost)
// every port into a trustworthy one:
//  1. every port the pass called open is judged by consensus;
//  2. the ports the pass called tcpwrapped are audited on a sample; if any sampled
//     port is not confirmed closed, the in-pass rule is unreliable on this host and
//     all of them are judged by consensus too.
func verifyWildcardResult(ctx context.Context, address netip.Addr, pass Result, d dialer, policy Policy) (Result, error) {
	slog.Info("port probe first pass", "survivors", len(pass.Open), "in_pass_tcpwrapped", len(pass.TCPWrapped))
	open, closedFromOpen, unconfirmed, err := judgePorts(ctx, address, pass.Open, d, policy)
	if err != nil {
		return Result{}, err
	}
	result := Result{Open: open, TCPWrapped: closedFromOpen, Unconfirmed: unconfirmed}
	sample := auditSample(pass.TCPWrapped, auditSampleSize)
	sampleOpen, _, sampleUnconfirmed, err := judgePorts(ctx, address, sample, d, policy)
	if err != nil {
		return Result{}, err
	}
	slog.Info("port probe audit", "sample", len(sample), "not_closed", len(sampleOpen)+len(sampleUnconfirmed))
	if len(sampleOpen) == 0 && len(sampleUnconfirmed) == 0 {
		result.TCPWrapped = append(result.TCPWrapped, pass.TCPWrapped...)
	} else {
		reopen, reclosed, reunconfirmed, err := judgePorts(ctx, address, pass.TCPWrapped, d, policy)
		if err != nil {
			return Result{}, err
		}
		result.Open = append(result.Open, reopen...)
		result.TCPWrapped = append(result.TCPWrapped, reclosed...)
		result.Unconfirmed = append(result.Unconfirmed, reunconfirmed...)
	}
	sort.Ints(result.Open)
	sort.Ints(result.TCPWrapped)
	sort.Ints(result.Unconfirmed)
	slog.Info("port probe verified", "open", len(result.Open), "tcpwrapped", len(result.TCPWrapped), "unconfirmed", len(result.Unconfirmed))
	return result, nil
}

// auditSample picks up to size ports spread evenly over the sorted list, so the
// sample is reproducible and covers the whole range rather than only its start.
func auditSample(ports []int, size int) []int {
	if len(ports) <= size {
		return append([]int(nil), ports...)
	}
	sorted := append([]int(nil), ports...)
	sort.Ints(sorted)
	sample := make([]int, 0, size)
	for i := 0; i < size; i++ {
		sample = append(sample, sorted[i*len(sorted)/size])
	}
	return sample
}
