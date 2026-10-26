package portprobe

import (
	"context"
	"errors"
	"net"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestSelectPortsPresetsRangesAndExclusions(t *testing.T) {
	common, err := SelectPorts(Config{Preset: PresetCommon, Exclusions: []Range{{Start: 22, End: 22}, {Start: 8080, End: 8081}}})
	if err != nil {
		t.Fatal(err)
	}
	if contains(common, 22) || contains(common, 8080) || contains(common, 8081) || !contains(common, 443) {
		t.Fatalf("common exclusions not applied: %v", common)
	}
	custom, err := SelectPorts(Config{Preset: PresetCustom, Ranges: []Range{{Start: 8000, End: 8002}, {Start: 9000, End: 9001}}, Exclusions: []Range{{Start: 8001, End: 8001}}})
	if err != nil || !reflect.DeepEqual(custom, []int{8000, 8002, 9000, 9001}) {
		t.Fatalf("custom selection=%v err=%v", custom, err)
	}
	combined, err := SelectPorts(Config{Preset: PresetCommonAndCustom, Ranges: []Range{{Start: 8000, End: 8001}}})
	if err != nil || !contains(combined, 443) || !contains(combined, 8001) {
		t.Fatalf("combined selection=%v err=%v", combined, err)
	}
}

func TestSelectPortsRejectsInvalidOrOversizedConfiguration(t *testing.T) {
	for _, config := range []Config{
		{Preset: PresetCustom},
		{Preset: PresetCustom, Ranges: []Range{{Start: 0, End: 80}}},
		{Preset: PresetCustom, Ranges: []Range{{Start: 80, End: 79}}},
		{Preset: PresetCustom, Ranges: []Range{{Start: 1, End: 65536}}},
		{Preset: PresetCommon, Ranges: []Range{{Start: 1, End: 1}}},
		{Preset: PresetCommon, Exclusions: []Range{{Start: 1, End: 65535}}},
		{Preset: "all", Ranges: []Range{{Start: 1, End: 1}}},
	} {
		if _, err := SelectPorts(config); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("accepted %+v: %v", config, err)
		}
	}
}

func TestSelectPortsAllowsFullTCPPortRange(t *testing.T) {
	ports, err := SelectPorts(Config{Preset: PresetCustom, Ranges: []Range{{Start: 1, End: 65535}}, FullConfirmed: true})
	if err != nil || len(ports) != 65535 || ports[0] != 1 || ports[len(ports)-1] != 65535 {
		t.Fatalf("full port range count=%d first/last=%v err=%v", len(ports), ports, err)
	}
}

func TestScanConnectsOnlyNumericTargetAndReturnsOpenPorts(t *testing.T) {
	d := &fixtureDialer{open: map[int]bool{80: true, 443: true}}
	got, err := scanWithDialer(context.Background(), "192.0.2.20", []int{443, 80, 22}, d)
	if err != nil || !reflect.DeepEqual(got, []int{80, 443}) {
		t.Fatalf("open ports=%v err=%v", got, err)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.targets) != 3 {
		t.Fatalf("dial calls=%v", d.targets)
	}
	for _, target := range d.targets {
		if !strings.HasPrefix(target, "192.0.2.20:") {
			t.Fatalf("unexpected dial target %q", target)
		}
	}
}

func TestScanRejectsHostnameRangesAndDuplicatePorts(t *testing.T) {
	d := &fixtureDialer{open: map[int]bool{}}
	for _, test := range []struct {
		target string
		ports  []int
		want   error
	}{
		{"example.test", []int{80}, ErrInvalidTarget},
		{"192.0.2.20", []int{0}, ErrInvalidConfig},
		{"192.0.2.20", []int{80, 80}, ErrInvalidConfig},
		{"192.0.2.20", make([]int, MaxPorts+1), ErrInvalidTarget},
	} {
		if _, err := scanWithDialer(context.Background(), test.target, test.ports, d); !errors.Is(err, test.want) {
			t.Errorf("target=%q err=%v want %v", test.target, err, test.want)
		}
	}
}

func TestScanUsesBoundedParallelConnections(t *testing.T) {
	d := &concurrencyDialer{started: make(chan struct{}, ProbeConcurrency), release: make(chan struct{})}
	ports := make([]int, ProbeConcurrency*2)
	for i := range ports {
		ports[i] = i + 1
	}
	done := make(chan error, 1)
	go func() {
		_, err := scanWithDialer(context.Background(), "192.0.2.20", ports, d)
		done <- err
	}()
	for range ProbeConcurrency {
		<-d.started
	}
	close(d.release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.maxActive != ProbeConcurrency {
		t.Fatalf("maximum active connections=%d want %d", d.maxActive, ProbeConcurrency)
	}
}

type fixtureDialer struct {
	mu      sync.Mutex
	open    map[int]bool
	targets []string
}

type concurrencyDialer struct {
	mu        sync.Mutex
	active    int
	maxActive int
	started   chan struct{}
	release   chan struct{}
}

func (d *concurrencyDialer) DialContext(ctx context.Context, _, _ string) (net.Conn, error) {
	d.mu.Lock()
	d.active++
	if d.active > d.maxActive {
		d.maxActive = d.active
	}
	d.mu.Unlock()
	select {
	case d.started <- struct{}{}:
	default:
	}
	defer func() {
		d.mu.Lock()
		d.active--
		d.mu.Unlock()
	}()
	select {
	case <-d.release:
		return nil, errors.New("closed")
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (d *fixtureDialer) DialContext(_ context.Context, network, target string) (net.Conn, error) {
	if network != "tcp" {
		return nil, errors.New("unexpected network")
	}
	d.mu.Lock()
	d.targets = append(d.targets, target)
	isOpen := d.open[mustPort(target)]
	d.mu.Unlock()
	if !isOpen {
		return nil, errors.New("closed")
	}
	client, server := net.Pipe()
	_ = server.Close()
	return client, nil
}

func mustPort(target string) int {
	_, value, _ := net.SplitHostPort(target)
	port, _ := strconv.Atoi(value)
	return port
}

func contains(values []int, want int) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func TestPoliciesConfirmationAndConfigurablePorts(t *testing.T) {
	for _, config := range []Config{{Preset: PresetFull}, {Preset: PresetCustom, Ranges: []Range{{1, 32767}, {32768, 65535}}}, {Preset: PresetFull, Exclusions: []Range{{80, 80}}}} {
		if _, err := SelectPorts(config); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("full scan without confirmation accepted: %+v", config)
		}
	}
	ports, err := SelectPorts(Config{Preset: PresetRegistered, RegisteredPorts: []int{18888, 80, 80}, Exclusions: []Range{{80, 80}}})
	if err != nil || !reflect.DeepEqual(ports, []int{18888}) {
		t.Fatal(ports, err)
	}
	ports, err = SelectPorts(Config{Preset: PresetCommon, CommonPorts: []int{22, 8118}})
	if err != nil || !reflect.DeepEqual(ports, []int{22, 8118}) {
		t.Fatal(ports, err)
	}
	for _, config := range []Config{{Intensity: "unbounded"}, {CommonPorts: []int{0}}, {Preset: PresetRegistered}, {IdentificationMaxAttempts: 4}, {QuarantineThreshold: 4}} {
		if _, err := SelectPorts(config); err == nil {
			t.Fatalf("invalid policy accepted: %+v", config)
		}
	}
	gentle, _ := PolicyFor(Config{Preset: PresetFull})
	standard, _ := PolicyFor(Config{})
	aggressive, _ := PolicyFor(Config{Intensity: IntensityAggressive})
	if gentle.Concurrency >= standard.Concurrency || standard.Concurrency >= aggressive.Concurrency || gentle.Rate >= standard.Rate || standard.Rate >= aggressive.Rate || gentle.Timeout <= aggressive.Timeout {
		t.Fatal(gentle, standard, aggressive)
	}
}

func FuzzSelectPorts(f *testing.F) {
	f.Add(1, 65535, true)
	f.Add(80, 81, false)
	f.Fuzz(func(t *testing.T, start, end int, confirm bool) {
		ports, err := SelectPorts(Config{Preset: PresetCustom, Ranges: []Range{{start, end}}, FullConfirmed: confirm})
		if err == nil {
			if len(ports) == 0 || len(ports) > MaxPorts {
				t.Fatal("unbounded selection")
			}
			for i, p := range ports {
				if p < 1 || p > 65535 || i > 0 && p <= ports[i-1] {
					t.Fatal("invalid selected port")
				}
			}
		}
	})
}

// middleboxDialer completes every connection; only the real ports keep it open.
type middleboxDialer struct{ real map[int]bool }

func (d middleboxDialer) DialContext(_ context.Context, _, target string) (net.Conn, error) {
	_, portText, _ := net.SplitHostPort(target)
	port, _ := strconv.Atoi(portText)
	client, server := net.Pipe()
	if !d.real[port] {
		_ = server.Close() // accept-then-close: the peer ends the connection at once
	}
	return client, nil
}

func TestScanDropsAcceptThenCloseWhenNearlyEveryPortAnswers(t *testing.T) {
	shortenFinalWait(t)
	ports := make([]int, 0, 1000)
	for port := 1; port <= 1000; port++ {
		ports = append(ports, port)
	}
	got, err := scanWithDialer(context.Background(), "192.0.2.10", ports, middleboxDialer{real: map[int]bool{22: true, 443: true}})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, []int{22, 443}) {
		t.Fatalf("expected only real listeners, got %d ports: %v", len(got), got)
	}
}

func TestScanKeepsSmallOpenSetsUntouched(t *testing.T) {
	// Few answering ports are normal: a service that closes at once is still reported.
	got, err := scanWithDialer(context.Background(), "192.0.2.10", []int{22, 80, 443}, middleboxDialer{})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, []int{22, 80, 443}) {
		t.Fatalf("small open sets must not be re-filtered, got %v", got)
	}
}

type countingDialer struct {
	middleboxDialer
	mu    sync.Mutex
	dials int
}

func (d *countingDialer) DialContext(ctx context.Context, network, target string) (net.Conn, error) {
	d.mu.Lock()
	d.dials++
	d.mu.Unlock()
	return d.middleboxDialer.DialContext(ctx, network, target)
}

func TestWildcardHostIsHandledInOnePass(t *testing.T) {
	shortenFinalWait(t)
	ports := make([]int, 0, 5000)
	for port := 1; port <= 5000; port++ {
		ports = append(ports, port)
	}
	dialer := &countingDialer{middleboxDialer: middleboxDialer{real: map[int]bool{22: true, 3000: true}}}
	got, err := scanWithDialer(context.Background(), "192.0.2.10", ports, dialer)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, []int{22, 3000}) {
		t.Fatalf("expected only real listeners, got %d ports", len(got))
	}
	// One attempt per port plus bounded verification (consensus on the early sample
	// and an audit sample), never a second full pass.
	if limit := len(ports) + 2*wildcardSampleSize + 2*auditSampleSize + 200; dialer.dials > limit {
		t.Fatalf("wildcard handling dialed %d times, limit %d", dialer.dials, limit)
	}
}

func shortenFinalWait(t *testing.T) {
	t.Helper()
	previous := finalSettleWait
	finalSettleWait = 50 * time.Millisecond
	t.Cleanup(func() { finalSettleWait = previous })
}

// slowCloseDialer models a middlebox that is slow under load: it ends fake
// connections only after a delay longer than the in-pass silence window.
type slowCloseDialer struct {
	real  map[int]bool
	delay time.Duration
}

func (d slowCloseDialer) DialContext(_ context.Context, _, target string) (net.Conn, error) {
	_, portText, _ := net.SplitHostPort(target)
	port, _ := strconv.Atoi(portText)
	client, server := net.Pipe()
	if !d.real[port] {
		time.AfterFunc(d.delay, func() { _ = server.Close() })
	}
	return client, nil
}

func TestSlowClosingMiddleboxPortsAreDroppedByTheLowLoadRecheck(t *testing.T) {
	previous := finalSettleWait
	finalSettleWait = 1500 * time.Millisecond
	t.Cleanup(func() { finalSettleWait = previous })
	ports := make([]int, 0, 600)
	for port := 1; port <= 600; port++ {
		ports = append(ports, port)
	}
	got, err := scanWithDialer(context.Background(), "192.0.2.10", ports, slowCloseDialer{real: map[int]bool{22: true, 443: true}, delay: settleWait + 100*time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, []int{22, 443}) {
		t.Fatalf("ports that close after the short window must still be dropped, got %d ports", len(got))
	}
}

func TestScanDetailedReportsHandshakeOnlyPortsAsTCPWrapped(t *testing.T) {
	shortenFinalWait(t)
	ports := make([]int, 0, 1000)
	for port := 1; port <= 1000; port++ {
		ports = append(ports, port)
	}
	result, err := scanDetailed(context.Background(), "192.0.2.10", ports, middleboxDialer{real: map[int]bool{22: true, 443: true}}, Policy{Concurrency: 64, Timeout: ProbeTimeout}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(result.Open, []int{22, 443}) {
		t.Fatalf("unexpected open ports %v", result.Open)
	}
	if len(result.TCPWrapped) != 998 {
		t.Fatalf("every other answering port must be reported as tcpwrapped, got %d", len(result.TCPWrapped))
	}
	seen := map[int]bool{22: true, 443: true}
	for _, port := range result.TCPWrapped {
		if seen[port] {
			t.Fatalf("port %d is reported twice or as both open and tcpwrapped", port)
		}
		seen[port] = true
	}
}

// flakyDialer lets the first connection to a port through, then fails the next
// `failures` dials to it, as a busy middlebox does right after a heavy scan.
type flakyDialer struct {
	middleboxDialer
	failures map[int]int
	mu       sync.Mutex
	dials    map[int]int
}

func (d *flakyDialer) DialContext(ctx context.Context, network, target string) (net.Conn, error) {
	_, portText, _ := net.SplitHostPort(target)
	port, _ := strconv.Atoi(portText)
	d.mu.Lock()
	d.dials[port]++
	n := d.dials[port]
	d.mu.Unlock()
	if n > 1 && n <= 1+d.failures[port] {
		return nil, errors.New("simulated timeout")
	}
	return d.middleboxDialer.DialContext(ctx, network, target)
}

func TestFailedRecheckConnectionsAreNotReportedAsTCPWrapped(t *testing.T) {
	shortenFinalWait(t)
	ports := make([]int, 0, 600)
	for port := 1; port <= 600; port++ {
		ports = append(ports, port)
	}
	dialer := &flakyDialer{middleboxDialer: middleboxDialer{real: map[int]bool{22: true, 443: true}}, failures: map[int]int{22: 2, 443: 99}, dials: map[int]int{}}
	result, err := scanDetailed(context.Background(), "192.0.2.10", ports, dialer, Policy{Concurrency: 64, Timeout: ProbeTimeout}, nil)
	if err != nil {
		t.Fatal(err)
	}
	// 22 recovers on a later attempt and is confirmed. 443 never reconnects: that
	// proves nothing, so it is unconfirmed rather than open or tcpwrapped.
	if !reflect.DeepEqual(result.Open, []int{22}) || !reflect.DeepEqual(result.Unconfirmed, []int{443}) {
		t.Fatalf("expected open [22] and unconfirmed [443], got open %v unconfirmed %v", result.Open, result.Unconfirmed)
	}
	for _, port := range result.TCPWrapped {
		if port == 22 || port == 443 {
			t.Fatalf("port %d wrongly reported as tcpwrapped", port)
		}
	}
}

// scriptedDialer replays a per-port behaviour for each successive dial:
// "hold" keeps the connection silent, "close" ends it at once, "fail" refuses the dial.
type scriptedDialer struct {
	script map[int][]string
	mu     sync.Mutex
	calls  map[int]int
}

func (d *scriptedDialer) DialContext(_ context.Context, _, target string) (net.Conn, error) {
	_, portText, _ := net.SplitHostPort(target)
	port, _ := strconv.Atoi(portText)
	d.mu.Lock()
	n := d.calls[port]
	d.calls[port]++
	d.mu.Unlock()
	behaviour := "close"
	if steps := d.script[port]; n < len(steps) {
		behaviour = steps[n]
	} else if len(steps) > 0 {
		behaviour = steps[len(steps)-1]
	}
	if behaviour == "fail" {
		return nil, errors.New("simulated failure")
	}
	client, server := net.Pipe()
	if behaviour == "close" {
		_ = server.Close()
	}
	return client, nil
}

func scanScripted(t *testing.T, total int, script map[int][]string) Result {
	t.Helper()
	shortenFinalWait(t)
	ports := make([]int, 0, total)
	for port := 1; port <= total; port++ {
		ports = append(ports, port)
	}
	result, err := scanDetailed(context.Background(), "192.0.2.10", ports, &scriptedDialer{script: script, calls: map[int]int{}}, Policy{Concurrency: 64, Timeout: ProbeTimeout}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestInconsistentObservationsAreUnconfirmedNotGuessed(t *testing.T) {
	// Port 10 is among the first ports (counted open before the wildcard is noticed).
	// Its checks disagree (closed, open) and then cannot connect: no consensus.
	result := scanScripted(t, 600, map[int][]string{10: {"hold", "close", "hold", "fail", "fail"}, 22: {"hold"}})
	if !reflect.DeepEqual(result.Open, []int{22}) || !reflect.DeepEqual(result.Unconfirmed, []int{10}) {
		t.Fatalf("open %v unconfirmed %v", result.Open, result.Unconfirmed)
	}
	for _, port := range result.TCPWrapped {
		if port == 10 || port == 22 {
			t.Fatalf("port %d must not be tcpwrapped", port)
		}
	}
}

func TestUnreliableInPassRuleTriggersFullVerification(t *testing.T) {
	// Port 250 is called tcpwrapped by the in-pass check (closes on the first dial)
	// but keeps connections afterwards. The audit sample catches it and every in-pass
	// tcpwrapped port is then judged by consensus.
	result := scanScripted(t, 300, map[int][]string{250: {"close", "hold"}})
	if !reflect.DeepEqual(result.Open, []int{250}) {
		t.Fatalf("a port the in-pass rule wrongly rejected must be recovered, got open %v", result.Open)
	}
}

func TestAPortThatEverKeptAConnectionIsNeverCalledTCPWrapped(t *testing.T) {
	// One silent observation followed by closes: not a pure accept-then-close fake.
	result := scanScripted(t, 600, map[int][]string{10: {"hold", "hold", "close", "close", "close"}})
	for _, port := range result.TCPWrapped {
		if port == 10 {
			t.Fatalf("a port with mixed observations must not be tcpwrapped")
		}
	}
	if !reflect.DeepEqual(result.Unconfirmed, []int{10}) {
		t.Fatalf("expected port 10 unconfirmed, got open %v unconfirmed %v", result.Open, result.Unconfirmed)
	}
}
