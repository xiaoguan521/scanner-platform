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
	ports, err := SelectPorts(Config{Preset: PresetCustom, Ranges: []Range{{Start: 1, End: 65535}}})
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
