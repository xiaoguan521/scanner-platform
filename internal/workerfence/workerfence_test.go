package workerfence

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"scanner-platform/internal/scope"
)

func endpoint(ip string, port uint16) scope.Endpoint {
	return scope.Endpoint{IP: netip.MustParseAddr(ip), Port: port}
}

func samplePlan() Plan {
	return Plan{
		Decision: scope.Decision{
			Status:       "READY",
			Targets:      []scope.Endpoint{endpoint("192.0.2.10", 443)},
			HardDeadline: time.Now().Add(time.Hour),
		},
		Infrastructure: []Permit{{Endpoint: endpoint("198.51.100.7", 8443), Protocol: TCP}},
	}
}

func TestRulesDefaultDropAndExactPermits(t *testing.T) {
	got, err := Rules(samplePlan(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, needle := range []string{
		"type filter hook output priority -150; policy drop;",
		"type filter hook forward priority -150; policy drop;",
		"oifname \"lo\" counter accept",
		"ip daddr 192.0.2.10 tcp dport 443 counter accept",
		"ip daddr 198.51.100.7 tcp dport 8443 counter accept",
		"egress counter drop", "forward counter drop",
	} {
		if !strings.Contains(got.String(), needle) {
			t.Errorf("missing %q in rules", needle)
		}
	}
	for _, unsafe := range []string{"ct state established", "0.0.0.0/0", "flush ruleset", "accept all"} {
		if strings.Contains(got.String(), unsafe) {
			t.Errorf("unsafe permissive rule %q", unsafe)
		}
	}
	again, err := Rules(samplePlan(), time.Now())
	if err != nil || got != again {
		t.Fatal("non-deterministic firewall plan")
	}
}

func TestRulesDeniedInputs(t *testing.T) {
	tests := []struct {
		name   string
		change func(*Plan)
	}{
		{"unapproved", func(p *Plan) { p.Decision.Status = "WAITING_WINDOW" }},
		{"deadline", func(p *Plan) { p.Decision.HardDeadline = time.Now().Add(-time.Second) }},
		{"no targets", func(p *Plan) { p.Decision.Targets = nil }},
		{"no infrastructure", func(p *Plan) { p.Infrastructure = nil }},
		{"unspecified", func(p *Plan) { p.Decision.Targets[0] = endpoint("0.0.0.0", 443) }},
		{"zone", func(p *Plan) { p.Decision.Targets[0] = endpoint("fe80::1%eth0", 443) }},
		{"zero port", func(p *Plan) { p.Decision.Targets[0].Port = 0 }},
		{"unknown protocol", func(p *Plan) { p.Infrastructure[0].Protocol = "tcp; accept" }},
		{"dup permit", func(p *Plan) { p.Infrastructure = append(p.Infrastructure, p.Infrastructure[0]) }},
		{"overlap", func(p *Plan) { p.Infrastructure[0] = Permit{Endpoint: p.Decision.Targets[0], Protocol: TCP} }},
		{"too many", func(p *Plan) {
			for i := 0; i < maxPermits; i++ {
				p.Decision.Targets = append(p.Decision.Targets, endpoint("203.0.113.10", uint16(i+1)))
			}
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := samplePlan()
			tc.change(&p)
			got, err := Rules(p, time.Now())
			if err == nil || got.String() != "" {
				t.Fatalf("unsafe plan admitted: %s", got)
			}
		})
	}
}

func TestRulesIPv6AndUDPInfrastructure(t *testing.T) {
	p := samplePlan()
	p.Decision.Targets = []scope.Endpoint{endpoint("2001:db8::20", 443)}
	p.Infrastructure = []Permit{{Endpoint: endpoint("2001:db8::53", 53), Protocol: UDP}}
	rules, err := Rules(p, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"ip6 daddr 2001:db8::20 tcp dport 443",
		"ip6 daddr 2001:db8::53 udp dport 53",
	} {
		if !strings.Contains(rules.String(), want) {
			t.Errorf("missing %s", want)
		}
	}
}

type fakeConfigurator struct {
	err     error
	applied atomic.Int32
	started chan struct{}
	block   <-chan struct{}
}

func (f *fakeConfigurator) Apply(ctx context.Context, _ RuleSet) error {
	f.applied.Add(1)
	if f.started != nil {
		close(f.started)
	}
	if f.block != nil {
		select {
		case <-f.block:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return f.err
}

type fakeLauncher struct {
	called atomic.Int32
	run    func(context.Context) error
}

func (f *fakeLauncher) restrictedWorkerLauncher() {}

func (f *fakeLauncher) Launch(ctx context.Context) error {
	f.called.Add(1)
	if f.run != nil {
		return f.run(ctx)
	}
	return nil
}

func TestSupervisorApplyFailureCannotLaunch(t *testing.T) {
	firewall := &fakeConfigurator{err: errors.New("nft denied")}
	launcher := &fakeLauncher{}
	s := NewSupervisor(firewall)
	if err := s.Run(context.Background(), samplePlan(), launcher); err == nil {
		t.Fatal("firewall failure ignored")
	}
	if launcher.called.Load() != 0 {
		t.Fatal("engine launched without firewall")
	}
	if err := s.Run(context.Background(), samplePlan(), launcher); err == nil {
		t.Fatal("failed namespace reused")
	}
	if firewall.applied.Load() != 1 {
		t.Fatal("firewall retried after failure")
	}
}

func TestSupervisorInvalidPolicyCannotApply(t *testing.T) {
	firewall := &fakeConfigurator{}
	launcher := &fakeLauncher{}
	p := samplePlan()
	p.Decision.Status = "WAITING_WINDOW"
	if err := NewSupervisor(firewall).Run(context.Background(), p, launcher); err == nil {
		t.Fatal("window violation accepted")
	}
	if firewall.applied.Load() != 0 || launcher.called.Load() != 0 {
		t.Fatal("invalid policy got execution")
	}
}

func TestSupervisorSingleUseAndConcurrency(t *testing.T) {
	release := make(chan struct{})
	firewall := &fakeConfigurator{started: make(chan struct{}), block: release}
	launcher := &fakeLauncher{}
	s := NewSupervisor(firewall)
	result := make(chan error, 1)
	go func() { result <- s.Run(context.Background(), samplePlan(), launcher) }()
	select {
	case <-firewall.started:
	case <-time.After(2 * time.Second):
		t.Fatal("firewall did not begin")
	}
	if err := s.Run(context.Background(), samplePlan(), launcher); err == nil {
		t.Fatal("second concurrent scan permitted")
	}
	close(release)
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	if launcher.called.Load() != 1 {
		t.Fatalf("expected 1 launch, got %d", launcher.called.Load())
	}
	if err := s.Run(context.Background(), samplePlan(), launcher); err == nil {
		t.Fatal("worker namespace reused")
	}
}

func TestSupervisorLocalDeadlineCancels(t *testing.T) {
	p := samplePlan()
	p.Decision.HardDeadline = time.Now().Add(90 * time.Millisecond)
	launcher := &fakeLauncher{run: func(ctx context.Context) error {
		<-ctx.Done()
		return ctx.Err()
	}}
	err := NewSupervisor(&fakeConfigurator{}).Run(context.Background(), p, launcher)
	if err == nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("hard deadline failed: %v", err)
	}
}

func TestSupervisorNilComponentsFailClosed(t *testing.T) {
	p := samplePlan()
	if err := NewSupervisor(nil).Run(context.Background(), p, &fakeLauncher{}); err == nil {
		t.Fatal("nil firewall permitted")
	}
	if err := NewSupervisor(&fakeConfigurator{}).Run(context.Background(), p, nil); err == nil {
		t.Fatal("nil launcher permitted")
	}
}

func TestRestrictedExecArgv(t *testing.T) {
	p := RestrictedExec{SetprivPath: "/usr/bin/setpriv", EnginePath: "/usr/local/bin/nuclei",
		EngineArgs: []string{"-ni", "-fhr"}, RuntimeDir: "/runtime"}
	argv, env, err := p.restrictedCommand()
	if err != nil {
		t.Fatal(err)
	}
	for _, wanted := range []string{
		"--reuid=10001", "--regid=10001", "--clear-groups",
		"--inh-caps=-all", "--ambient-caps=-all", "--bounding-set=-all",
		"--no-new-privs", "--", "/usr/local/bin/nuclei",
	} {
		found := false
		for _, arg := range argv {
			if arg == wanted {
				found = true
			}
		}
		if !found {
			t.Errorf("missing mandatory flag %s", wanted)
		}
	}
	if len(env) == 0 || !strings.Contains(strings.Join(env, " "), "HOME=/runtime/home") {
		t.Fatalf("runtime is not private: %v", env)
	}
}

func TestRestrictedExecRejectsUnexpectedCommands(t *testing.T) {
	cases := []RestrictedExec{
		{SetprivPath: "setpriv", EnginePath: "/usr/bin/nuclei", RuntimeDir: "/runtime"},
		{SetprivPath: "/usr/bin/setpriv", EnginePath: "/bin/bash", RuntimeDir: "/runtime"},
		{SetprivPath: "/usr/bin/setpriv", EnginePath: "/usr/bin/trivy", RuntimeDir: "/"},
		{SetprivPath: "/usr/bin/setpriv", EnginePath: "/usr/bin/trivy", RuntimeDir: "/runtime", EngineArgs: []string{"--bad\narg"}},
	}
	for _, p := range cases {
		if _, _, err := p.restrictedCommand(); err == nil {
			t.Fatalf("unexpected command accepted: %+v", p)
		}
	}
}
