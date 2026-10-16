package scope

import (
	"context"
	"net/netip"
	"testing"
	"time"
)

func now() time.Time {
	return time.Date(2026, 10, 16, 10, 0, 0, 0, time.FixedZone("SGT", 8*3600))
}

func policy() Policy {
	return Policy{
		Approved: true, ApprovedBy: "example-approver", ApprovalTicket: "DEMO-TICKET",
		CIDRs: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}, MaxTargets: 3,
		Ports: []PortGrant{
			{Endpoint: "192.0.2.10:443", Kind: Web},
			{Endpoint: "192.0.2.10:8443", Kind: ExcludedProxy},
			{Endpoint: "192.0.2.20:80", Kind: Web, Quarantined: true},
		},
		Windows: []Window{{Weekdays: []time.Weekday{time.Friday}, Start: "09:00", End: "18:00", TimeZone: "Asia/Singapore"}},
	}
}

func TestApprovedExplicitEndpoint(t *testing.T) {
	decision, err := Admit(context.Background(), policy(), []string{"192.0.2.10:443"}, now())
	if err != nil {
		t.Fatal(err)
	}
	if decision.Status != "READY" || len(decision.Targets) != 1 || decision.HardDeadline.Hour() != 18 {
		t.Fatalf("unexpected admission: %+v", decision)
	}
}

func TestUnauthorizedEndpointDeniesWholeBatch(t *testing.T) {
	bad := []string{
		"192.0.2.10:22", "192.0.2.10:8443", "192.0.2.20:80",
		"192.0.2.11:443", "198.51.100.5:443", "example.com:443",
		"192.0.2.0/24:443", "192.0.2.10:0", "192.0.2.10:65536",
	}
	for _, candidate := range bad {
		t.Run(candidate, func(t *testing.T) {
			got, err := Admit(context.Background(), policy(), []string{"192.0.2.10:443", candidate}, now())
			if err == nil || len(got.Targets) != 0 {
				t.Fatalf("unsafe partial approval: %+v, %v", got, err)
			}
		})
	}
}

func TestMissingApprovalAndExpiredScope(t *testing.T) {
	p := policy()
	p.ApprovalTicket = ""
	if _, err := Admit(context.Background(), p, []string{"192.0.2.10:443"}, now()); err == nil {
		t.Fatal("missing ticket accepted")
	}
	p = policy()
	p.ExpiresAt = now().Add(-time.Second)
	if _, err := Admit(context.Background(), p, []string{"192.0.2.10:443"}, now()); err == nil {
		t.Fatal("expired scope accepted")
	}
	p = policy()
	p.MaxTargets = 0
	if _, err := Admit(context.Background(), p, []string{"192.0.2.10:443"}, now()); err == nil {
		t.Fatal("zero target limit accepted")
	}
}

func TestDuplicatesAndInvalidConfigFailClosed(t *testing.T) {
	p := policy()
	if _, err := Admit(context.Background(), p, []string{"192.0.2.10:443", "192.0.2.10:443"}, now()); err == nil {
		t.Fatal("duplicate target accepted")
	}
	p = policy()
	p.Ports = append(p.Ports, p.Ports[0])
	if _, err := Admit(context.Background(), p, []string{"192.0.2.10:443"}, now()); err == nil {
		t.Fatal("duplicate grant accepted")
	}
	p = policy()
	p.Windows[0].Start = "25:00"
	if _, err := Admit(context.Background(), p, []string{"192.0.2.10:443"}, now()); err == nil {
		t.Fatal("malformed clock accepted")
	}
	p = policy()
	p.Windows[0].Weekdays = []time.Weekday{time.Weekday(20)}
	if _, err := Admit(context.Background(), p, []string{"192.0.2.10:443"}, now()); err == nil {
		t.Fatal("invalid weekday accepted")
	}
}

func TestOutsideWindowIsNotPermission(t *testing.T) {
	got, err := Admit(context.Background(), policy(), []string{"192.0.2.10:443"}, now().Add(12*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "WAITING_WINDOW" || !got.HardDeadline.IsZero() {
		t.Fatalf("unsafe status: %+v", got)
	}
}

func TestCrossMidnightWindow(t *testing.T) {
	w := []Window{{Weekdays: []time.Weekday{time.Friday}, Start: "23:00", End: "05:00", TimeZone: "Asia/Singapore"}}
	oneAM := time.Date(2026, 10, 17, 1, 0, 0, 0, time.FixedZone("SGT", 8*3600))
	_, open, err := ActiveDeadline(w, oneAM)
	if err != nil || !open {
		t.Fatalf("Saturday 1 AM should be open: %v", err)
	}
	_, open, err = ActiveDeadline(w, oneAM.Add(4*time.Hour))
	if err != nil || open {
		t.Fatalf("Saturday 5 AM should be closed: %v", err)
	}
}

func TestCanceledContextAndExpiryDeadline(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Admit(ctx, policy(), []string{"192.0.2.10:443"}, now()); err == nil {
		t.Fatal("canceled request accepted")
	}
	p := policy()
	p.ExpiresAt = now().Add(30 * time.Minute)
	got, err := Admit(context.Background(), p, []string{"192.0.2.10:443"}, now())
	if err != nil || !got.HardDeadline.Equal(p.ExpiresAt) {
		t.Fatalf("scope expiry not enforced: %+v, %v", got, err)
	}
}
