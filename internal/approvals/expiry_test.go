package approvals

import (
	"testing"
	"time"
)

func TestScopeExpiryState(t *testing.T) {
	now := time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		name    string
		status  string
		expires time.Time
		want    string
	}{
		{name: "pending ignores future date", status: "PENDING", expires: now.Add(time.Hour), want: "NOT_APPLICABLE"},
		{name: "approved active", status: "APPROVED", expires: now.Add(8 * 24 * time.Hour), want: "ACTIVE"},
		{name: "approved expiring at boundary", status: "APPROVED", expires: now.Add(7 * 24 * time.Hour), want: "EXPIRING"},
		{name: "approved expired", status: "APPROVED", expires: now, want: "EXPIRED"},
		{name: "revoked ignores past date", status: "REVOKED", expires: now.Add(-time.Hour), want: "NOT_APPLICABLE"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := scopeExpiryState(test.status, test.expires, now); got != test.want {
				t.Fatalf("scopeExpiryState(%q, %s)=%q, want %q", test.status, test.expires, got, test.want)
			}
		})
	}
}
