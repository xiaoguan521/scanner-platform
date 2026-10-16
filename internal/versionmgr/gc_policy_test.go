package versionmgr

import (
	"context"
	"errors"
	"testing"
	"time"
)

type runningCounter func(context.Context, string, string) (int, error)

func (f runningCounter) CountRunning(ctx context.Context, node, version string) (int, error) {
	return f(ctx, node, version)
}
func fixture() (GCPolicy, GCRequest, time.Time) {
	now := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	p := GCPolicy{Grace: DefaultGCGrace, Running: runningCounter(func(_ context.Context, node, v string) (int, error) {
		if node != "worker-demo" || v != "20261015.01" {
			return 0, errors.New("bad Server query")
		}
		return 0, nil
	})}
	r := GCRequest{NodeID: "worker-demo", Version: "20261015.01", CurrentVersion: "20261016.02", BackupVersion: "20261016.01", RetiredAt: now.Add(-3 * time.Hour), Phase: Quarantine}
	return p, r, now
}
func TestGCTwoPhasesOnlyWithZeroRunningTasks(t *testing.T) {
	p, r, now := fixture()
	if err := p.Check(context.Background(), r, now); err != nil {
		t.Fatal(err)
	}
	r.Phase = Delete
	r.QuarantinedAt = now.Add(-30 * time.Minute)
	if err := p.Check(context.Background(), r, now); err != nil {
		t.Fatal(err)
	}
}
func TestGCProtectCurrentAndBackup(t *testing.T) {
	for _, v := range []string{"20261016.02", "20261016.01"} {
		p, r, now := fixture()
		r.Version = v
		if err := p.Check(context.Background(), r, now); !errors.Is(err, ErrGCProtected) {
			t.Fatalf("protected %s: %v", v, err)
		}
	}
}
func TestGCServerOfflineAndRunningLeaseFailClosed(t *testing.T) {
	for _, tc := range []struct {
		name    string
		count   int
		failure error
		want    error
	}{
		{"offline", 0, errors.New("offline"), ErrGCUnverified},
		{"active pinned", 1, nil, ErrGCInUse},
		{"invalid negative count", -1, nil, ErrGCUnverified},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, r, now := fixture()
			p.Running = runningCounter(func(context.Context, string, string) (int, error) { return tc.count, tc.failure })
			if err := p.Check(context.Background(), r, now); !errors.Is(err, tc.want) {
				t.Fatalf("unsafe GC: %v", err)
			}
		})
	}
}
func TestGCRechecksWhenProceedingToDelete(t *testing.T) {
	p, r, now := fixture()
	n := 0
	p.Running = runningCounter(func(context.Context, string, string) (int, error) {
		n++
		if n == 1 {
			return 0, nil
		}
		return 1, nil
	})
	if err := p.Check(context.Background(), r, now); err != nil {
		t.Fatal(err)
	}
	r.Phase = Delete
	r.QuarantinedAt = now.Add(-10 * time.Minute)
	if err := p.Check(context.Background(), r, now); !errors.Is(err, ErrGCInUse) {
		t.Fatalf("missing second check: %v", err)
	}
}
func TestGCRejectsInvalidSnapshot(t *testing.T) {
	cases := []struct {
		name   string
		change func(*GCPolicy, *GCRequest, time.Time)
		want   error
	}{
		{"traversal", func(_ *GCPolicy, r *GCRequest, _ time.Time) { r.Version = "../20261015.01" }, ErrGCUnverified},
		{"no CURRENT", func(_ *GCPolicy, r *GCRequest, _ time.Time) { r.CurrentVersion = "" }, ErrGCUnverified},
		{"no backup", func(_ *GCPolicy, r *GCRequest, _ time.Time) { r.BackupVersion = "" }, ErrGCUnverified},
		{"no node", func(_ *GCPolicy, r *GCRequest, _ time.Time) { r.NodeID = "" }, ErrGCUnverified},
		{"short grace", func(p *GCPolicy, _ *GCRequest, _ time.Time) { p.Grace = time.Minute }, ErrGCUnverified},
		{"retired too recently", func(_ *GCPolicy, r *GCRequest, n time.Time) { r.RetiredAt = n.Add(-time.Hour) }, ErrGCProtected},
		{"future retired", func(_ *GCPolicy, r *GCRequest, n time.Time) { r.RetiredAt = n.Add(time.Minute) }, ErrGCProtected},
		{"delete without quarantine", func(_ *GCPolicy, r *GCRequest, _ time.Time) { r.Phase = Delete }, ErrGCUnverified},
		{"unknown phase", func(_ *GCPolicy, r *GCRequest, _ time.Time) { r.Phase = "ERASE" }, ErrGCUnverified},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, r, now := fixture()
			tc.change(&p, &r, now)
			if err := p.Check(context.Background(), r, now); !errors.Is(err, tc.want) {
				t.Fatalf("unsafe GC: %v", err)
			}
		})
	}
}
func TestGCCanceledContextFailsClosed(t *testing.T) {
	p, r, now := fixture()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := p.Check(ctx, r, now); !errors.Is(err, ErrGCUnverified) {
		t.Fatalf("canceled GC allowed: %v", err)
	}
}
