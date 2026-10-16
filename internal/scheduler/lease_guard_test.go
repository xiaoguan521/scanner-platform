package scheduler

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type renewerFunc func(context.Context, Assignment) (time.Time, error)

func (fn renewerFunc) Renew(ctx context.Context, a Assignment) (time.Time, error) {
	return fn(ctx, a)
}

func validAssignment() Assignment {
	now := time.Now()
	return Assignment{
		TaskID: "chunk-demo-1", WorkerNodeID: "worker-demo-1",
		PinnedRuleVersion: "20261016.01",
		LeaseExpiresAt:    now.Add(150 * time.Millisecond),
		HardDeadline:      now.Add(550 * time.Millisecond),
	}
}

func shortGuard() LeaseGuard {
	return LeaseGuard{
		RenewInterval:    15 * time.Millisecond,
		RenewTimeout:     25 * time.Millisecond,
		MaxLeaseDuration: time.Second,
		ShutdownGrace:    100 * time.Millisecond,
	}
}

func waitForCancel(ctx context.Context) error {
	<-ctx.Done()
	return ctx.Err()
}

func TestLeaseGuardCompletesWithSuccessfulRenewals(t *testing.T) {
	lease := validAssignment()
	var calls atomic.Int32
	renewer := renewerFunc(func(ctx context.Context, a Assignment) (time.Time, error) {
		calls.Add(1)
		if a.PinnedRuleVersion != lease.PinnedRuleVersion || a.WorkerNodeID != lease.WorkerNodeID {
			t.Errorf("renewal changed assignment binding")
		}
		return time.Now().Add(200 * time.Millisecond), nil
	})
	result := shortGuard().Run(context.Background(), lease, renewer, func(ctx context.Context) error {
		select {
		case <-time.After(235 * time.Millisecond):
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	})
	if result != nil {
		t.Fatalf("job stopped despite healthy lease: %v", result)
	}
	if calls.Load() == 0 {
		t.Fatal("no successful renewals")
	}
}

func TestLeaseGuardStopsAfterContinuousOutage(t *testing.T) {
	lease := validAssignment()
	var calls atomic.Int32
	start := time.Now()
	err := shortGuard().Run(context.Background(), lease, renewerFunc(func(ctx context.Context, a Assignment) (time.Time, error) {
		calls.Add(1)
		return time.Time{}, errors.New("node API unavailable")
	}), waitForCancel)
	if !errors.Is(err, ErrLeaseExpired) {
		t.Fatalf("lease loss did not terminate job: %v", err)
	}
	if calls.Load() == 0 || time.Since(start) > time.Second {
		t.Fatalf("renewal attempts missing or late termination: %d, %v", calls.Load(), time.Since(start))
	}
}

func TestLeaseGuardStuckRPCDoesNotBlockExpiry(t *testing.T) {
	lease := validAssignment()
	wait := make(chan struct{})
	defer close(wait)
	started := make(chan struct{}, 1)
	err := shortGuard().Run(context.Background(), lease, renewerFunc(func(ctx context.Context, a Assignment) (time.Time, error) {
		select {
		case started <- struct{}{}:
		default:
		}
		<-wait // deliberately ignores ctx; must not block watchdog expiration
		return time.Time{}, errors.New("late RPC")
	}), waitForCancel)
	if !errors.Is(err, ErrLeaseExpired) {
		t.Fatalf("stalled renew request blocked expiry: %v", err)
	}
	select {
	case <-started:
	default:
		t.Fatal("stalled renewal not exercised")
	}
}

func TestLeaseGuardHardDeadlineStopsDuringOutage(t *testing.T) {
	lease := validAssignment()
	lease.LeaseExpiresAt = time.Now().Add(500 * time.Millisecond)
	lease.HardDeadline = time.Now().Add(80 * time.Millisecond)
	err := shortGuard().Run(context.Background(), lease, renewerFunc(func(ctx context.Context, a Assignment) (time.Time, error) {
		return time.Time{}, errors.New("offline")
	}), waitForCancel)
	if !errors.Is(err, ErrHardDeadline) {
		t.Fatalf("hard deadline bypassed: %v", err)
	}
}

func TestLeaseGuardRejectsExpiredOrUnboundBeforeExecution(t *testing.T) {
	valid := validAssignment()
	cfg := shortGuard()
	cases := []struct {
		name  string
		alter func(*Assignment)
	}{
		{"no task", func(a *Assignment) { a.TaskID = "" }},
		{"no node", func(a *Assignment) { a.WorkerNodeID = "" }},
		{"no pinned version", func(a *Assignment) { a.PinnedRuleVersion = "" }},
		{"expired", func(a *Assignment) { a.LeaseExpiresAt = time.Now().Add(-time.Millisecond) }},
		{"missing hard deadline", func(a *Assignment) { a.HardDeadline = time.Time{} }},
		{"lease too long", func(a *Assignment) { a.LeaseExpiresAt = time.Now().Add(time.Hour) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := valid
			tc.alter(&a)
			var started atomic.Bool
			err := cfg.Run(context.Background(), a, renewerFunc(func(context.Context, Assignment) (time.Time, error) {
				return time.Now().Add(100 * time.Millisecond), nil
			}), func(ctx context.Context) error { started.Store(true); return nil })
			if !errors.Is(err, ErrInvalidLease) || started.Load() {
				t.Fatalf("unapproved lease executed: %v, started=%v", err, started.Load())
			}
		})
	}
}

func TestLeaseGuardInvalidRenewalRevokesExecution(t *testing.T) {
	lease := validAssignment()
	err := shortGuard().Run(context.Background(), lease, renewerFunc(func(ctx context.Context, a Assignment) (time.Time, error) {
		return time.Now().Add(3 * time.Hour), nil
	}), waitForCancel)
	if !errors.Is(err, ErrInvalidRenewal) {
		t.Fatalf("unbounded lease extension accepted: %v", err)
	}
}

func TestLeaseGuardHonorsCallerCancellation(t *testing.T) {
	lease := validAssignment()
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()
	err := shortGuard().Run(ctx, lease, renewerFunc(func(context.Context, Assignment) (time.Time, error) {
		return time.Now().Add(time.Second), nil
	}), waitForCancel)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("parent cancellation not honored: %v", err)
	}
}

func TestLeaseGuardReportsWorkerThatIgnoresStop(t *testing.T) {
	lease := validAssignment()
	lease.LeaseExpiresAt = time.Now().Add(60 * time.Millisecond)
	cfg := shortGuard()
	cfg.ShutdownGrace = 25 * time.Millisecond
	block := make(chan struct{})
	defer close(block)
	err := cfg.Run(context.Background(), lease, renewerFunc(func(ctx context.Context, a Assignment) (time.Time, error) {
		return time.Time{}, errors.New("offline")
	}), func(ctx context.Context) error {
		<-block // violation: process did not obey cancellation
		return nil
	})
	if !errors.Is(err, ErrLeaseExpired) || !errors.Is(err, ErrWorkerStopTimeout) {
		t.Fatalf("unproven worker shutdown was not reported: %v", err)
	}
}

func TestLeaseGuardMissingConfigurationFailsClosed(t *testing.T) {
	lease := validAssignment()
	var started atomic.Bool
	work := func(context.Context) error { started.Store(true); return nil }
	cfg := shortGuard()
	cfg.RenewInterval = 0
	err := cfg.Run(context.Background(), lease, renewerFunc(func(context.Context, Assignment) (time.Time, error) {
		return time.Now().Add(time.Second), nil
	}), work)
	if !errors.Is(err, ErrInvalidLease) || started.Load() {
		t.Fatalf("invalid duration accepted: %v", err)
	}
	err = shortGuard().Run(context.Background(), lease, nil, work)
	if err == nil || !strings.Contains(err.Error(), "required") {
		t.Fatalf("nil renewer accepted: %v", err)
	}
}
