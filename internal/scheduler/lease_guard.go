package scheduler

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"time"
)

var (
	ErrLeaseExpired      = errors.New("worker lease expired")
	ErrHardDeadline      = errors.New("task hard deadline reached")
	ErrInvalidLease      = errors.New("invalid server lease")
	ErrInvalidRenewal    = errors.New("invalid lease renewal")
	ErrWorkerStopTimeout = errors.New("worker did not stop within shutdown grace")
)

// The local Phase 0 lease defaults are deliberately short. A Worker must
// renew well before the Server lease expires so a temporary API outage cannot
// silently extend execution past the last Server-confirmed deadline.
const (
	DefaultLeaseDuration = 45 * time.Second
	DefaultRenewInterval = 10 * time.Second
	DefaultRenewTimeout  = 5 * time.Second
	DefaultShutdownGrace = 5 * time.Second
)

// DefaultLeaseGuard returns the safe local defaults used by the real Worker.
// Tests and embedding callers may replace individual values explicitly.
func DefaultLeaseGuard() LeaseGuard {
	return LeaseGuard{
		RenewInterval:    DefaultRenewInterval,
		RenewTimeout:     DefaultRenewTimeout,
		MaxLeaseDuration: DefaultLeaseDuration,
		ShutdownGrace:    DefaultShutdownGrace,
	}
}

// Assignment is a single Server-issued chunk lease, bound to a worker node
// and a precise local rule-bundle version. It is NOT scan authorization:
// scope admission and the network fence must also succeed before execution.
type Assignment struct {
	TaskID            string
	WorkerNodeID      string
	PinnedRuleVersion string
	LeaseExpiresAt    time.Time
	HardDeadline      time.Time
}

// Renewer talks only to the Server's authenticated node API; it must not
// silently create a new task or change the pinned rule version.
type Renewer interface {
	Renew(context.Context, Assignment) (time.Time, error)
}

// LeaseGuard enforces local expiry even during loss of Server connectivity.
// The durations are explicit so missing configuration fails closed.
type LeaseGuard struct {
	RenewInterval    time.Duration
	RenewTimeout     time.Duration
	MaxLeaseDuration time.Duration
	ShutdownGrace    time.Duration
}

func (g LeaseGuard) validate(a Assignment, renew Renewer, work func(context.Context) error, now time.Time) error {
	if renew == nil || work == nil || strings.TrimSpace(a.TaskID) == "" ||
		strings.TrimSpace(a.WorkerNodeID) == "" || strings.TrimSpace(a.PinnedRuleVersion) == "" {
		return fmt.Errorf("%w: task, worker, version and callbacks required", ErrInvalidLease)
	}
	if g.RenewInterval <= 0 || g.RenewTimeout <= 0 || g.MaxLeaseDuration <= 0 || g.ShutdownGrace <= 0 ||
		g.RenewInterval >= g.MaxLeaseDuration || g.RenewTimeout > g.MaxLeaseDuration {
		return fmt.Errorf("%w: invalid guard durations", ErrInvalidLease)
	}
	if !a.HardDeadline.After(now) || !a.LeaseExpiresAt.After(now) ||
		a.LeaseExpiresAt.Sub(now) > g.MaxLeaseDuration {
		return fmt.Errorf("%w: missing, expired or overly long deadline", ErrInvalidLease)
	}
	return nil
}

type renewResult struct {
	expiry time.Time
	err    error
}

// watch never extends a lease on a failed renewal. A stalled renewal cannot
// prevent expiry: RPC is run separately and bounded by the earlier of local
// expiry and RenewTimeout. A real Renewer MUST honor context cancellation.
func (g LeaseGuard) watch(ctx context.Context, a Assignment, renew Renewer, lastConfirmed *atomic.Int64) error {
	expiry := a.LeaseExpiresAt
	next := time.NewTimer(g.RenewInterval)
	defer next.Stop()
	leaseTimer := time.NewTimer(time.Until(expiry))
	defer leaseTimer.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-leaseTimer.C:
			return ErrLeaseExpired
		case <-next.C:
			if !time.Now().Before(expiry) {
				return ErrLeaseExpired
			}
			rpcDeadline := time.Now().Add(g.RenewTimeout)
			if expiry.Before(rpcDeadline) {
				rpcDeadline = expiry
			}
			rpcCtx, cancel := context.WithDeadline(ctx, rpcDeadline)
			reply := make(chan renewResult, 1)
			go func() {
				newExpiry, err := renew.Renew(rpcCtx, a)
				reply <- renewResult{expiry: newExpiry, err: err}
			}()
			select {
			case <-ctx.Done():
				cancel()
				return ctx.Err()
			case <-leaseTimer.C:
				cancel()
				return ErrLeaseExpired
			case <-rpcCtx.Done():
				cancel()
				if !time.Now().Before(expiry) {
					return ErrLeaseExpired
				}
			case response := <-reply:
				cancel()
				now := time.Now()
				if !now.Before(expiry) {
					return ErrLeaseExpired
				}
				if response.err == nil {
					if !response.expiry.After(expiry) || response.expiry.Sub(now) > g.MaxLeaseDuration {
						return fmt.Errorf("%w: Server returned an invalid expiration", ErrInvalidRenewal)
					}
					expiry = response.expiry
					lastConfirmed.Store(expiry.UnixNano())
					if !leaseTimer.Stop() {
						select {
						case <-leaseTimer.C:
						default:
						}
					}
					leaseTimer.Reset(time.Until(expiry))
				}
				// On connection errors, retain the last confirmed expiry.
			}
			next.Reset(g.RenewInterval)
		}
	}
}

// Run guards one chunk, cancels its work on lease loss or hard deadline,
// and waits a bounded interval for the Worker executor to acknowledge stop.
// Returning ErrWorkerStopTimeout means termination has NOT been proven: the
// process supervisor must escalate to kill/cgroup termination before reuse.
func (g LeaseGuard) Run(ctx context.Context, a Assignment, renew Renewer, work func(context.Context) error) error {
	now := time.Now()
	if err := g.validate(a, renew, work, now); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("lease task canceled before start: %w", err)
	}
	var lastConfirmed atomic.Int64
	lastConfirmed.Store(a.LeaseExpiresAt.UnixNano())
	taskCtx, cancel := context.WithDeadline(ctx, a.HardDeadline)
	defer cancel()

	completed := make(chan error, 1)
	watchFinished := make(chan error, 1)
	go func() { completed <- work(taskCtx) }()
	go func() { watchFinished <- g.watch(taskCtx, a, renew, &lastConfirmed) }()

	stop := func(reason error) error {
		cancel()
		timer := time.NewTimer(g.ShutdownGrace)
		defer timer.Stop()
		select {
		case workerErr := <-completed:
			if workerErr != nil && !errors.Is(workerErr, context.Canceled) &&
				!errors.Is(workerErr, context.DeadlineExceeded) {
				return errors.Join(reason, fmt.Errorf("worker stop: %w", workerErr))
			}
			return reason
		case <-timer.C:
			return errors.Join(reason, ErrWorkerStopTimeout)
		}
	}

	select {
	case result := <-completed:
		if time.Now().UnixNano() >= lastConfirmed.Load() {
			return ErrLeaseExpired
		}
		if !time.Now().Before(a.HardDeadline) {
			return fmt.Errorf("%w: %w", ErrHardDeadline, context.DeadlineExceeded)
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		return result
	case err := <-watchFinished:
		if !time.Now().Before(a.HardDeadline) {
			return stop(ErrHardDeadline)
		}
		if ctx.Err() != nil {
			return stop(ctx.Err())
		}
		return stop(err)
	case <-taskCtx.Done():
		if ctx.Err() != nil {
			return stop(ctx.Err())
		}
		return stop(ErrHardDeadline)
	}
}
