// Package supervisor provides the restart policy for one-shot Worker
// processes. It does not start processes or know anything about scan data.
package supervisor

import (
	"context"
	"errors"
	"fmt"
	"time"
)

var ErrRestartLimit = errors.New("worker supervisor restart limit reached")

// Policy controls how a one-shot child is relaunched. MaxRestarts is the
// number of relaunches after the first cycle; zero means unlimited.
type Policy struct {
	RestartDelay time.Duration
	MaxBackoff   time.Duration
	MaxRestarts  int
}

func (p Policy) validate() error {
	if p.RestartDelay < 0 || p.MaxBackoff < 0 || p.MaxBackoff < p.RestartDelay || p.MaxRestarts < 0 {
		return errors.New("invalid supervisor restart policy")
	}
	return nil
}

// Run repeatedly invokes one one-shot child cycle. The cycle must return the
// child's exit code and may return an error when it could not start. A zero
// exit is treated as a normal completed task and uses the base delay; failure
// exits use exponential backoff capped by MaxBackoff. Cancellation never
// causes a relaunch.
func Run(ctx context.Context, policy Policy, cycle func(context.Context) (int, error), sleep func(context.Context, time.Duration) error, report func(code int, err error, delay time.Duration)) error {
	if cycle == nil || sleep == nil {
		return errors.New("supervisor cycle and sleep callbacks are required")
	}
	if err := policy.validate(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	failures := 0
	restarts := 0
	for {
		code, err := cycle(ctx)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if policy.MaxRestarts > 0 && restarts >= policy.MaxRestarts {
			return fmt.Errorf("%w: %d restarts, last exit code %d", ErrRestartLimit, restarts, code)
		}
		if code == 0 && err == nil {
			failures = 0
		} else {
			failures++
		}
		delay := policy.RestartDelay
		if failures > 0 && delay > 0 {
			for i := 1; i < failures; i++ {
				if delay >= policy.MaxBackoff && policy.MaxBackoff > 0 {
					delay = policy.MaxBackoff
					break
				}
				delay *= 2
				if policy.MaxBackoff > 0 && delay > policy.MaxBackoff {
					delay = policy.MaxBackoff
					break
				}
			}
		}
		if report != nil {
			report(code, err, delay)
		}
		restarts++
		if err := sleep(ctx, delay); err != nil {
			return err
		}
	}
}

// Sleep waits without blocking shutdown indefinitely.
func Sleep(ctx context.Context, delay time.Duration) error {
	if delay <= 0 {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			return nil
		}
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
