package versionmgr

import (
	"context"
	"errors"
	"time"
)

// renameWithRetry is separately testable without depending on the platform's
// filesystem error injection. Each retry leaves the prior CURRENT intact.
func renameWithRetry(
	ctx context.Context,
	src, dst string,
	rename func(string, string) error,
	retryable func(error) bool,
) error {
	const attempts = 5
	var err error
	for i := 0; i < attempts; i++ {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err = rename(src, dst); err == nil {
			return nil
		}
		if !retryable(err) || i == attempts-1 {
			return err
		}
		timer := time.NewTimer(time.Duration(i+1) * 20 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return errors.Join(ctx.Err(), err)
		case <-timer.C:
		}
	}
	return err
}
