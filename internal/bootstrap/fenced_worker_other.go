//go:build !linux

package bootstrap

import (
	"context"
	"errors"
	"io"

	"scanner-platform/internal/taskflow"
)

func newFencedTaskRunner(_ fencedRunnerConfig) (*fencedTaskRunner, error) {
	return nil, errors.New("kernel-enforced worker fence requires Linux isolated network namespace")
}

func (r *fencedTaskRunner) run(_ context.Context, _ string, _ taskflow.Task) (fencedTaskOutput, error) {
	return fencedTaskOutput{}, errors.New("kernel-enforced worker fence requires Linux isolated network namespace")
}

func runFencedChild(_, _ io.Writer) int { return 2 }
