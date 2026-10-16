//go:build !linux

package workerfence

import (
	"context"
	"errors"
)

func (p RestrictedExec) Launch(_ context.Context) error {
	return errors.New("restricted worker engine launcher is supported only on Linux")
}
