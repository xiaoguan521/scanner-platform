//go:build !linux

package workerfence

import (
	"context"
	"errors"
)

// TaskCgroup is unavailable on non-Linux platforms. Fenced mode is already
// Linux-only; exposing the same API keeps callers buildable cross-platform.
type TaskCgroup struct{}

func NewTaskCgroup(string) (*TaskCgroup, error) {
	return nil, errors.New("cgroup-v2 task isolation requires Linux")
}
func OpenTaskCgroup(string, string) (*TaskCgroup, error) {
	return nil, errors.New("cgroup-v2 task isolation requires Linux")
}
func (*TaskCgroup) Path() string     { return "" }
func (*TaskCgroup) Attach(int) error { return errors.New("cgroup-v2 task isolation requires Linux") }
func (*TaskCgroup) Detach(int) error { return errors.New("cgroup-v2 task isolation requires Linux") }
func (*TaskCgroup) Kill() error      { return errors.New("cgroup-v2 task isolation requires Linux") }
func (*TaskCgroup) Close(context.Context) error {
	return errors.New("cgroup-v2 task isolation requires Linux")
}
