//go:build linux

package workerfence

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

// Launch invokes util-linux setpriv directly with a structured argv slice.
// setpriv execs the trusted engine and must verify privilege drop in lab.
// Process-group termination on cancellation is a PoC-level safeguard; full
// cgroup kill semantics remain required before production engine integration.
func (p RestrictedExec) Launch(ctx context.Context) error {
	argv, env, err := p.restrictedCommand()
	if err != nil {
		return fmt.Errorf("restricted command denied: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("restricted launch canceled: %w", err)
	}
	cmd := exec.Command(p.SetprivPath, argv...)
	cmd.Env = env
	cmd.Stdin = nil
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("restricted launch failed: %w", err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			return fmt.Errorf("restricted process failed: %w", err)
		}
		return nil
	case <-ctx.Done():
		// Kill the entire process group rather than only the launcher PID.
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		<-done
		return fmt.Errorf("restricted process canceled: %w", ctx.Err())
	}
}
