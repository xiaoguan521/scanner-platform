package workerfence

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

// Configurator installs an nftables transaction in the worker's private netns.
type Configurator interface {
	Apply(context.Context, string) error
}

// Launcher MUST start the approved engine without root or capabilities.
// Production integrations must use the Linux restricted launcher, not arbitrary callbacks.
type Launcher interface {
	Launch(context.Context) error
}

// Supervisor is single-use: one fresh network namespace per worker task.
// It never attempts to flush or relax existing firewall rules between tasks.
type Supervisor struct {
	mu       sync.Mutex
	used     bool
	firewall Configurator
	now      func() time.Time
}

func NewSupervisor(firewall Configurator) *Supervisor {
	return &Supervisor{firewall: firewall, now: time.Now}
}

func (s *Supervisor) Run(ctx context.Context, p Plan, launch Launcher) error {
	if s == nil || s.firewall == nil || launch == nil || s.now == nil {
		return errors.New("missing supervisor, firewall or restricted launcher")
	}
	if !s.mu.TryLock() {
		return errors.New("worker is already executing or configuring a task")
	}
	defer s.mu.Unlock()
	if s.used {
		return errors.New("worker network namespace already consumed; start a fresh worker")
	}
	// A failed nft application might partially modify the environment.
	// Never retry in this worker; the namespace must be destroyed.
	s.used = true

	rules, err := Rules(p, s.now())
	if err != nil {
		return fmt.Errorf("worker fence plan rejected: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("task canceled before fence: %w", err)
	}
	taskCtx, cancel := context.WithDeadline(ctx, p.Decision.HardDeadline)
	defer cancel()
	if err := s.firewall.Apply(taskCtx, rules); err != nil {
		return fmt.Errorf("worker fence application failed; engine not started: %w", err)
	}
	if err := taskCtx.Err(); err != nil {
		return fmt.Errorf("deadline/cancellation after fence: %w", err)
	}
	// Only callers that have separately verified namespace isolation, command
	// allowlisting and privilege drop may provide a real Launcher.
	if err := launch.Launch(taskCtx); err != nil {
		return fmt.Errorf("restricted execution failed: %w", err)
	}
	return nil
}
