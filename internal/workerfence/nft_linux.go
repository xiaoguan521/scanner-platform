//go:build linux

package workerfence

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

// nftConfigurator runs ONE atomic nft transaction in the worker's own netns.
// Deployment MUST isolate the network namespace from the host before calling.
// This is not connected to cmd/worker until that precondition is validated.
type nftConfigurator struct {
	executable string
	parentNS   *os.File
}

// NewConfigurator requires a namespace descriptor that the trusted launcher
// opened BEFORE it created the worker's private network namespace. An absent
// or identical namespace prevents modification of host/parent firewall rules.
// Never accept an arbitrary descriptor or path from a task API.
func NewConfigurator(nftPath string, parentNS *os.File) Configurator {
	return &nftConfigurator{executable: nftPath, parentNS: parentNS}
}

func (c *nftConfigurator) requireIsolatedNamespace() error {
	if c.parentNS == nil {
		return errors.New("pre-isolation network namespace descriptor required")
	}
	currentNS, err := os.Open("/proc/self/ns/net")
	if err != nil {
		return fmt.Errorf("open current network namespace: %w", err)
	}
	defer currentNS.Close()
	// NSFS_MAGIC; verify both descriptors actually reference Linux namespace
	// objects, not regular files handed to the supervisor by mistake.
	const nsfsMagic = 0x6e736673
	for _, fd := range []*os.File{c.parentNS, currentNS} {
		var info syscall.Statfs_t
		if err := syscall.Fstatfs(int(fd.Fd()), &info); err != nil {
			return fmt.Errorf("inspect network namespace: %w", err)
		}
		if uint64(info.Type) != nsfsMagic {
			return errors.New("network namespace descriptor is not nsfs")
		}
	}
	before, err := c.parentNS.Stat()
	if err != nil {
		return fmt.Errorf("inspect parent namespace: %w", err)
	}
	current, err := currentNS.Stat()
	if err != nil {
		return fmt.Errorf("inspect current namespace: %w", err)
	}
	if os.SameFile(before, current) {
		return errors.New("refusing to alter parent network namespace firewall")
	}
	return nil
}

func (c *nftConfigurator) Apply(ctx context.Context, rules RuleSet) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("firewall context canceled: %w", err)
	}
	if c == nil || !filepath.IsAbs(c.executable) || filepath.Clean(c.executable) != c.executable {
		return errors.New("nft executable must use an absolute canonical path")
	}
	if err := c.requireIsolatedNamespace(); err != nil {
		return fmt.Errorf("isolation not established: %w", err)
	}
	if os.Geteuid() != 0 {
		return errors.New("nft supervisor requires root in its isolated namespace")
	}
	if rules.script == "" {
		return errors.New("refusing empty nft policy")
	}
	cmd := exec.CommandContext(ctx, c.executable, "-f", "-")
	cmd.Stdin = strings.NewReader(rules.script)
	// Do not return raw nft stderr: it may contain internal asset addresses.
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("atomic firewall transaction rejected: %w", err)
	}
	return nil
}
