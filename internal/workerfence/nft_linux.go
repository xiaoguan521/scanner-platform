//go:build linux

package workerfence

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
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

const maxNftCounterOutput = 1 << 20

// ReadDropCounters reads only the generated drop rules from the isolated
// namespace. The JSON parser deliberately ignores all other nft expressions
// and never returns the command output to callers or logs.
func (c *nftConfigurator) ReadDropCounters(ctx context.Context) (DropCounters, error) {
	if err := ctx.Err(); err != nil {
		return DropCounters{}, fmt.Errorf("counter context canceled: %w", err)
	}
	if c == nil || !filepath.IsAbs(c.executable) || filepath.Clean(c.executable) != c.executable {
		return DropCounters{}, errors.New("nft executable must use an absolute canonical path")
	}
	if err := c.requireIsolatedNamespace(); err != nil {
		return DropCounters{}, fmt.Errorf("isolation not established: %w", err)
	}
	if os.Geteuid() != 0 {
		return DropCounters{}, errors.New("nft counter reader requires root in the isolated namespace")
	}
	egress, err := c.readDropChain(ctx, "egress")
	if err != nil {
		return DropCounters{}, err
	}
	forward, err := c.readDropChain(ctx, "forward")
	if err != nil {
		return DropCounters{}, err
	}
	return DropCounters{EgressPackets: egress, ForwardPackets: forward}, nil
}

func (c *nftConfigurator) readDropChain(ctx context.Context, chain string) (uint64, error) {
	command := exec.CommandContext(ctx, c.executable, "-j", "list", "chain", "inet", "sec_scan_fence", chain)
	var output limitedNftBuffer
	command.Stdout = &output
	command.Stderr = io.Discard
	if err := command.Run(); err != nil {
		return 0, fmt.Errorf("read nft %s drop counter: %w", chain, err)
	}
	packets, err := parseDropCounterJSON(output.Bytes(), chain)
	if err != nil {
		return 0, err
	}
	return packets, nil
}

type limitedNftBuffer struct {
	bytes.Buffer
	tooLarge bool
}

func (b *limitedNftBuffer) Write(p []byte) (int, error) {
	if b.Len()+len(p) > maxNftCounterOutput {
		b.tooLarge = true
		return 0, errors.New("nft counter output exceeds limit")
	}
	return b.Buffer.Write(p)
}

func parseDropCounterJSON(raw []byte, chain string) (uint64, error) {
	var document struct {
		NFTables []json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(raw, &document); err != nil {
		return 0, fmt.Errorf("decode nft %s counter output: %w", chain, err)
	}
	var total uint64
	found := false
	for _, item := range document.NFTables {
		var entry struct {
			Rule *struct {
				Expr []json.RawMessage `json:"expr"`
			} `json:"rule"`
		}
		if err := json.Unmarshal(item, &entry); err != nil || entry.Rule == nil {
			continue
		}
		var isDrop bool
		var packets uint64
		var hasCounter bool
		for _, expression := range entry.Rule.Expr {
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(expression, &fields); err != nil {
				return 0, fmt.Errorf("decode nft %s rule expression: %w", chain, err)
			}
			if _, ok := fields["drop"]; ok {
				isDrop = true
			}
			counter, ok := fields["counter"]
			if !ok {
				continue
			}
			var value struct {
				Packets uint64 `json:"packets"`
			}
			if err := json.Unmarshal(counter, &value); err != nil {
				return 0, fmt.Errorf("decode nft %s counter: %w", chain, err)
			}
			packets = value.Packets
			hasCounter = true
		}
		if !isDrop || !hasCounter {
			continue
		}
		if math.MaxUint64-total < packets {
			return 0, fmt.Errorf("nft %s drop counter overflow", chain)
		}
		total += packets
		found = true
	}
	if !found {
		return 0, fmt.Errorf("nft %s drop counter is missing", chain)
	}
	return total, nil
}
