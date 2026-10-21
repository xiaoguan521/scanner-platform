//go:build linux

package main

import (
	"os/exec"
	"path/filepath"
	"testing"
)

func TestSupervisorRequiresExplicitWorkerSeparator(t *testing.T) {
	if argsAfterSeparator([]string{"--worker", "/opt/sec/bin/sec-worker"}) != nil {
		t.Fatal("accepted worker arguments without separator")
	}
	if got := argsAfterSeparator([]string{"--worker", "/opt/sec/bin/sec-worker", "--"}); got != nil {
		t.Fatalf("accepted empty worker argument list: %v", got)
	}
	got := argsAfterSeparator([]string{"--worker", "/opt/sec/bin/sec-worker", "--", "--server", "https://192.0.2.10:8443"})
	if len(got) != 2 || got[0] != "--server" {
		t.Fatalf("unexpected worker args: %v", got)
	}
}

func TestSupervisorRejectsFencedModeOverrides(t *testing.T) {
	for _, args := range [][]string{
		{"--status"},
		{"--help"},
		{"--fence-child"},
		{"--fence=false"},
		{"--once=false"},
		{"--fence-parent-netns-fd=7"},
	} {
		if err := validateWorkerArgs(args); err == nil {
			t.Fatalf("accepted protected worker args: %v", args)
		}
	}
	if err := validateWorkerArgs([]string{"--server", "https://192.0.2.10:8443", "--node-token-file", "/run/secrets/worker-token"}); err != nil {
		t.Fatal(err)
	}
}

func TestSupervisorPathsRequirePinnedExecutables(t *testing.T) {
	trusted, err := exec.LookPath("dash")
	if err != nil {
		t.Skip("dash is not installed")
	}
	trusted, err = filepath.Abs(trusted)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateSupervisorPaths(trusted, trusted); err != nil {
		t.Fatalf("trusted paths rejected: %v", err)
	}
	if err := validateSupervisorPaths(filepath.Join(t.TempDir(), "missing"), trusted); err == nil {
		t.Fatal("accepted missing launcher")
	}
}
