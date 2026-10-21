//go:build linux

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestValidateChildArgsRejectsLauncherOverrides(t *testing.T) {
	for _, args := range [][]string{
		{"--status"},
		{"--help"},
		{"--fence-child"},
		{"--fence=false"},
		{"--once=false"},
		{"--fence-parent-netns-fd", "7"},
		{"--fence-parent-netns-fd=7"},
	} {
		if err := validateChildArgs(args); err == nil {
			t.Fatalf("accepted protected args: %v", args)
		}
	}
	if err := validateChildArgs([]string{"--server", "https://192.0.2.10:8443", "--fence-infra", "tcp://192.0.2.53:53"}); err != nil {
		t.Fatal(err)
	}
}

func TestValidateWorkerPathRequiresPinnedExecutable(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "worker")
	if err := os.WriteFile(path, []byte("worker"), 0700); err != nil {
		t.Fatal(err)
	}
	trusted, err := exec.LookPath("dash")
	if err != nil {
		t.Skip("dash is not installed")
	}
	trusted, err = filepath.Abs(trusted)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateWorkerPath(trusted); err != nil {
		t.Fatalf("trusted executable rejected: %v", err)
	}
	for _, mode := range []os.FileMode{0600, 0675} {
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		if validateWorkerPath(path) == nil {
			t.Fatalf("accepted worker mode %o", mode)
		}
	}
	if validateWorkerPath(filepath.Join(root, "missing")) == nil {
		t.Fatal("accepted missing worker")
	}
	if err := os.Chmod(root, 0777); err != nil {
		t.Fatal(err)
	}
	if validateWorkerPath(path) == nil {
		t.Fatal("accepted worker below writable directory")
	}
}

func TestParentNetworkNamespaceIsNsfs(t *testing.T) {
	file, err := os.Open("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if !isNetworkNamespace(file) {
		t.Fatal("current network namespace was not recognized")
	}
}
