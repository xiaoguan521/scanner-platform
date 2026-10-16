//go:build linux

package workerfence

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLinuxLauncherRejectsUnverifiedEngineFlags(t *testing.T) {
	p := RestrictedExec{
		SetprivPath: "/usr/bin/setpriv",
		EnginePath:  "/usr/bin/nuclei",
		EngineArgs:  []string{"-code"},
		RuntimeDir:  "/runtime",
	}
	err := p.Launch(context.Background())
	if err == nil || !strings.Contains(err.Error(), "unverified") {
		t.Fatalf("unverified engine flags could execute: %v", err)
	}
}

func TestLinuxFenceRefusesMissingNamespaceProof(t *testing.T) {
	err := NewConfigurator("/usr/sbin/nft", nil).Apply(context.Background(), RuleSet{script: "add table inet sec_scan_fence\n"})
	if err == nil || !strings.Contains(err.Error(), "pre-isolation") {
		t.Fatalf("missing namespace proof unexpectedly accepted: %v", err)
	}
}

func TestLinuxFenceRefusesSameNamespace(t *testing.T) {
	original, err := os.Open("/proc/self/ns/net")
	if err != nil {
		t.Fatalf("open current namespace: %v", err)
	}
	defer original.Close()
	err = NewConfigurator("/usr/sbin/nft", original).Apply(context.Background(), RuleSet{script: "add table inet sec_scan_fence\n"})
	if err == nil || !strings.Contains(err.Error(), "parent network namespace") {
		t.Fatalf("current namespace unexpectedly accepted: %v", err)
	}
}

func TestLinuxFenceRefusesOrdinaryFileAsNamespace(t *testing.T) {
	path := filepath.Join(t.TempDir(), "false-proof")
	if err := os.WriteFile(path, []byte("not a namespace"), 0600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	err = NewConfigurator("/usr/sbin/nft", file).Apply(context.Background(), RuleSet{script: "add table inet sec_scan_fence\n"})
	if err == nil || !strings.Contains(err.Error(), "not nsfs") {
		t.Fatalf("regular file accepted as namespace: %v", err)
	}
}
