//go:build linux

package workerfence

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fakeCgroup(t *testing.T, root, name string) string {
	t.Helper()
	path := filepath.Join(root, name)
	if err := os.Mkdir(path, 0750); err != nil {
		t.Fatal(err)
	}
	for _, file := range []string{"cgroup.controllers", "cgroup.procs", "cgroup.kill"} {
		if err := os.WriteFile(filepath.Join(path, file), nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	return path
}

func TestOpenTaskCgroupRequiresDirectChildAndKillControl(t *testing.T) {
	root := t.TempDir()
	for _, file := range []string{"cgroup.controllers", "cgroup.procs", "cgroup.kill"} {
		if err := os.WriteFile(filepath.Join(root, file), nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	path := fakeCgroup(t, root, ".scan-test")
	group, err := OpenTaskCgroup(root, path)
	if err != nil {
		t.Fatal(err)
	}
	if got := group.Path(); got != path {
		t.Fatalf("path = %q, want %q", got, path)
	}
	for _, unsafe := range []string{root, filepath.Join(root, "nested", "child"), filepath.Join(root, "..", "outside")} {
		if _, err := OpenTaskCgroup(root, unsafe); err == nil {
			t.Fatalf("unsafe cgroup path accepted: %q", unsafe)
		}
	}
	if err := group.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("task cgroup still exists: %v", err)
	}
}

func TestTaskCgroupWritesAttachAndKillControls(t *testing.T) {
	root := t.TempDir()
	for _, file := range []string{"cgroup.controllers", "cgroup.procs", "cgroup.kill"} {
		if err := os.WriteFile(filepath.Join(root, file), nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	path := fakeCgroup(t, root, ".scan-test")
	group, err := OpenTaskCgroup(root, path)
	if err != nil {
		t.Fatal(err)
	}
	if err := group.Attach(1234); err != nil {
		t.Fatal(err)
	}
	procs, err := os.ReadFile(filepath.Join(path, "cgroup.procs"))
	if err != nil || strings.TrimSpace(string(procs)) != "1234" {
		t.Fatalf("cgroup.procs = %q, err=%v", procs, err)
	}
	if err := group.Kill(); err != nil {
		t.Fatal(err)
	}
	kill, err := os.ReadFile(filepath.Join(path, "cgroup.kill"))
	if err != nil || strings.TrimSpace(string(kill)) != "1" {
		t.Fatalf("cgroup.kill = %q, err=%v", kill, err)
	}
}

func TestNewTaskCgroupRequiresKillControl(t *testing.T) {
	root := t.TempDir()
	for _, file := range []string{"cgroup.controllers", "cgroup.procs"} {
		if err := os.WriteFile(filepath.Join(root, file), nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := NewTaskCgroup(root); err == nil {
		t.Fatal("cgroup root without cgroup.kill accepted")
	}
}
