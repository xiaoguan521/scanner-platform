//go:build linux

package workerfence

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// TaskCgroup is a single-use cgroup-v2 boundary for one Worker task. The
// boundary is deliberately created below an operator-provisioned root; it
// never accepts a task id as a path component and requires cgroup.kill so
// descendant cleanup cannot silently fall back to a racy process walk.
type TaskCgroup struct {
	mu     sync.Mutex
	parent string
	path   string
	closed bool
}

// NewTaskCgroup creates a private child cgroup below root. root must already
// be a dedicated, writable cgroup-v2 directory provisioned by deployment.
func NewTaskCgroup(root string) (*TaskCgroup, error) {
	root, err := validateCgroupRoot(root)
	if err != nil {
		return nil, err
	}
	if err := requireCgroupFiles(root); err != nil {
		return nil, fmt.Errorf("cgroup root is not usable: %w", err)
	}
	path, err := os.MkdirTemp(root, ".scan-")
	if err != nil {
		return nil, fmt.Errorf("create task cgroup: %w", err)
	}
	if err := requireCgroupFiles(path); err != nil {
		_ = os.Remove(path)
		return nil, fmt.Errorf("task cgroup is not usable: %w", err)
	}
	return &TaskCgroup{parent: root, path: path}, nil
}

// OpenTaskCgroup opens a cgroup created by the trusted supervisor. The path
// must be exactly one child below root, preventing the task wire from naming
// an unrelated host cgroup.
func OpenTaskCgroup(root, path string) (*TaskCgroup, error) {
	root, err := validateCgroupRoot(root)
	if err != nil {
		return nil, err
	}
	if err := requireCgroupFiles(root); err != nil {
		return nil, fmt.Errorf("cgroup root is not usable: %w", err)
	}
	cleanPath := filepath.Clean(path)
	if !filepath.IsAbs(cleanPath) || cleanPath == root {
		return nil, errors.New("task cgroup path must be an absolute child of root")
	}
	rel, err := filepath.Rel(root, cleanPath)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || strings.ContainsRune(rel, filepath.Separator) {
		return nil, errors.New("task cgroup path escapes root or is nested")
	}
	if err := requireCgroupFiles(cleanPath); err != nil {
		return nil, fmt.Errorf("task cgroup is not usable: %w", err)
	}
	return &TaskCgroup{parent: root, path: cleanPath}, nil
}

func validateCgroupRoot(root string) (string, error) {
	if root == "" || !filepath.IsAbs(root) || filepath.Clean(root) != root || root == string(filepath.Separator) {
		return "", errors.New("cgroup root must be an existing absolute non-root path")
	}
	info, err := os.Stat(root)
	if err != nil {
		return "", fmt.Errorf("stat cgroup root: %w", err)
	}
	if !info.IsDir() {
		return "", errors.New("cgroup root is not a directory")
	}
	return root, nil
}

func requireCgroupFiles(path string) error {
	for _, name := range []string{"cgroup.controllers", "cgroup.procs", "cgroup.kill"} {
		info, err := os.Stat(filepath.Join(path, name))
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("%s is not a regular cgroup control file", name)
		}
	}
	return nil
}

func (c *TaskCgroup) Path() string {
	if c == nil {
		return ""
	}
	return c.path
}

// Attach moves pid into the task cgroup. It is called by the root fenced
// child before installing the firewall or starting any engine subprocess.
func (c *TaskCgroup) Attach(pid int) error {
	if c == nil || c.path == "" || pid <= 0 {
		return errors.New("invalid task cgroup or pid")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return errors.New("task cgroup is closed")
	}
	if err := os.WriteFile(filepath.Join(c.path, "cgroup.procs"), []byte(strconv.Itoa(pid)), 0600); err != nil {
		return fmt.Errorf("attach pid to task cgroup: %w", err)
	}
	return nil
}

// Detach moves a supervisor process back to the provisioned parent cgroup.
// The task cgroup must contain only the engine subtree before Close removes it;
// otherwise cgroup.kill would also kill the supervisor doing the cleanup.
func (c *TaskCgroup) Detach(pid int) error {
	if c == nil || c.parent == "" || pid <= 0 {
		return errors.New("invalid task cgroup or pid")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	if err := os.WriteFile(filepath.Join(c.parent, "cgroup.procs"), []byte(strconv.Itoa(pid)), 0600); err != nil {
		return fmt.Errorf("detach pid from task cgroup: %w", err)
	}
	return nil
}

// Kill uses the kernel cgroup-v2 kill operation, which covers all current
// and future descendants in the group without a process-list race.
func (c *TaskCgroup) Kill() error {
	if c == nil || c.path == "" {
		return errors.New("invalid task cgroup")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	if err := os.WriteFile(filepath.Join(c.path, "cgroup.kill"), []byte("1"), 0600); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("kill task cgroup: %w", err)
	}
	return nil
}

func (c *TaskCgroup) empty() (bool, error) {
	if c == nil || c.path == "" {
		return false, errors.New("invalid task cgroup")
	}
	raw, err := os.ReadFile(filepath.Join(c.path, "cgroup.procs"))
	if err != nil {
		if os.IsNotExist(err) {
			return true, nil
		}
		return false, fmt.Errorf("read task cgroup processes: %w", err)
	}
	return strings.TrimSpace(string(raw)) == "", nil
}

// Close kills any remaining descendants, waits for the kernel to empty the
// group, and only then removes the directory. It is safe to call repeatedly.
func (c *TaskCgroup) Close(ctx context.Context) error {
	if c == nil || c.path == "" {
		return nil
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.mu.Unlock()

	empty, err := c.empty()
	if err != nil {
		return err
	}
	if !empty {
		if err := c.Kill(); err != nil {
			return err
		}
		for {
			empty, err = c.empty()
			if err != nil {
				return err
			}
			if empty {
				break
			}
			select {
			case <-ctx.Done():
				return fmt.Errorf("wait for task cgroup cleanup: %w", ctx.Err())
			case <-time.After(10 * time.Millisecond):
			}
		}
	}
	// A cgroup v2 directory is removed with rmdir once it holds no
	// processes; the kernel keeps its interface files but they do not block
	// rmdir. On a plain filesystem (unit tests) those files are real and
	// would block it, so clear the direct regular files first. On a real
	// cgroupfs those removals return EPERM and are ignored, leaving
	// behaviour unchanged. Child cgroup directories are left alone so a
	// non-empty hierarchy still fails rmdir.
	if entries, readErr := os.ReadDir(c.path); readErr == nil {
		for _, entry := range entries {
			if !entry.IsDir() {
				_ = os.Remove(filepath.Join(c.path, entry.Name()))
			}
		}
	}
	if err := os.Remove(c.path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove task cgroup: %w", err)
	}
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	return nil
}
