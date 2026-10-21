//go:build linux && lab

package poc01

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"scanner-platform/internal/workerfence"
)

func TestFencedCgroupKillsDescendants(t *testing.T) {
	if os.Getenv("LAB_ENV") != "isolated" {
		t.Skip("requires an explicitly approved isolated lab")
	}
	root := os.Getenv("LAB_CGROUP_ROOT")
	if root == "" {
		root = "/sys/fs/cgroup/sec-worker-lab"
	}
	if err := os.MkdirAll(root, 0750); err != nil {
		t.Fatal(err)
	}
	group, err := workerfence.NewTaskCgroup(root)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = group.Close(context.Background()) }()

	command := exec.Command("/bin/sh", "-c", "sleep 30 & echo $!; wait")
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	if err := group.Attach(command.Process.Pid); err != nil {
		_ = command.Process.Kill()
		_ = command.Wait()
		t.Fatal(err)
	}
	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil {
		_ = group.Kill()
		_ = command.Wait()
		t.Fatal(err)
	}
	descendantPID, err := strconv.Atoi(line[:len(line)-1])
	if err != nil || descendantPID <= 0 {
		_ = group.Kill()
		_ = command.Wait()
		t.Fatalf("invalid descendant pid %q: %v", line, err)
	}
	if err := group.Kill(); err != nil {
		_ = command.Process.Kill()
		_ = command.Wait()
		t.Fatal(err)
	}
	if err := command.Wait(); err == nil {
		t.Fatal("cgroup kill did not stop the supervisor child")
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(filepath.Join("/proc", fmt.Sprint(descendantPID))); os.IsNotExist(err) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("cgroup kill did not remove descendant process %d", descendantPID)
}
