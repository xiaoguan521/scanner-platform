//go:build linux

// sec-fence-launcher is the small trusted Linux entry point for a fenced
// Worker. It creates the Worker network namespace before execing sec-worker,
// passes the already-open parent namespace as fd 3, and forces the Worker to
// process one task before the namespace is discarded.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"scanner-platform/internal/execguard"
)

const nsfsMagic = 0x6e736673

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("sec-fence-launcher", flag.ContinueOnError)
	flags.SetOutput(stderr)
	workerPath := flags.String("worker", "", "Absolute, pinned sec-worker executable")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if flags.NArg() == 0 {
		fmt.Fprintln(stderr, "provide sec-worker arguments after --")
		return 2
	}
	if err := validateWorkerPath(*workerPath); err != nil {
		fmt.Fprintln(stderr, "invalid --worker path")
		return 2
	}
	childArgs := append([]string(nil), flags.Args()...)
	if err := validateChildArgs(childArgs); err != nil {
		fmt.Fprintln(stderr, "invalid fenced worker arguments")
		return 2
	}
	if os.Geteuid() != 0 {
		fmt.Fprintln(stderr, "sec-fence-launcher requires root")
		return 2
	}
	parent, err := os.Open("/proc/self/ns/net")
	if err != nil || !isNetworkNamespace(parent) {
		if parent != nil {
			_ = parent.Close()
		}
		fmt.Fprintln(stderr, "cannot open trusted parent network namespace")
		return 2
	}
	defer parent.Close()

	childArgs = append(childArgs, "--fence", "--once", "--fence-parent-netns-fd=3")
	command := exec.Command(*workerPath, childArgs...)
	command.Stdin = os.Stdin
	command.Stdout = stdout
	command.Stderr = stderr
	command.ExtraFiles = []*os.File{parent}
	command.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWNET,
		Pdeathsig:  syscall.SIGKILL,
	}
	if err := command.Run(); err != nil {
		if status, ok := childExitStatus(err); ok {
			return status
		}
		fmt.Fprintln(stderr, "fenced worker failed to start or wait")
		return 1
	}
	return 0
}

func validateWorkerPath(path string) error {
	return execguard.ValidatePinnedExecutable(path)
}

func validateChildArgs(args []string) error {
	for _, arg := range args {
		if arg == "--status" || arg == "--help" || arg == "-h" || arg == "--fence-child" {
			return fmt.Errorf("launcher cannot run worker control mode %s", arg)
		}
		for _, protected := range []string{"--fence", "--once", "--fence-parent-netns-fd"} {
			if arg == protected || strings.HasPrefix(arg, protected+"=") {
				return fmt.Errorf("launcher owns %s", protected)
			}
		}
	}
	return nil
}

func isNetworkNamespace(file *os.File) bool {
	if file == nil {
		return false
	}
	var info syscall.Statfs_t
	return syscall.Fstatfs(int(file.Fd()), &info) == nil && uint64(info.Type) == nsfsMagic
}

func childExitStatus(err error) (int, bool) {
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		return 0, false
	}
	status, ok := exitErr.Sys().(syscall.WaitStatus)
	if !ok {
		return 1, true
	}
	if status.Exited() {
		return status.ExitStatus(), true
	}
	if status.Signaled() {
		return 128 + int(status.Signal()), true
	}
	return 1, true
}
