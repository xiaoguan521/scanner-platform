//go:build linux

// sec-worker-supervisor restarts the trusted fenced Worker launcher after each
// one-shot task. It owns no database credentials and never constructs a shell
// command; the launcher's own checks remain the final security boundary.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"scanner-platform/internal/execguard"
	"scanner-platform/internal/supervisor"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("sec-worker-supervisor", flag.ContinueOnError)
	flags.SetOutput(stderr)
	launcherPath := flags.String("launcher", "", "Absolute, pinned sec-fence-launcher executable")
	workerPath := flags.String("worker", "", "Absolute, pinned sec-worker executable")
	restartDelay := flags.Duration("restart-delay", 2*time.Second, "Delay after a one-shot Worker exits")
	maxBackoff := flags.Duration("max-backoff", 60*time.Second, "Maximum delay after consecutive Worker failures")
	maxRestarts := flags.Int("max-restarts", 0, "Maximum relaunches after the first cycle; zero is unlimited")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if flags.NArg() == 0 || argsAfterSeparator(args) == nil {
		fmt.Fprintln(stderr, "provide sec-worker arguments after --")
		return 2
	}
	if err := validateSupervisorPaths(*launcherPath, *workerPath); err != nil {
		fmt.Fprintln(stderr, "invalid supervisor executable path")
		return 2
	}
	if os.Geteuid() != 0 {
		fmt.Fprintln(stderr, "sec-worker-supervisor requires root")
		return 2
	}
	if *restartDelay < 0 || *maxBackoff < *restartDelay || *maxRestarts < 0 {
		fmt.Fprintln(stderr, "invalid restart policy")
		return 2
	}
	workerArgs := append([]string(nil), flags.Args()...)
	if err := validateWorkerArgs(workerArgs); err != nil {
		fmt.Fprintln(stderr, "invalid fenced worker arguments")
		return 2
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	policy := supervisor.Policy{RestartDelay: *restartDelay, MaxBackoff: *maxBackoff, MaxRestarts: *maxRestarts}
	launcherArgs := append([]string{"--worker", *workerPath}, workerArgs...)
	err := supervisor.Run(ctx, policy, func(cycleCtx context.Context) (int, error) {
		command := exec.CommandContext(cycleCtx, *launcherPath, launcherArgs...)
		command.Stdin = os.Stdin
		command.Stdout = stdout
		command.Stderr = stderr
		command.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
		runErr := command.Run()
		if cycleCtx.Err() != nil {
			return 0, cycleCtx.Err()
		}
		if runErr == nil {
			return 0, nil
		}
		return childExitCode(command, runErr), runErr
	}, supervisor.Sleep, func(code int, err error, delay time.Duration) {
		if err != nil {
			fmt.Fprintf(stderr, "fenced Worker exited with code %d; restarting in %s\n", code, delay)
			return
		}
		fmt.Fprintf(stderr, "fenced Worker completed one task; restarting in %s\n", delay)
	})
	if err == nil || errors.Is(err, context.Canceled) {
		return 0
	}
	if errors.Is(err, supervisor.ErrRestartLimit) {
		fmt.Fprintln(stderr, "Worker restart limit reached")
		return 1
	}
	fmt.Fprintln(stderr, "Worker supervisor stopped")
	return 1
}

func validateSupervisorPaths(launcherPath, workerPath string) error {
	if err := execguard.ValidatePinnedExecutable(launcherPath); err != nil {
		return err
	}
	return execguard.ValidatePinnedExecutable(workerPath)
}

func validateWorkerArgs(args []string) error {
	for _, arg := range args {
		if arg == "--status" || arg == "--help" || arg == "-h" || arg == "--fence-child" {
			return fmt.Errorf("supervisor cannot run worker control mode")
		}
		for _, protected := range []string{"--fence", "--once", "--fence-parent-netns-fd"} {
			if arg == protected || len(arg) > len(protected) && arg[:len(protected)+1] == protected+"=" {
				return fmt.Errorf("supervisor owns fenced worker mode")
			}
		}
	}
	return nil
}

// argsAfterSeparator makes the CLI contract explicit: worker flags are not
// parsed by the supervisor's flag set and must follow a literal -- separator.
func argsAfterSeparator(args []string) []string {
	for index, arg := range args {
		if arg == "--" {
			if index+1 >= len(args) {
				return nil
			}
			return args[index+1:]
		}
	}
	return nil
}

func childExitCode(command *exec.Cmd, runErr error) int {
	if command.ProcessState != nil && command.ProcessState.Exited() {
		return command.ProcessState.ExitCode()
	}
	var exitErr *exec.ExitError
	if errors.As(runErr, &exitErr) {
		if status, ok := exitErr.Sys().(syscall.WaitStatus); ok && status.Signaled() {
			return 128 + int(status.Signal())
		}
	}
	return 1
}
