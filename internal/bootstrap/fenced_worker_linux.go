//go:build linux

package bootstrap

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"scanner-platform/internal/executor"
	"scanner-platform/internal/sshcollect"
	"scanner-platform/internal/taskflow"
	"scanner-platform/internal/workerfence"
)

const maxFencedTaskInput = 64 << 20
const fencedCapabilityBytes = sha256.Size

func newFencedTaskRunner(config fencedRunnerConfig) (*fencedTaskRunner, error) {
	if os.Geteuid() != 0 {
		return nil, errors.New("--fence requires a root supervisor process")
	}
	if config.ParentNetNSFD < 3 {
		return nil, errors.New("--fence requires a trusted parent network namespace fd")
	}
	if !filepath.IsAbs(config.Executable) || filepath.Clean(config.Executable) != config.Executable {
		return nil, errors.New("worker executable must be absolute/canonical")
	}
	if !filepath.IsAbs(config.NftPath) || filepath.Clean(config.NftPath) != config.NftPath {
		return nil, errors.New("nft path must be absolute/canonical")
	}
	if !filepath.IsAbs(config.SetprivPath) || filepath.Clean(config.SetprivPath) != config.SetprivPath {
		return nil, errors.New("setpriv path must be absolute/canonical")
	}
	if !filepath.IsAbs(config.CgroupRoot) || filepath.Clean(config.CgroupRoot) != config.CgroupRoot || config.CgroupRoot == "/" {
		return nil, errors.New("fence requires an absolute dedicated cgroup root")
	}
	if len(config.Infrastructure) == 0 {
		return nil, errors.New("--fence requires at least one infrastructure permit")
	}
	return &fencedTaskRunner{config: config}, nil
}

type boundedBuffer struct {
	bytes.Buffer
	remaining int64
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	if int64(len(p)) > b.remaining {
		return 0, errors.New("fenced child output exceeded limit")
	}
	b.remaining -= int64(len(p))
	return b.Buffer.Write(p)
}

func (r *fencedTaskRunner) run(ctx context.Context, operation string, task taskflow.Task) (result fencedTaskOutput, runErr error) {
	r.setTelemetry(taskflow.FenceTelemetry{})
	cgroup, err := workerfence.NewTaskCgroup(r.config.CgroupRoot)
	if err != nil {
		return fencedTaskOutput{}, fmt.Errorf("create fenced task cgroup: %w", err)
	}
	defer func() {
		if closeErr := cgroup.Close(context.Background()); closeErr != nil && runErr == nil {
			runErr = fmt.Errorf("clean up fenced task cgroup: %w", closeErr)
		}
	}()
	input := fencedTaskInput{
		Operation: operation,
		Task:      task,
		Config:    r.config,
		Infra:     permitsWire(r.config.Infrastructure),
	}
	input.Config.ParentNetNSFD = 3
	input.Config.CgroupPath = cgroup.Path()
	raw, err := json.Marshal(input)
	if err != nil {
		return fencedTaskOutput{}, fmt.Errorf("encode fenced task: %w", err)
	}
	command := exec.CommandContext(ctx, r.config.Executable, "--fence-child")
	command.Stdin = bytes.NewReader(raw)
	output := &boundedBuffer{remaining: maxFencedTaskInput}
	command.Stdout = output
	command.Stderr = io.Discard
	parent := os.NewFile(uintptr(r.config.ParentNetNSFD), "parent-network-namespace")
	if parent == nil {
		return fencedTaskOutput{}, errors.New("open trusted parent network namespace fd")
	}
	progressRead, progressWrite, err := os.Pipe()
	if err != nil {
		return fencedTaskOutput{}, errors.New("create fenced progress channel")
	}
	command.ExtraFiles = []*os.File{parent, progressWrite}
	command.Env = append(os.Environ(), "SCANNER_FENCE_CHILD=1")
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	command.Cancel = func() error {
		if command.Process == nil {
			return os.ErrProcessDone
		}
		_ = cgroup.Kill()
		return syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
	}
	if err := command.Start(); err != nil {
		_ = progressRead.Close()
		_ = progressWrite.Close()
		return fencedTaskOutput{}, errors.New("start fenced task child")
	}
	_ = progressWrite.Close()
	progressErrors := make(chan error, 1)
	go func() { progressErrors <- readFencedProgress(ctx, progressRead) }()
	commandErr := command.Wait()
	progressErr := <-progressErrors
	_ = progressRead.Close()
	if commandErr != nil {
		if ctx.Err() != nil {
			return fencedTaskOutput{}, ctx.Err()
		}
		return fencedTaskOutput{}, errors.New("fenced task child failed")
	}
	if progressErr != nil {
		return fencedTaskOutput{}, errors.New("invalid fenced task progress")
	}
	var decoded fencedTaskOutput
	decoder := json.NewDecoder(bytes.NewReader(output.Bytes()))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&decoded); err != nil || decoder.Decode(new(any)) != io.EOF || decoded.Status == "" {
		return fencedTaskOutput{}, errors.New("invalid fenced task result")
	}
	r.setTelemetry(taskflow.FenceTelemetry{Status: decoded.FenceStatus, DropCount: decoded.DropCount})
	if decoded.Status != "ok" {
		return fencedTaskOutput{}, errors.New("fenced task execution failed")
	}
	if decoded.FenceStatus != "ENFORCED" {
		return fencedTaskOutput{}, errors.New("fenced task did not report network counter status")
	}
	if decoded.DropCount > 0 {
		slog.Warn("fenced network drops observed", "drop_count", decoded.DropCount)
	} else {
		slog.Info("fenced network drop counters recorded", "drop_count", decoded.DropCount)
	}
	return decoded, nil
}

const (
	maxFencedProgressLine   = 4096
	maxFencedProgressEvents = 100000
)

func readFencedProgress(ctx context.Context, r io.Reader) error {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 1024), maxFencedProgressLine)
	count := 0
	var firstErr error
	for scanner.Scan() {
		if firstErr != nil {
			continue
		}
		if ctx.Err() != nil {
			firstErr = ctx.Err()
			continue
		}
		count++
		if count > maxFencedProgressEvents {
			firstErr = errors.New("fenced progress event limit exceeded")
			continue
		}
		var update taskflow.TaskProgress
		decoder := json.NewDecoder(bytes.NewReader(scanner.Bytes()))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&update); err != nil || decoder.Decode(new(any)) != io.EOF || update.Phase == "" || len(update.Phase) > 64 || update.Completed < 0 || update.Total < 0 || update.Total > 0 && update.Completed > update.Total {
			firstErr = errors.New("invalid progress event")
			continue
		}
		taskflow.ReportProgress(ctx, update.Phase, update.Completed, update.Total)
	}
	if err := scanner.Err(); err != nil {
		if firstErr == nil {
			firstErr = fmt.Errorf("read fenced progress: %w", err)
		}
		// Keep draining the pipe after a malformed/oversized event so the child
		// cannot block on a full pipe while the supervisor waits for it to exit.
		_, _ = io.Copy(io.Discard, r)
	}
	return firstErr
}

func readFencedInput(r io.Reader) ([]byte, fencedTaskInput, error) {
	raw, err := io.ReadAll(io.LimitReader(r, maxFencedTaskInput+1))
	if err != nil {
		return nil, fencedTaskInput{}, fmt.Errorf("read fenced task: %w", err)
	}
	if len(raw) > maxFencedTaskInput {
		return nil, fencedTaskInput{}, errors.New("fenced task input exceeds limit")
	}
	var input fencedTaskInput
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		return nil, fencedTaskInput{}, errors.New("invalid fenced task input")
	}
	if decoder.Decode(new(any)) != io.EOF {
		return nil, fencedTaskInput{}, errors.New("fenced task input has trailing data")
	}
	return raw, input, nil
}

func fencedDeadline(task taskflow.Task) (time.Time, error) {
	deadline, err := time.Parse(time.RFC3339Nano, task.HardDeadline)
	if err != nil || !deadline.After(time.Now()) {
		return time.Time{}, errors.New("fenced task hard deadline is missing or expired")
	}
	return deadline, nil
}

func runFencedChild(stdout, stderr io.Writer) (exitCode int) {
	raw, input, err := readFencedInput(os.Stdin)
	if err != nil {
		fmt.Fprintln(stderr, "fenced worker input rejected")
		return 2
	}
	if input.Operation != "execute" && input.Operation != "probe-ports" && input.Operation != "auto" {
		fmt.Fprintln(stderr, "fenced worker operation rejected")
		return 2
	}
	deadline, err := fencedDeadline(input.Task)
	if err != nil {
		fmt.Fprintln(stderr, "fenced worker deadline rejected")
		return 2
	}
	var taskCgroup *workerfence.TaskCgroup
	defer func() {
		if taskCgroup == nil {
			return
		}
		if err := taskCgroup.Detach(os.Getpid()); err != nil {
			fmt.Fprintln(stderr, "fenced task cgroup detach failed")
			if exitCode == 0 {
				exitCode = 1
			}
		}
		if err := taskCgroup.Close(context.Background()); err != nil {
			fmt.Fprintln(stderr, "fenced task cgroup cleanup failed")
			if exitCode == 0 {
				exitCode = 1
			}
		}
	}()
	if os.Getenv("SCANNER_FENCE_DROPPED") != "1" {
		if os.Geteuid() != 0 {
			fmt.Fprintln(stderr, "fenced worker requires root only for firewall setup")
			return 2
		}
		cgroup, err := workerfence.OpenTaskCgroup(input.Config.CgroupRoot, input.Config.CgroupPath)
		if err != nil {
			fmt.Fprintln(stderr, "fenced task cgroup rejected")
			return 2
		}
		if err := cgroup.Attach(os.Getpid()); err != nil {
			_ = cgroup.Close(context.Background())
			fmt.Fprintln(stderr, "fenced task cgroup attach rejected")
			return 2
		}
		taskCgroup = cgroup
		parent := os.NewFile(3, "parent-network-namespace")
		if parent == nil {
			fmt.Fprintln(stderr, "trusted parent network namespace fd missing")
			return 2
		}
		defer parent.Close()
		infrastructure, err := parseWirePermits(input.Infra)
		if err != nil {
			fmt.Fprintln(stderr, "fenced infrastructure rejected")
			return 2
		}
		plan, err := fencePlanForTask(input.Task, infrastructure)
		if err != nil {
			fmt.Fprintln(stderr, "fenced task plan rejected")
			return 2
		}
		rules, err := workerfence.Rules(plan, time.Now())
		if err != nil {
			fmt.Fprintln(stderr, "fenced task rules rejected")
			return 2
		}
		configurator := workerfence.NewConfigurator(input.Config.NftPath, parent)
		counterReader, ok := configurator.(workerfence.CounterReader)
		if !ok {
			fmt.Fprintln(stderr, "fenced worker counter reader unavailable")
			return 2
		}
		fenceCtx, cancel := context.WithDeadline(context.Background(), deadline)
		err = configurator.Apply(fenceCtx, rules)
		cancel()
		if err != nil {
			fmt.Fprintln(stderr, "fenced task firewall rejected")
			return 2
		}
		counterCtx, counterCancel := context.WithDeadline(context.Background(), deadline)
		beforeCounters, err := counterReader.ReadDropCounters(counterCtx)
		counterCancel()
		if err != nil {
			fmt.Fprintln(stderr, "fenced task counters unavailable")
			return 2
		}
		executable, err := os.Executable()
		if err != nil {
			fmt.Fprintln(stderr, "fenced worker executable unavailable")
			return 2
		}
		argv, err := workerfence.UnprivilegedWorkerArgs(input.Config.SetprivPath, executable, []string{"--fence-child"})
		if err != nil {
			fmt.Fprintln(stderr, "fenced worker privilege drop rejected")
			return 2
		}
		fenceCtx, cancel = context.WithDeadline(context.Background(), deadline)
		defer cancel()
		command := exec.CommandContext(fenceCtx, input.Config.SetprivPath, argv...)
		command.Stdin = bytes.NewReader(raw)
		childOutput := &boundedBuffer{remaining: maxFencedTaskInput}
		command.Stdout = childOutput
		command.Stderr = stderr
		capRead, capWrite, pipeErr := os.Pipe()
		if pipeErr != nil {
			fmt.Fprintln(stderr, "fenced worker capability unavailable")
			return 2
		}
		digest := sha256.Sum256(raw)
		if _, pipeErr = capWrite.Write(digest[:]); pipeErr != nil {
			_ = capRead.Close()
			_ = capWrite.Close()
			fmt.Fprintln(stderr, "fenced worker capability unavailable")
			return 2
		}
		_ = capWrite.Close()
		defer capRead.Close()
		// ExtraFiles maps the capability pipe to fd 3 in the dropped child.
		// The parent namespace fd is intentionally not inherited by uid 10001.
		progress := os.NewFile(4, "fenced-progress")
		if progress == nil {
			fmt.Fprintln(stderr, "fenced worker progress channel unavailable")
			return 2
		}
		defer progress.Close()
		command.ExtraFiles = []*os.File{capRead, progress}
		command.Env = append(os.Environ(), "SCANNER_FENCE_DROPPED=1")
		command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		command.Cancel = func() error {
			if command.Process == nil {
				return os.ErrProcessDone
			}
			return syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
		}
		if err := command.Run(); err != nil {
			return 1
		}
		counterCtx, counterCancel = context.WithDeadline(context.Background(), deadline)
		afterCounters, err := counterReader.ReadDropCounters(counterCtx)
		counterCancel()
		if err != nil || afterCounters.EgressPackets < beforeCounters.EgressPackets || afterCounters.ForwardPackets < beforeCounters.ForwardPackets {
			fmt.Fprintln(stderr, "fenced task counters invalid")
			return 1
		}
		egressDelta := afterCounters.EgressPackets - beforeCounters.EgressPackets
		forwardDelta := afterCounters.ForwardPackets - beforeCounters.ForwardPackets
		if ^uint64(0)-egressDelta < forwardDelta {
			fmt.Fprintln(stderr, "fenced task counters overflow")
			return 1
		}
		dropCount := egressDelta + forwardDelta
		var result fencedTaskOutput
		decoder := json.NewDecoder(bytes.NewReader(childOutput.Bytes()))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&result); err != nil || decoder.Decode(new(any)) != io.EOF || result.Status == "" {
			fmt.Fprintln(stderr, "fenced task result rejected")
			return 1
		}
		result.FenceStatus = "ENFORCED"
		result.DropCount = dropCount
		if err := json.NewEncoder(stdout).Encode(result); err != nil {
			return 1
		}
		return 0
	}
	if err := verifyDroppedChild(raw); err != nil {
		fmt.Fprintln(stderr, "fenced worker drop authorization rejected")
		return 2
	}
	if os.Geteuid() == 0 {
		fmt.Fprintln(stderr, "fenced worker did not drop privileges")
		return 2
	}
	progress := os.NewFile(4, "fenced-progress")
	if progress == nil {
		fmt.Fprintln(stderr, "fenced worker progress channel unavailable")
		return 2
	}
	defer progress.Close()
	var progressMu sync.Mutex
	var progressErr error
	reportProgress := func(value taskflow.TaskProgress) {
		progressMu.Lock()
		defer progressMu.Unlock()
		if progressErr != nil {
			return
		}
		if err := json.NewEncoder(progress).Encode(value); err != nil {
			progressErr = err
		}
	}
	runner := executor.Runner{BinDir: input.Config.BinDir, RulesDir: input.Config.RulesDir, RuntimeDir: input.Config.RuntimeDir, InputsDir: input.Config.InputsDir, Rate: input.Config.Rate, Timeout: input.Config.Timeout}
	if input.Config.SSHConfigPath != "" {
		collector, err := sshcollect.Load(input.Config.SSHConfigPath)
		if err != nil {
			fmt.Fprintln(stderr, "fenced worker SSH configuration rejected")
			return 2
		}
		runner.SSHCollector = collector
	}
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	ctx = taskflow.WithProgressReporter(ctx, reportProgress)
	result := fencedTaskOutput{Status: "ok"}
	switch input.Operation {
	case "execute":
		result.Detections, err = runner.Execute(ctx, input.Task)
	case "probe-ports":
		result.Ports, err = runner.ProbePorts(ctx, input.Task)
	case "auto":
		result.Auto, err = runner.AutoScan(ctx, input.Task)
	}
	progressMu.Lock()
	if progressErr != nil {
		err = progressErr
	}
	progressMu.Unlock()
	if err != nil {
		result.Status = "error"
	}
	if err := json.NewEncoder(stdout).Encode(result); err != nil {
		return 1
	}
	return 0
}

func verifyDroppedChild(raw []byte) error {
	if os.Getenv("SCANNER_FENCE_DROPPED") != "1" {
		return errors.New("missing dropped marker")
	}
	if os.Geteuid() == 0 {
		return errors.New("child is still privileged")
	}
	if os.Geteuid() != 10001 || os.Getegid() != 10001 {
		return errors.New("worker child must run as uid/gid 10001")
	}
	if value, err := procStatusValue(os.Getpid(), "NoNewPrivs:"); err != nil || value != "1" {
		return errors.New("no_new_privs is not enabled")
	}
	for _, key := range []string{"CapInh:", "CapPrm:", "CapEff:", "CapBnd:", "CapAmb:"} {
		value, err := procStatusValue(os.Getpid(), key)
		if err != nil || !zeroCapabilityField(value) {
			return errors.New("worker child retains capabilities")
		}
	}
	parentUID, err := procStatusValue(os.Getppid(), "Uid:")
	parentFields := strings.Fields(parentUID)
	if err != nil || len(parentFields) == 0 || parentFields[0] != "0" {
		return errors.New("root supervisor parent required")
	}
	capabilityFile := os.NewFile(3, "fenced-capability")
	if capabilityFile == nil {
		return errors.New("fenced capability missing")
	}
	defer capabilityFile.Close()
	capability, err := io.ReadAll(io.LimitReader(capabilityFile, fencedCapabilityBytes+1))
	if err != nil || len(capability) != fencedCapabilityBytes {
		return errors.New("fenced capability missing")
	}
	digest := sha256.Sum256(raw)
	if !bytes.Equal(capability, digest[:]) {
		return errors.New("fenced task digest mismatch")
	}
	return nil
}

func zeroCapabilityField(value string) bool {
	fields := strings.Fields(value)
	if len(fields) != 1 {
		return false
	}
	parsed, err := strconv.ParseUint(fields[0], 16, 64)
	return err == nil && parsed == 0
}

func procStatusValue(pid int, key string) (string, error) {
	data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/status")
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, key) {
			return strings.TrimSpace(strings.TrimPrefix(line, key)), nil
		}
	}
	return "", errors.New("process status field missing")
}
