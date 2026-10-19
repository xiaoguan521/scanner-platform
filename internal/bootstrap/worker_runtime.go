package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"scanner-platform/internal/executor"
	"scanner-platform/internal/sshcollect"
	"syscall"
	"time"

	"scanner-platform/internal/taskflow"
)

func RunWorker(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("sec-worker", flag.ContinueOnError)
	flags.SetOutput(stderr)
	server := flags.String("server", "http://127.0.0.1:8080", "Local Server URL")
	id := flags.String("id", "worker-local", "Worker identifier")
	once := flags.Bool("once", false, "Process at most one queued task and exit")
	interval := flags.Duration("interval", time.Second, "Queue polling interval")
	delay := flags.Duration("synthetic-delay", 2*time.Second, "Synthetic task duration")
	binDir := flags.String("bin-dir", "bin", "Pinned engine binaries")
	rulesDir := flags.String("rules-dir", "vuln-data", "Read-only rule directory")
	runtimeDir := flags.String("runtime-dir", "runtime/worker", "Private engine runtime and cache")
	inputsDir := flags.String("inputs-dir", "runtime/inputs", "Local Trivy input root")
	sshConfigPath := flags.String("ssh-config", "", "Worker-local SSH public-key profile and known-hosts JSON")
	rate := flags.Int("rate", 5, "Nuclei requests per second (1-100)")
	timeout := flags.Int("request-timeout", 10, "HTTP request timeout in seconds (1-60)")
	status := flags.Bool("status", false, "Print worker mode and exit")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	absolute := func(path string) string { p, _ := filepath.Abs(path); return p }
	runner := &executor.Runner{BinDir: absolute(*binDir), RulesDir: absolute(*rulesDir), RuntimeDir: absolute(*runtimeDir), InputsDir: absolute(*inputsDir), Rate: *rate, Timeout: *timeout}
	if *sshConfigPath != "" {
		collector, err := sshcollect.Load(absolute(*sshConfigPath))
		if err != nil {
			fmt.Fprintln(stderr, "invalid --ssh-config; see docs/ssh-collection.md")
			return 2
		}
		runner.SSHCollector = collector
	}
	if *status {
		_ = json.NewEncoder(stdout).Encode(map[string]any{"role": "sec-worker", "engines": runner.Status()})
		return 0
	}
	if *rate < 1 || *rate > 100 || *timeout < 1 || *timeout > 60 {
		fmt.Fprintln(stderr, "rate or timeout outside supported range")
		return 2
	}

	endpoint, err := url.Parse(*server)
	if err != nil || endpoint.Scheme != "http" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" || (endpoint.Path != "" && endpoint.Path != "/") || !isNumericLoopback(endpoint.Host) || *id == "" || *interval <= 0 || *delay < 0 || flags.NArg() != 0 {
		fmt.Fprintln(stderr, "provide a local numeric loopback http:// Server URL, worker ID and valid timing flags")
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	worker := taskflow.Worker{
		ServerURL: *server, ID: *id, Interval: *interval, Delay: *delay,
		Execute: runner.Execute, ProbePorts: runner.ProbePorts, AutoScan: runner.AutoScan, EngineStatus: runner.Status,
		Client: &http.Client{
			Timeout:       5 * time.Second,
			Transport:     &http.Transport{Proxy: nil},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
	if err := worker.Run(ctx, *once); err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintf(stderr, "worker stopped: %v\n", err)
		return 1
	}
	return 0
}
