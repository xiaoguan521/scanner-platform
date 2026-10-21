package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"scanner-platform/internal/api"
	"scanner-platform/internal/executor"
	"scanner-platform/internal/sshcollect"
	"syscall"
	"time"

	"scanner-platform/internal/taskflow"
)

func RunWorker(args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 && args[0] == "--fence-child" {
		return runFencedChild(stdout, stderr)
	}
	flags := flag.NewFlagSet("sec-worker", flag.ContinueOnError)
	flags.SetOutput(stderr)
	server := flags.String("server", "http://127.0.0.1:8080", "Local Server URL")
	nodeTokenFile := flags.String("node-token-file", "", "Owner-only bearer token file for the Worker node API")
	nodeCACert := flags.String("node-ca-cert", "", "PEM CA bundle used to verify an HTTPS Server node API")
	nodeClientCert := flags.String("node-client-cert", "", "Optional PEM client certificate for mTLS")
	nodeClientKey := flags.String("node-client-key", "", "Owner-only PEM client private key for mTLS")
	id := flags.String("id", "worker-local", "Worker identifier")
	once := flags.Bool("once", false, "Process at most one queued task and exit")
	interval := flags.Duration("interval", time.Second, "Queue polling interval")
	delay := flags.Duration("synthetic-delay", 2*time.Second, "Synthetic task duration")
	binDir := flags.String("bin-dir", "bin", "Pinned engine binaries")
	rulesDir := flags.String("rules-dir", "vuln-data", "Read-only rule directory")
	runtimeDir := flags.String("runtime-dir", "runtime/worker", "Private engine runtime and cache")
	inputsDir := flags.String("inputs-dir", "runtime/inputs", "Local Trivy input root")
	sshConfigPath := flags.String("ssh-config", "", "Worker-local SSH public-key profile and known-hosts JSON")
	fence := flags.Bool("fence", false, "Enable Linux network-namespace firewall supervisor mode")
	fenceParentFD := flags.Int("fence-parent-netns-fd", -1, "Trusted inherited fd for the parent network namespace (Linux fence mode)")
	fenceNftPath := flags.String("fence-nft-path", "/usr/sbin/nft", "Absolute nft path used by Linux fence supervisor")
	fenceSetprivPath := flags.String("fence-setpriv-path", "/usr/bin/setpriv", "Absolute setpriv path used by Linux fence supervisor")
	fenceCgroupRoot := flags.String("fence-cgroup-root", "/sys/fs/cgroup/sec-worker", "Dedicated writable cgroup-v2 root for Linux fence tasks")
	fenceInfra := flags.String("fence-infra", "", "Comma-separated exact TCP/UDP IP:port infrastructure permits; tcp:// and udp:// prefixes are supported")
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
	if err != nil || (endpoint.Scheme != "http" && endpoint.Scheme != "https") || endpoint.Host == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" || (endpoint.Path != "" && endpoint.Path != "/") || endpoint.Scheme == "http" && !isNumericLoopback(endpoint.Host) || *id == "" || *interval <= 0 || *delay < 0 || flags.NArg() != 0 {
		fmt.Fprintln(stderr, "provide an http loopback or HTTPS Server URL, worker ID and valid timing flags")
		return 2
	}
	if endpoint.Scheme == "https" && *nodeTokenFile == "" {
		fmt.Fprintln(stderr, "HTTPS Server URL requires --node-token-file")
		return 2
	}
	var fenced *fencedTaskRunner
	if *fence {
		if runtime.GOOS != "linux" {
			fmt.Fprintln(stderr, "--fence is supported only on Linux")
			return 2
		}
		if !*once {
			fmt.Fprintln(stderr, "--fence requires --once; restart a fresh worker namespace for each task")
			return 2
		}
		if os.Geteuid() != 0 {
			fmt.Fprintln(stderr, "--fence requires a root supervisor process")
			return 2
		}
		if endpoint.Scheme != "https" {
			fmt.Fprintln(stderr, "--fence requires an HTTPS Server URL")
			return 2
		}
		serverHost, _, splitErr := net.SplitHostPort(endpoint.Host)
		if splitErr != nil || net.ParseIP(serverHost) == nil {
			fmt.Fprintln(stderr, "--fence requires a numeric Server IP:port")
			return 2
		}
		infrastructure, err := parseFenceInfrastructure(endpoint.Host, *fenceInfra)
		if err != nil {
			fmt.Fprintln(stderr, "invalid --fence-infra:", err)
			return 2
		}
		executable, err := os.Executable()
		if err != nil {
			fmt.Fprintln(stderr, "resolve worker executable:", err)
			return 2
		}
		executable, err = filepath.Abs(executable)
		if err != nil {
			fmt.Fprintln(stderr, "resolve worker executable:", err)
			return 2
		}
		fencedSSHConfig := ""
		if *sshConfigPath != "" {
			fencedSSHConfig = absolute(*sshConfigPath)
		}
		fenced, err = newFencedTaskRunner(fencedRunnerConfig{
			Executable: executable, NftPath: absolute(*fenceNftPath), SetprivPath: absolute(*fenceSetprivPath), ParentNetNSFD: *fenceParentFD,
			CgroupRoot:     absolute(*fenceCgroupRoot),
			Infrastructure: infrastructure, BinDir: runner.BinDir, RulesDir: runner.RulesDir, RuntimeDir: runner.RuntimeDir, InputsDir: runner.InputsDir,
			SSHConfigPath: fencedSSHConfig, Rate: runner.Rate, Timeout: runner.Timeout,
		})
		if err != nil {
			fmt.Fprintln(stderr, "configure worker fence:", err)
			return 2
		}
	}
	if endpoint.Scheme == "http" && (*nodeCACert != "" || *nodeClientCert != "" || *nodeClientKey != "") {
		fmt.Fprintln(stderr, "node TLS client flags require an HTTPS Server URL")
		return 2
	}
	nodeToken := ""
	if *nodeTokenFile != "" {
		nodeToken, err = api.ReadNodeTokenFile(*nodeTokenFile)
		if err != nil {
			fmt.Fprintln(stderr, "read node token file:", err)
			return 2
		}
	}
	clientTLS, err := loadNodeClientTLSConfig(*nodeCACert, *nodeClientCert, *nodeClientKey)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	execute, probePorts, autoScan := runner.Execute, runner.ProbePorts, runner.AutoScan
	if fenced != nil {
		execute, probePorts, autoScan = fenced.Execute, fenced.ProbePorts, fenced.AutoScan
	}
	worker := taskflow.Worker{
		ServerURL: *server, ID: *id, NodeToken: nodeToken, Interval: *interval, Delay: *delay,
		Execute: execute, ProbePorts: probePorts, AutoScan: autoScan, EngineStatus: runner.Status,
		CurrentRuleVersion: runner.CurrentRuleVersion,
		RequireLeases:      true,
		Client: &http.Client{
			Timeout:       5 * time.Second,
			Transport:     &http.Transport{Proxy: nil, TLSClientConfig: clientTLS},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
	if fenced != nil {
		worker.FenceTelemetry = fenced.Telemetry
	}
	if err := worker.Run(ctx, *once); err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintf(stderr, "worker stopped: %v\n", err)
		return 1
	}
	return 0
}
