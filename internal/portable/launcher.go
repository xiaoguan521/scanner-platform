package portable

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"time"

	"scanner-platform/internal/api"
	"scanner-platform/internal/bootstrap"
	"scanner-platform/internal/webui"
)

const (
	workerID  = "portable-worker"
	updaterID = "portable-updater"
)

// Options configures one sec-portable run.
type Options struct {
	Home, Listen string
	// UIDir overrides the embedded UI, for binaries built without it.
	UIDir       string
	OpenBrowser bool
	// ReadyTimeout bounds how long the Server may take to answer /readyz.
	ReadyTimeout time.Duration
	// Ready, when set, receives the Web UI URL once every component started.
	Ready func(url string)
}

// tokenSource is replaced in tests to observe the issued tokens.
var tokenSource = newToken

// newToken returns 32 random bytes, base64url encoded. Tokens live only in
// memory for this run: they are never written to disk, logs or environment.
func newToken() (string, error) {
	buffer := make([]byte, 32)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buffer), nil
}

// loopbackAddress accepts only a numeric loopback IP and an explicit port.
func loopbackAddress(addr string) error {
	parsed, err := netip.ParseAddrPort(addr)
	if err != nil || !parsed.Addr().IsLoopback() {
		return errors.New("sec-portable only listens on a numeric loopback address such as 127.0.0.1:8080")
	}
	return nil
}

// Run starts Server, Worker and Updater in this process and blocks until ctx
// ends or one of them fails. The Worker and Updater still reach the Server
// only through its node API on loopback, each with its own per-start token,
// so the Worker never holds database access and only the Updater writes the
// rule directory, as in the multi-process deployment.
func Run(ctx context.Context, opts Options, stdout, stderr io.Writer) error {
	if err := loopbackAddress(opts.Listen); err != nil {
		return err
	}
	layout, err := ResolveLayout(opts.Home)
	if err != nil {
		return err
	}
	if err := layout.Prepare(); err != nil {
		return err
	}
	release, err := acquireLock(layout.LockFile)
	if err != nil {
		return err
	}
	defer release()

	logFile, err := os.OpenFile(layout.LogFile, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("open log file: %w", err)
	}
	defer logFile.Close()
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(io.MultiWriter(logFile, stderr), nil)))
	defer slog.SetDefault(previous)

	var ui http.FileSystem
	if opts.UIDir != "" {
		ui = http.Dir(opts.UIDir)
	} else if embedded, ok := webui.FileSystem(); ok {
		ui = embedded
	} else {
		return errors.New("this sec-portable was built without the web UI; build it with `make portable` or pass --ui-dir")
	}
	sshConfig, err := layout.OptionalSSHConfig()
	if err != nil {
		return err
	}
	trustedKeys, err := layout.TrustedRuleKeys()
	if err != nil {
		return err
	}
	workerToken, err := tokenSource()
	if err != nil {
		return err
	}
	updaterToken, err := tokenSource()
	if err != nil {
		return err
	}

	// Listen before starting anything else, so a busy port fails fast.
	listener, err := net.Listen("tcp", opts.Listen)
	if err != nil {
		return fmt.Errorf("listen on %s (use --listen to pick another port): %w", opts.Listen, err)
	}
	// Serve closes it on shutdown; this covers a Server that fails before serving.
	defer listener.Close()
	address := listener.Addr().String()
	serverURL := "http://" + address

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	group := newSupervisor(ctx, cancel)
	start := group.start
	fail := group.fail
	start("server", func() error {
		code := bootstrap.ServeServer(ctx, bootstrap.ServerOptions{
			Addr: address, DBPath: layout.Database, Storage: "sqlite", UI: ui, ReportDir: layout.Reports,
			NodeTokens: api.NodeTokenSet{workerID: workerToken, updaterID: updaterToken},
			Listener:   listener,
		}, stdout, stderr)
		if code != 0 {
			return fmt.Errorf("exit code %d", code)
		}
		return nil
	})
	if err := waitReady(ctx, serverURL, opts.ReadyTimeout); err != nil {
		fail(err)
		return group.wait()
	}
	start("worker", func() error {
		return bootstrap.ServeWorker(ctx, bootstrap.WorkerOptions{
			ServerURL: serverURL, ID: workerID, NodeToken: workerToken,
			BinDir: layout.Bin, RulesDir: layout.Rules, RuntimeDir: layout.WorkerRuntime, InputsDir: layout.Inputs,
			SSHConfigPath: sshConfig, Rate: 5, Timeout: 10, Interval: time.Second, SyntheticDelay: 2 * time.Second,
		}, stderr)
	})
	start("updater", func() error {
		return bootstrap.ServeUpdater(ctx, bootstrap.UpdaterOptions{
			ServerURL: serverURL, ID: updaterID, NodeToken: updaterToken, RulesDir: layout.Rules, TrustedKeys: trustedKeys,
		})
	})

	webURL := serverURL + "/"
	fmt.Fprintf(stdout, "sec-portable 已启动：%s（数据目录 %s，按 Ctrl+C 退出）\n", webURL, layout.Home)
	slog.Info("portable started", "address", address, "home", layout.Home, "sshConfig", sshConfig != "", "trustedRuleKeys", len(trustedKeys))
	if opts.Ready != nil {
		opts.Ready(webURL)
	}
	if opts.OpenBrowser {
		openBrowser(webURL)
	}
	<-ctx.Done()
	return group.wait()
}

// supervisor runs the components and stops all of them when one exits.
type supervisor struct {
	ctx     context.Context
	cancel  context.CancelFunc
	group   sync.WaitGroup
	once    sync.Once
	failure error
}

func newSupervisor(ctx context.Context, cancel context.CancelFunc) *supervisor {
	return &supervisor{ctx: ctx, cancel: cancel}
}

func (s *supervisor) fail(err error) {
	s.once.Do(func() { s.failure = err })
	s.cancel()
}

func (s *supervisor) start(name string, run func() error) {
	s.group.Add(1)
	go func() {
		defer s.group.Done()
		err := run()
		// Once shutdown has started, in-flight requests fail with the
		// cancellation; only an exit before shutdown is a failure.
		if s.ctx.Err() != nil {
			return
		}
		if err != nil {
			s.fail(fmt.Errorf("%s: %w", name, err))
		} else {
			s.fail(fmt.Errorf("%s stopped unexpectedly", name))
		}
	}()
}

// wait returns the first failure, or nil after a requested shutdown.
func (s *supervisor) wait() error {
	s.group.Wait()
	return s.failure
}

// waitReady polls /readyz until the Server answers, ctx ends or the timeout passes.
func waitReady(ctx context.Context, serverURL string, timeout time.Duration) error {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	deadline := time.Now().Add(timeout)
	client := &http.Client{Timeout: time.Second, Transport: &http.Transport{Proxy: nil}}
	for {
		request, _ := http.NewRequestWithContext(ctx, http.MethodGet, serverURL+"/readyz", nil)
		if response, err := client.Do(request); err == nil {
			response.Body.Close()
			if response.StatusCode == http.StatusOK {
				return nil
			}
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if time.Now().After(deadline) {
			return errors.New("server did not become ready")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// openBrowser asks the desktop to open the loopback UI. Failure is harmless:
// the URL is printed on the console as well.
func openBrowser(url string) {
	var command *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		command = exec.Command("open", url)
	case "windows":
		command = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		command = exec.Command("xdg-open", url)
	}
	if err := command.Start(); err != nil {
		slog.Info("could not open a browser; open the printed URL manually", "error", err)
		return
	}
	go func() { _ = command.Wait() }()
}
