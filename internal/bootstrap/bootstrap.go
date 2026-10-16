// Package bootstrap owns the four service entrypoint shells.
// It deliberately does not construct a scanner, node API, or database.
package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"scanner-platform/internal/api"
)

type Role string

const (
	Server   Role = "sec-server"
	Updater  Role = "sec-updater"
	Worker   Role = "sec-worker"
	Portable Role = "sec-portable"
)

func validRole(role Role) bool {
	switch role {
	case Server, Updater, Worker, Portable:
		return true
	default:
		return false
	}
}

// Run provides consistent help, status and opt-in local UI debugging.
// Default boot remains fail-closed; no scanner or updater is started.
func Run(role Role, args []string, stdout, stderr io.Writer) int {
	if !validRole(role) {
		fmt.Fprintln(stderr, "unknown service role")
		return 2
	}
	flags := flag.NewFlagSet(string(role), flag.ContinueOnError)
	flags.SetOutput(stderr)
	printStatus := flags.Bool("status", false, "Print scaffold status and exit")
	devUI := flags.Bool("dev-ui", false, "Serve read-only status API on loopback (server and portable only)")
	listenAddr := flags.String("listen", "127.0.0.1:8080", "Loopback-only development API address")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(stderr, "positional arguments are unsupported")
		return 2
	}
	if *printStatus && *devUI {
		fmt.Fprintln(stderr, "--status and --dev-ui are mutually exclusive")
		return 2
	}
	if *printStatus {
		_ = json.NewEncoder(stdout).Encode(api.Status{
			Role: string(role), Phase: "Phase 0 / PoC", State: "SCAFFOLD",
			Ready: false, Enabled: []string{"local-status"},
			Unavailable: []string{"node-api", "database", "task-dispatch", "rule-activation", "scanning"},
		})
		return 0
	}
	if !*devUI {
		fmt.Fprintf(stderr, "%s: Phase 0 scaffold; startup disabled until security gates are implemented. Use --status or --help.\n", role)
		return 2
	}
	if role != Server && role != Portable {
		fmt.Fprintf(stderr, "%s does not provide a development HTTP API\n", role)
		return 2
	}
	if !isNumericLoopback(*listenAddr) {
		fmt.Fprintln(stderr, "development API must bind a numeric loopback address")
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := serveDevAPI(ctx, string(role), *listenAddr); err != nil {
		slog.Error("development API stopped", "role", role, "error", err)
		return 1
	}
	return 0
}

func isNumericLoopback(addr string) bool {
	host, port, err := net.SplitHostPort(addr)
	if err != nil || strings.TrimSpace(port) == "" {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func serveDevAPI(ctx context.Context, role, addr string) error {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen for local dev API: %w", err)
	}
	server := &http.Server{
		Handler:           api.NewScaffoldHandler(role),
		ReadHeaderTimeout: api.DevelopmentReadHeaderTimeout,
	}
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()
	slog.Info("Phase 0 read-only API; no scans or mutations", "role", role, "address", l.Addr().String())
	err = server.Serve(l)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
