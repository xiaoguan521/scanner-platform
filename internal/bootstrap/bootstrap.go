// Package bootstrap owns the service entrypoints. Server's local development
// mode runs SQLite account management; scanner and Node APIs remain disabled.
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
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"

	"scanner-platform/internal/account"
	"scanner-platform/internal/api"
	"scanner-platform/internal/approvals"
	"scanner-platform/internal/assets"
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
	devUI := flags.Bool("dev-ui", false, "Serve local development API on loopback (server and portable only)")
	listenAddr := flags.String("listen", "127.0.0.1:8080", "Loopback-only development API address")
	configDir, _ := os.UserConfigDir()
	if configDir == "" {
		configDir = os.TempDir()
	}
	dbPath := flags.String("db", filepath.Join(configDir, "scanner-platform", "server.sqlite"), "Server SQLite database file")
	initAdmin := flags.String("init-admin", "", "Initialize first admin (username)")
	passwordFile := flags.String("password-file", "", "Read initial admin password from protected file")
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
	if *printStatus && (*devUI || *initAdmin != "") {
		fmt.Fprintln(stderr, "--status cannot be combined with --dev-ui or --init-admin")
		return 2
	}
	if *printStatus {
		_ = json.NewEncoder(stdout).Encode(api.Status{
			Role: string(role), Phase: "Phase 0 / PoC", State: "SCAFFOLD",
			Ready: false, Enabled: []string{"local-status"},
			Unavailable: []string{"node-api", "database", "task-dispatch", "rule-activation", "scanning", "authentication", "user-management", "rbac"},
		})
		return 0
	}
	if *initAdmin != "" {
		if role != Server || *devUI {
			fmt.Fprintln(stderr, "--init-admin requires sec-server, without --dev-ui")
			return 2
		}
		var password []byte
		if *passwordFile != "" {
			info, err := os.Stat(*passwordFile)
			if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
				fmt.Fprintln(stderr, "password file must exist and be owner-only (0600)")
				return 2
			}
			password, err = os.ReadFile(*passwordFile)
			if err != nil || len(password) > 256 {
				fmt.Fprintln(stderr, "unable to read password file")
				return 2
			}
		} else {
			if !term.IsTerminal(int(os.Stdin.Fd())) {
				fmt.Fprintln(stderr, "initial admin password requires an interactive terminal or --password-file")
				return 2
			}
			fmt.Fprint(stderr, "Initial admin password (12–72 bytes): ")
			var err error
			password, err = term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Fprintln(stderr)
			if err != nil {
				fmt.Fprintln(stderr, "unable to read terminal password")
				return 2
			}
		}
		store, err := account.New(*dbPath)
		if err != nil {
			fmt.Fprintf(stderr, "open database: %v\n", err)
			return 1
		}
		defer store.Close()
		if err := store.InitAdmin(context.Background(), *initAdmin, strings.TrimRight(string(password), "\r\n")); err != nil {
			fmt.Fprintf(stderr, "initialize admin: %v\n", err)
			return 1
		}
		fmt.Fprintln(stdout, "Administrator initialized. Server can now be started.")
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
	var handler http.Handler = api.NewScaffoldHandler(string(role))
	if role == Server {
		store, err := account.New(*dbPath)
		if err != nil {
			fmt.Fprintf(stderr, "open database: %v\n", err)
			return 1
		}
		defer store.Close()
		assetStore, err := assets.New(store.SQLDB())
		if err != nil {
			fmt.Fprintf(stderr, "initialize asset database: %v\n", err)
			return 1
		}
		approvalStore, err := approvals.New(store.SQLDB())
		if err != nil {
			fmt.Fprintf(stderr, "initialize approvals: %v\n", err)
			return 1
		}
		handler = api.NewDevelopmentHandler(store, assetStore, approvalStore)
	}
	if err := serveDevAPI(ctx, string(role), *listenAddr, handler); err != nil {
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

func serveDevAPI(ctx context.Context, role, addr string, handler http.Handler) error {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen for local dev API: %w", err)
	}
	server := &http.Server{
		Handler:           handler,
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
	slog.Info("Local development API; no scanner or rule mutations", "role", role, "address", l.Addr().String())
	err = server.Serve(l)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
