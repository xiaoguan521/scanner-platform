package bootstrap

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"scanner-platform/internal/account"
	"scanner-platform/internal/api"
	"scanner-platform/internal/approvals"
	"scanner-platform/internal/assets"
	"scanner-platform/internal/repo"
)

// RunServer starts the local framework. Existing explicit account/scaffold
// commands keep their original entrypoint for work already in progress.
func RunServer(args []string, stdout, stderr io.Writer) int {
	for _, arg := range args {
		for _, legacy := range []string{"--init-admin", "--password-file"} {
			if arg == legacy || strings.HasPrefix(arg, legacy+"=") {
				initArgs := append([]string{}, args...)
				hasDB := false
				for _, a := range args {
					hasDB = hasDB || a == "--db" || strings.HasPrefix(a, "--db=")
				}
				if !hasDB {
					abs, _ := filepath.Abs(filepath.Join("runtime", "platform.db"))
					initArgs = append(initArgs, "--db", abs)
				}
				return Run(Server, initArgs, stdout, stderr)
			}
		}
	}
	flags := flag.NewFlagSet("sec-server", flag.ContinueOnError)
	flags.SetOutput(stderr)
	addr := flags.String("listen", "127.0.0.1:8080", "Local web and API address")
	dbPath := flags.String("db", filepath.Join("runtime", "platform.db"), "SQLite database path")
	uiDir := flags.String("ui-dir", filepath.Join("web", "dist"), "Built web UI directory")
	reportDir := flags.String("report-dir", "", "Private generated report directory (defaults beside the SQLite database)")
	flags.Bool("dev-ui", false, "Compatibility alias for the unified local Server")
	status := flags.Bool("status", false, "Show local runtime capabilities")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if *status {
		fmt.Fprintln(stdout, `{"role":"sec-server","mode":"local","engines":["synthetic","nuclei","trivy","zap"]}`)
		return 0
	}
	if flags.NArg() != 0 || !isNumericLoopback(*addr) {
		fmt.Fprintln(stderr, "provide flags only and use a numeric loopback listen address")
		return 2
	}
	if _, err := os.Stat(filepath.Join(*uiDir, "index.html")); err != nil {
		fmt.Fprintln(stderr, "Web UI is missing. Run make dev, or build web/ and pass --ui-dir.")
		return 1
	}
	absoluteDB, err := filepath.Abs(*dbPath)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	accounts, err := account.New(absoluteDB)
	if err != nil {
		fmt.Fprintf(stderr, "open account database: %v\n", err)
		return 1
	}
	defer accounts.Close()
	assetStore, err := assets.New(accounts.SQLDB())
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	approvalsStore, err := approvals.New(accounts.SQLDB())
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	store, err := repo.NewRuntime(accounts.SQLDB())
	if err != nil {
		fmt.Fprintf(stderr, "open task database: %v\n", err)
		return 1
	}
	defer store.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if *reportDir == "" {
		*reportDir = filepath.Join(filepath.Dir(absoluteDB), "reports")
	}
	go store.RunReports(ctx, *reportDir)
	go func() {
		for {
			if err := assetStore.RefreshReachability(ctx); err != nil && ctx.Err() == nil {
				slog.Error("asset reachability refresh failed", "error", err)
			}
			timer := time.NewTimer(assets.ReachabilityInterval)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
		}
	}()
	if _, err := accounts.SQLDB().ExecContext(ctx, `UPDATE scan_tasks SET status='FAILED',details=json_set(details,'$.error','Server restarted during scan; create a new task') WHERE status='RUNNING'`); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if _, err := accounts.SQLDB().ExecContext(ctx, `UPDATE rule_jobs SET status='PENDING',data=json_set(data,'$.nodeId','') WHERE status='RUNNING'`); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	go func() {
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-ticker.C:
				if err := store.Tick(ctx, now); err != nil && ctx.Err() == nil {
					slog.Error("local scheduler tick failed", "error", err)
				}
			}
		}
	}()
	handler := api.NewRuntimeHandler(store, api.NewDevelopmentHandler(accounts, assetStore, approvalsStore), *uiDir, accounts)
	server := &http.Server{Addr: *addr, Handler: handler, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()
	fmt.Fprintf(stdout, "Web UI: http://%s/#/tasks\n", *addr)
	slog.Info("local framework started", "address", *addr, "mode", "local")
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Fprintf(stderr, "serve framework: %v\n", err)
		return 1
	}
	return 0
}
