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

	"scanner-platform/internal/api"
	"scanner-platform/internal/repo"
)

// RunServer starts the local framework. Existing explicit account/scaffold
// commands keep their original entrypoint for work already in progress.
func RunServer(args []string, stdout, stderr io.Writer) int {
	for _, arg := range args {
		for _, legacy := range []string{"--init-admin", "--password-file", "--dev-ui", "--status"} {
			if arg == legacy || strings.HasPrefix(arg, legacy+"=") {
				return Run(Server, args, stdout, stderr)
			}
		}
	}
	flags := flag.NewFlagSet("sec-server", flag.ContinueOnError)
	flags.SetOutput(stderr)
	addr := flags.String("listen", "127.0.0.1:8080", "Local web and API address")
	dbPath := flags.String("db", filepath.Join("runtime", "platform.db"), "SQLite database path")
	uiDir := flags.String("ui-dir", filepath.Join("web", "dist"), "Built web UI directory")
	seed := flags.Bool("seed-demo", false, "Create a single synthetic startup task")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if flags.NArg() != 0 || !isNumericLoopback(*addr) {
		fmt.Fprintln(stderr, "provide flags only and use a numeric loopback listen address")
		return 2
	}
	if _, err := os.Stat(filepath.Join(*uiDir, "index.html")); err != nil {
		fmt.Fprintln(stderr, "Web UI is missing. Run make dev, or build web/ and pass --ui-dir.")
		return 1
	}
	store, err := repo.OpenRuntime(*dbPath)
	if err != nil {
		fmt.Fprintf(stderr, "open task database: %v\n", err)
		return 1
	}
	defer store.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if *seed {
		if err := store.SeedSyntheticTask(ctx); err != nil {
			fmt.Fprintf(stderr, "create startup task: %v\n", err)
			return 1
		}
	}
	handler := api.NewRuntimeHandler(store, nil, *uiDir)
	server := &http.Server{Addr: *addr, Handler: handler, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()
	fmt.Fprintf(stdout, "Web UI: http://%s/#/tasks\n", *addr)
	slog.Info("local framework started", "address", *addr, "mode", "synthetic")
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Fprintf(stderr, "serve framework: %v\n", err)
		return 1
	}
	return 0
}
