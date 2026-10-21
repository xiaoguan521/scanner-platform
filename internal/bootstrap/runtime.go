package bootstrap

import (
	"context"
	"crypto/tls"
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
	"scanner-platform/internal/repo"
)

// RunServer starts the local framework. Existing explicit account/scaffold
// commands keep their original entrypoint for work already in progress.
func RunServer(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("sec-server", flag.ContinueOnError)
	flags.SetOutput(stderr)
	addr := flags.String("listen", "127.0.0.1:8080", "Local web and API address")
	dbPath := flags.String("db", filepath.Join("runtime", "platform.db"), "SQLite database path")
	storage := flags.String("storage", "sqlite", "Runtime storage backend: sqlite or postgres")
	uiDir := flags.String("ui-dir", filepath.Join("web", "dist"), "Built web UI directory")
	reportDir := flags.String("report-dir", "", "Private generated report directory (defaults beside the SQLite database)")
	postgresDSNFile := flags.String("postgres-dsn-file", "", "Owner-only file containing the PostgreSQL connection string")
	migratePostgres := flags.Bool("migrate-postgres", false, "Apply embedded PostgreSQL migrations and exit")
	initAdmin := flags.String("init-admin", "", "Initialize the first administrator username and exit")
	passwordFile := flags.String("password-file", "", "Owner-only file containing the initial administrator password")
	nodeTokenFile := flags.String("node-token-file", "", "Owner-only Server registry with one node-id=token entry per line")
	nodeListen := flags.String("node-listen", "", "Separate HTTPS node API address (numeric IP:port)")
	nodeTLSCert := flags.String("node-tls-cert", "", "PEM certificate for the separate node API listener")
	nodeTLSKey := flags.String("node-tls-key", "", "Owner-only PEM private key for the separate node API listener")
	devUI := flags.Bool("dev-ui", false, "Compatibility alias for the unified local Server")
	status := flags.Bool("status", false, "Show local runtime capabilities")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if *storage != "sqlite" && *storage != "postgres" {
		fmt.Fprintln(stderr, "--storage must be sqlite or postgres")
		return 2
	}
	if *migratePostgres && *storage != "sqlite" {
		fmt.Fprintln(stderr, "--migrate-postgres uses the migration-only mode; omit --storage=postgres")
		return 2
	}
	if *initAdmin != "" && *migratePostgres {
		fmt.Fprintln(stderr, "--init-admin cannot be combined with --migrate-postgres")
		return 2
	}
	if *status {
		if *storage != "sqlite" || *migratePostgres || *postgresDSNFile != "" || *initAdmin != "" || *passwordFile != "" || *nodeTokenFile != "" || *nodeListen != "" || *nodeTLSCert != "" || *nodeTLSKey != "" {
			fmt.Fprintln(stderr, "--status cannot be combined with runtime configuration flags")
			return 2
		}
		fmt.Fprintln(stdout, `{"role":"sec-server","mode":"local","engines":["synthetic","nuclei","trivy","zap"]}`)
		return 0
	}
	if *initAdmin != "" {
		if flags.NArg() != 0 || *nodeTokenFile != "" || *nodeListen != "" || *nodeTLSCert != "" || *nodeTLSKey != "" || *devUI || *reportDir != "" {
			fmt.Fprintln(stderr, "--init-admin cannot be combined with server runtime flags")
			return 2
		}
		password, err := readInitialPassword(*passwordFile, stderr)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
		if *storage == "postgres" {
			return initPostgresAdmin(*postgresDSNFile, *initAdmin, password, stdout, stderr)
		}
		if *postgresDSNFile != "" {
			fmt.Fprintln(stderr, "--postgres-dsn-file requires --storage=postgres")
			return 2
		}
		absoluteDB, err := filepath.Abs(*dbPath)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		store, err := account.New(absoluteDB)
		if err != nil {
			fmt.Fprintf(stderr, "open account database: %v\n", err)
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
	if *migratePostgres {
		if *postgresDSNFile == "" || *nodeTokenFile != "" || *nodeListen != "" || *nodeTLSCert != "" || *nodeTLSKey != "" || *devUI || *reportDir != "" || flags.NArg() != 0 {
			fmt.Fprintln(stderr, "--migrate-postgres requires only --postgres-dsn-file")
			return 2
		}
		dsn, err := repo.ReadPostgresDSNFile(*postgresDSNFile)
		if err != nil {
			fmt.Fprintln(stderr, "read PostgreSQL DSN file: invalid protected file")
			return 2
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		db, err := repo.OpenPostgres(ctx, repo.PostgresConfig{DSN: dsn})
		if err != nil {
			fmt.Fprintf(stderr, "open PostgreSQL: %v\n", err)
			return 1
		}
		defer db.Close()
		report, err := repo.MigratePostgres(ctx, db)
		if err != nil {
			fmt.Fprintf(stderr, "migrate PostgreSQL: %v\n", err)
			return 1
		}
		if err := json.NewEncoder(stdout).Encode(report); err != nil {
			fmt.Fprintln(stderr, "write migration result:", err)
			return 1
		}
		return 0
	}
	if *storage == "postgres" && *postgresDSNFile == "" {
		fmt.Fprintln(stderr, "--storage=postgres requires --postgres-dsn-file")
		return 2
	}
	if *storage == "sqlite" && *postgresDSNFile != "" {
		fmt.Fprintln(stderr, "--postgres-dsn-file requires --storage=postgres")
		return 2
	}
	if (*nodeListen == "") != (*nodeTLSCert == "" || *nodeTLSKey == "") {
		fmt.Fprintln(stderr, "--node-listen requires --node-tls-cert and --node-tls-key, and those flags require --node-listen")
		return 2
	}
	if *nodeListen != "" {
		if *nodeTokenFile == "" {
			fmt.Fprintln(stderr, "--node-listen requires --node-token-file")
			return 2
		}
		if err := validateNodeListen(*nodeListen); err != nil {
			fmt.Fprintln(stderr, "invalid --node-listen:", err)
			return 2
		}
	}
	if flags.NArg() != 0 || !isNumericLoopback(*addr) {
		fmt.Fprintln(stderr, "provide flags only and use a numeric loopback listen address")
		return 2
	}
	if _, err := os.Stat(filepath.Join(*uiDir, "index.html")); err != nil {
		fmt.Fprintln(stderr, "Web UI is missing. Run make dev, or build web/ and pass --ui-dir.")
		return 1
	}
	var nodeTLSConfig *tls.Config
	if *nodeListen != "" {
		var err error
		nodeTLSConfig, err = loadNodeTLSConfig(*nodeTLSCert, *nodeTLSKey)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
	}
	var (
		accounts        account.Repository
		assetStore      assets.Repository
		approvalsStore  approvals.Repository
		store           repo.RuntimeBackend
		closeAccounts   = func() error { return nil }
		closeDatabase   = func() error { return nil }
		restartCleanup  = func(context.Context) error { return nil }
		notificationsOn bool
		absoluteDB      string
	)
	if *storage == "postgres" {
		dsn, err := repo.ReadPostgresDSNFile(*postgresDSNFile)
		if err != nil {
			fmt.Fprintln(stderr, "read PostgreSQL DSN file: invalid protected file")
			return 2
		}
		openCtx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		database, err := repo.OpenPostgres(openCtx, repo.PostgresConfig{DSN: dsn})
		if err == nil {
			_, err = repo.MigratePostgres(openCtx, database)
		}
		cancel()
		if err != nil {
			if database != nil {
				_ = database.Close()
			}
			fmt.Fprintf(stderr, "initialize PostgreSQL runtime: %v\n", err)
			return 1
		}
		closeDatabase = database.Close
		accounts, err = account.NewPostgres(database)
		if err == nil {
			assetStore, err = assets.NewPostgres(database)
		}
		if err == nil {
			approvalsStore, err = approvals.NewPostgres(database)
		}
		if err == nil {
			store, err = repo.NewPostgresRuntime(database)
		}
		if err == nil {
			initCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			err = store.InitReports(initCtx)
			cancel()
		}
		if err != nil {
			_ = closeDatabase()
			fmt.Fprintf(stderr, "initialize PostgreSQL repositories: %v\n", err)
			return 1
		}
	} else {
		var err error
		absoluteDB, err = filepath.Abs(*dbPath)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		localAccounts, err := account.New(absoluteDB)
		if err != nil {
			fmt.Fprintf(stderr, "open account database: %v\n", err)
			return 1
		}
		accounts = localAccounts
		closeAccounts = localAccounts.Close
		assetStore, err = assets.New(localAccounts.SQLDB())
		if err != nil {
			_ = closeAccounts()
			fmt.Fprintln(stderr, err)
			return 1
		}
		approvalsStore, err = approvals.New(localAccounts.SQLDB())
		if err != nil {
			_ = closeAccounts()
			fmt.Fprintln(stderr, err)
			return 1
		}
		store, err = repo.NewRuntime(localAccounts.SQLDB())
		if err != nil {
			_ = closeAccounts()
			fmt.Fprintf(stderr, "open task database: %v\n", err)
			return 1
		}
		notificationsOn = true
		restartCleanup = func(ctx context.Context) error {
			if _, err := localAccounts.SQLDB().ExecContext(ctx, `UPDATE scan_tasks SET status='FAILED',details=json_set(details,'$.error','Server restarted during scan; create a new task') WHERE status='RUNNING'`); err != nil {
				return err
			}
			_, err := localAccounts.SQLDB().ExecContext(ctx, `UPDATE rule_jobs SET status='PENDING',data=json_set(data,'$.nodeId','') WHERE status='RUNNING'`)
			return err
		}
	}
	defer closeAccounts()
	defer closeDatabase()
	defer store.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if *reportDir == "" {
		if *storage == "postgres" {
			*reportDir = filepath.Join("runtime", "reports")
		} else {
			*reportDir = filepath.Join(filepath.Dir(absoluteDB), "reports")
		}
	}
	go store.RunReports(ctx, *reportDir)
	if err := restartCleanup(ctx); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if refresher, ok := assetStore.(interface{ RefreshReachability(context.Context) error }); ok {
		go func() {
			for {
				if err := refresher.RefreshReachability(ctx); err != nil && ctx.Err() == nil {
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
	if notificationsOn {
		go func() {
			ticker := time.NewTicker(5 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					if err := store.RefreshNotifications(ctx); err != nil && ctx.Err() == nil {
						slog.Error("notification refresh failed", "error", err)
					}
					if _, err := store.DispatchNotificationOutbox(ctx); err != nil && ctx.Err() == nil {
						slog.Error("notification delivery failed", "error", err)
					}
				}
			}
		}()
	}
	baseHandler := api.NewRuntimeHandler(store, api.NewDevelopmentHandler(accounts, assetStore, approvalsStore), *uiDir, accounts)
	handler := http.Handler(baseHandler)
	var nodeTokens api.NodeTokenSet
	if *nodeTokenFile != "" {
		tokens, err := api.ReadNodeTokenSetFile(*nodeTokenFile)
		if err != nil {
			fmt.Fprintln(stderr, "read node token registry:", err)
			return 1
		}
		nodeTokens = tokens
		handler = api.NodeAuthMiddleware(handler, tokens)
	}
	server := &http.Server{Addr: *addr, Handler: handler, ReadHeaderTimeout: 5 * time.Second}
	var nodeServer *http.Server
	var nodeListener net.Listener
	if *nodeListen != "" {
		listener, err := net.Listen("tcp", *nodeListen)
		if err != nil {
			fmt.Fprintln(stderr, "listen node API:", err)
			return 1
		}
		nodeListener = tls.NewListener(listener, nodeTLSConfig)
		nodeHandler := api.NodeProtocolHandler(api.NodeAuthMiddleware(baseHandler, nodeTokens))
		nodeServer = &http.Server{Addr: *nodeListen, Handler: nodeHandler, ReadHeaderTimeout: 5 * time.Second, TLSConfig: nodeTLSConfig}
		go func() {
			if err := nodeServer.Serve(nodeListener); err != nil && !errors.Is(err, http.ErrServerClosed) {
				slog.Error("node API stopped", "error", err)
			}
		}()
		fmt.Fprintf(stdout, "Node API: https://%s\n", *nodeListen)
		slog.Info("node API started", "address", *nodeListen, "tls", true)
	}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
		if nodeServer != nil {
			_ = nodeServer.Shutdown(shutdown)
		}
	}()
	fmt.Fprintf(stdout, "Web UI: http://%s/#/tasks\n", *addr)
	slog.Info("local framework started", "address", *addr, "mode", *storage)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Fprintf(stderr, "serve framework: %v\n", err)
		return 1
	}
	return 0
}

func readInitialPassword(path string, stderr io.Writer) ([]byte, error) {
	if path != "" {
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode()&0077 != 0 {
			return nil, errors.New("password file must exist and be owner-only (0600)")
		}
		password, err := os.ReadFile(path)
		if err != nil || len(password) > 256 {
			return nil, errors.New("unable to read password file")
		}
		return password, nil
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return nil, errors.New("initial admin password requires an interactive terminal or --password-file")
	}
	fmt.Fprint(stderr, "Initial admin password (12–72 bytes): ")
	password, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(stderr)
	if err != nil {
		return nil, errors.New("unable to read terminal password")
	}
	return password, nil
}

func initPostgresAdmin(dsnFile, username string, password []byte, stdout, stderr io.Writer) int {
	dsn, err := repo.ReadPostgresDSNFile(dsnFile)
	if err != nil {
		fmt.Fprintln(stderr, "read PostgreSQL DSN file: invalid protected file")
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	db, err := repo.OpenPostgres(ctx, repo.PostgresConfig{DSN: dsn})
	if err == nil {
		_, err = repo.MigratePostgres(ctx, db)
	}
	if err != nil {
		if db != nil {
			_ = db.Close()
		}
		fmt.Fprintf(stderr, "initialize PostgreSQL schema: %v\n", err)
		return 1
	}
	defer db.Close()
	store, err := account.NewPostgres(db)
	if err != nil {
		fmt.Fprintf(stderr, "open PostgreSQL account store: %v\n", err)
		return 1
	}
	if err := store.InitAdmin(ctx, username, strings.TrimRight(string(password), "\r\n")); err != nil {
		fmt.Fprintf(stderr, "initialize admin: %v\n", err)
		return 1
	}
	fmt.Fprintln(stdout, "Administrator initialized. Server can now be started.")
	return 0
}
