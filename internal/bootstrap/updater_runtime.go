package bootstrap

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"scanner-platform/internal/api"
	"scanner-platform/internal/executor"
	"scanner-platform/internal/rules"
	"syscall"
	"time"
)

func RunUpdater(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("sec-updater", flag.ContinueOnError)
	flags.SetOutput(stderr)
	server := flags.String("server", "http://127.0.0.1:8080", "Local Server URL")
	nodeTokenFile := flags.String("node-token-file", "", "Owner-only bearer token file for the Updater node API")
	nodeCACert := flags.String("node-ca-cert", "", "PEM CA bundle used to verify an HTTPS Server node API")
	nodeClientCert := flags.String("node-client-cert", "", "Optional PEM client certificate for mTLS")
	nodeClientKey := flags.String("node-client-key", "", "Owner-only PEM client private key for mTLS")
	id := flags.String("id", "updater-local", "Updater identifier")
	root := flags.String("rules-dir", "vuln-data", "Updater-owned rule directory")
	trustedKey := flags.String("trusted-rule-public-key", "", "External Ed25519 PUBLIC KEY PEM file for rule import and activation")
	importBundle := flags.String("import-bundle-file", "", "Import a signed ZIP directly from a local file (large offline artifacts supported)")
	prepare := flags.Bool("prepare-engines", false, "Install and activate baseline templates and Trivy DB; no scans")
	skipDownload := flags.Bool("skip-db-download", false, "Use the existing Trivy DB cache during preparation")
	withJava := flags.Bool("with-java-db", false, "Include Java artifact index in explicit engine preparation")
	binDir := flags.String("bin-dir", "bin", "Pinned engine binaries")
	dbCache := flags.String("db-cache", "runtime/engine-data/trivy", "Updater DB download cache")
	once := flags.Bool("once", false, "Process at most one queued operation")
	syncStateOnly := flags.Bool("sync-state-only", false, "Publish local rule catalog metadata, then exit")
	status := flags.Bool("status", false, "Print updater mode")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if *status {
		fmt.Fprintln(stdout, `{"role":"sec-updater","mode":"local","scanning":false}`)
		return 0
	}
	endpoint, err := url.Parse(*server)
	if err != nil || (endpoint.Scheme != "http" && endpoint.Scheme != "https") || endpoint.Host == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" || (endpoint.Path != "" && endpoint.Path != "/") || endpoint.Scheme == "http" && !isNumericLoopback(endpoint.Host) || *id == "" || flags.NArg() != 0 {
		fmt.Fprintln(stderr, "provide an http loopback or HTTPS Server URL and updater ID")
		return 2
	}
	if endpoint.Scheme == "https" && *nodeTokenFile == "" {
		fmt.Fprintln(stderr, "HTTPS Server URL requires --node-token-file")
		return 2
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
	client := &http.Client{Timeout: 2 * time.Minute, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }, Transport: &http.Transport{Proxy: nil, TLSClientConfig: clientTLS}}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	manager := &rules.Manager{Root: *root}
	if *trustedKey != "" {
		manager, err = rules.NewVerifiedManager(*root, *trustedKey)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
	}
	if *importBundle != "" {
		if *prepare || *skipDownload || *withJava || *once || *syncStateOnly {
			fmt.Fprintln(stderr, "--import-bundle-file cannot be combined with preparation, --once or --sync-state-only")
			return 2
		}
		archivePath, err := filepath.Abs(*importBundle)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		bundle, err := manager.ImportFile(ctx, archivePath)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		fmt.Fprintln(stdout, "Imported signed rules", bundle.Version, "(manifest signature and file hashes verified)")
		fmt.Fprintln(stdout, "Restart the Updater, then activate this version from the rules page so the operation is audited")
		return 0
	}
	if *syncStateOnly {
		if *prepare || *skipDownload || *withJava || *once {
			fmt.Fprintln(stderr, "--sync-state-only cannot be combined with preparation or --once")
			return 2
		}
		agent := rules.Agent{ServerURL: *server, ID: *id, NodeToken: nodeToken, Manager: manager, Client: client}
		if err := agent.SyncState(ctx); err != nil {
			fmt.Fprintln(stderr, "sync rule state:", err)
			return 1
		}
		fmt.Fprintln(stdout, "Synchronized local rule catalog metadata")
		return 0
	}
	if *prepare {
		absolute := func(path string) string { p, _ := filepath.Abs(path); return p }
		if !*skipDownload {
			fmt.Fprintln(stdout, "Downloading Trivy vulnerability database (no scan)...")
			if err := executor.DownloadTrivyDB(ctx, absolute(*binDir), absolute(*dbCache), absolute("runtime/updater-prepare")); err != nil {
				fmt.Fprintln(stderr, err)
				return 1
			}
			if *withJava {
				fmt.Fprintln(stdout, "Downloading Trivy Java artifact index (no scan)...")
				if err := executor.DownloadTrivyJavaDB(ctx, absolute(*binDir), absolute(*dbCache), absolute("runtime/updater-prepare-java")); err != nil {
					fmt.Fprintln(stderr, err)
					return 1
				}
			}
		}
		version := time.Now().UTC().Format("20060102.150405")
		fmt.Fprintln(stdout, "Packaging, hashing and installing local engine rules...")
		bundle, err := manager.PrepareDefault(ctx, version, absolute(*dbCache), *withJava)
		if err == nil {
			err = manager.ActivatePreparedLocal(ctx, bundle.Version)
		}
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		fmt.Fprintln(stdout, "Activated rules", bundle.Version, "(Nuclei root-GET baseline + Trivy DB)")
		if *withJava {
			fmt.Fprintln(stdout, "Java artifact index included; scan runners remain offline")
		}
		return 0
	}
	agent := rules.Agent{ServerURL: *server, ID: *id, NodeToken: nodeToken, Manager: manager, Client: client}
	if err := agent.Run(ctx, *once); err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintf(stderr, "updater stopped: %v\n", err)
		return 1
	}
	return 0
}
