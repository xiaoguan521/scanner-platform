package bootstrap

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/signal"
	"scanner-platform/internal/rules"
	"syscall"
)

func RunUpdater(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("sec-updater", flag.ContinueOnError)
	flags.SetOutput(stderr)
	server := flags.String("server", "http://127.0.0.1:8080", "Local Server URL")
	id := flags.String("id", "updater-local", "Updater identifier")
	root := flags.String("rules-dir", "vuln-data", "Updater-owned rule directory")
	once := flags.Bool("once", false, "Process at most one queued operation")
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
	if err != nil || endpoint.Scheme != "http" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" || (endpoint.Path != "" && endpoint.Path != "/") || !isNumericLoopback(endpoint.Host) || *id == "" || flags.NArg() != 0 {
		fmt.Fprintln(stderr, "provide a local numeric loopback Server URL and updater ID")
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	agent := rules.Agent{ServerURL: *server, ID: *id, Manager: &rules.Manager{Root: *root}}
	if err := agent.Run(ctx, *once); err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintf(stderr, "updater stopped: %v\n", err)
		return 1
	}
	return 0
}
