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
	status := flags.Bool("status", false, "Print worker mode and exit")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if *status {
		fmt.Fprintln(stdout, `{"role":"sec-worker","mode":"synthetic","scanning":false}`)
		return 0
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
