package portable

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"scanner-platform/internal/bootstrap"
	"scanner-platform/internal/webui"
)

// Main is the sec-portable command line: run (default), --status, or prepare.
func Main(args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 && args[0] == "prepare" {
		return prepare(args[1:], stdout, stderr)
	}
	flags := flag.NewFlagSet("sec-portable", flag.ContinueOnError)
	flags.SetOutput(stderr)
	home := flags.String("home", "", "Portable directory (default: the directory holding this program)")
	listen := flags.String("listen", "127.0.0.1:8080", "Numeric loopback address for the web console")
	uiDir := flags.String("ui-dir", "", "Serve the web UI from this directory instead of the embedded copy")
	noBrowser := flags.Bool("no-browser", false, "Do not open the web console in a browser")
	status := flags.Bool("status", false, "Print the portable layout and exit")
	flags.Usage = func() {
		fmt.Fprintln(stderr, "用法：sec-portable [选项]        启动平台（Server、Worker、Updater 在同一进程）")
		fmt.Fprintln(stderr, "      sec-portable prepare [选项]  在联网机器上准备漏洞库和规则，不扫描")
		flags.PrintDefaults()
	}
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if flags.NArg() != 0 {
		flags.Usage()
		return 2
	}
	if *status {
		return printStatus(*home, *listen, stdout, stderr)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := Run(ctx, Options{Home: *home, Listen: *listen, UIDir: *uiDir, OpenBrowser: !*noBrowser}, stdout, stderr); err != nil {
		fmt.Fprintln(stderr, "sec-portable:", err)
		return 1
	}
	return 0
}

func printStatus(home, listen string, stdout, stderr io.Writer) int {
	layout, err := ResolveLayout(home)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	exists := func(path string) bool { _, err := os.Stat(path); return err == nil }
	engine := func(name string) bool {
		return exists(filepath.Join(layout.Bin, name)) || exists(filepath.Join(layout.Bin, name+".exe"))
	}
	_, embedded := webui.FileSystem()
	sshConfig, _ := layout.OptionalSSHConfig()
	keys, _ := layout.TrustedRuleKeys()
	_ = json.NewEncoder(stdout).Encode(map[string]any{
		"role": "sec-portable", "mode": "portable", "listen": listen, "home": layout.Home,
		"embeddedUI": embedded, "rulesActivated": exists(filepath.Join(layout.Rules, "CURRENT")),
		"engines":   map[string]bool{"nuclei": engine("nuclei"), "trivy": engine("trivy")},
		"sshConfig": sshConfig != "", "trustedRuleKeys": len(keys),
		// Without a Linux firewall the scan scope is enforced in Go (rule 4.1-8).
		"networkFence": false,
	})
	return 0
}

// prepare runs the Updater's --prepare-engines against the portable layout.
// It downloads vulnerability data and activates rules; it never scans.
func prepare(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("sec-portable prepare", flag.ContinueOnError)
	flags.SetOutput(stderr)
	home := flags.String("home", "", "Portable directory (default: the directory holding this program)")
	withJava := flags.Bool("with-java-db", false, "Include the Trivy Java artifact index")
	skipDownload := flags.Bool("skip-db-download", false, "Use the existing Trivy database cache")
	templatesDir := flags.String("nuclei-templates-dir", "", "Directory of curated read-only JSON Nuclei templates to include")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(stderr, "prepare takes flags only")
		return 2
	}
	layout, err := ResolveLayout(*home)
	if err == nil {
		err = layout.Prepare()
	}
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	// The running platform also writes the rule directory; never do both at once.
	release, err := acquireLock(layout.LockFile)
	if err != nil {
		fmt.Fprintln(stderr, "sec-portable prepare:", err, "— stop the running sec-portable first")
		return 1
	}
	defer release()
	keys, err := layout.TrustedRuleKeys()
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	manager, err := bootstrap.NewRuleManager(layout.Rules, keys)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 2*time.Hour)
	defer cancel()
	if err := bootstrap.PrepareEngines(ctx, manager, bootstrap.PrepareOptions{
		BinDir: layout.Bin, DBCache: layout.EngineData, WorkDir: layout.Runtime,
		WithJava: *withJava, SkipDownload: *skipDownload, TemplatesDir: *templatesDir,
	}, stdout); err != nil {
		fmt.Fprintln(stderr, "sec-portable prepare:", err)
		return 1
	}
	return 0
}
