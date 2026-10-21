package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strings"

	"scanner-platform/internal/deploy"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("sec-node-deploy", flag.ContinueOnError)
	flags.SetOutput(stderr)
	packageDir := flags.String("package-dir", "", "verified role-scoped node package directory")
	targetIP := flags.String("target-ip", "", "explicit numeric node IP")
	sshPort := flags.Uint("ssh-port", 22, "SSH port")
	user := flags.String("user", "", "SSH user")
	identity := flags.String("identity-file", "", "owner-only SSH private key file")
	knownHosts := flags.String("known-hosts-file", "", "pinned SSH known-hosts file")
	remoteDir := flags.String("remote-dir", "/var/lib/scanner-platform/node-materials", "new remote material directory")
	service := flags.String("service", "", "fixed scanner service name to restart")
	provisionBinary := flags.String("provision-binary", "/opt/sec/bin/sec-node-provision", "remote node provisioning verifier")
	rotateExisting := flags.Bool("rotate-existing", false, "replace an existing remote package with rollback on restart failure")
	dryRun := flags.Bool("dry-run", true, "print the deployment plan without executing it")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(stderr, "unexpected positional arguments")
		return 2
	}
	ip, err := netip.ParseAddr(strings.TrimSpace(*targetIP))
	if err != nil {
		fmt.Fprintln(stderr, "--target-ip must be a numeric IP")
		return 2
	}
	if *sshPort == 0 || *sshPort > 65535 {
		fmt.Fprintln(stderr, "--ssh-port must be between 1 and 65535")
		return 2
	}
	plan, err := deploy.BuildPlan(deploy.Options{
		PackageDir:      *packageDir,
		TargetIP:        ip,
		SSHPort:         uint16(*sshPort),
		User:            strings.TrimSpace(*user),
		IdentityFile:    *identity,
		KnownHostsFile:  *knownHosts,
		RemoteDir:       *remoteDir,
		ServiceName:     strings.TrimSpace(*service),
		ProvisionBinary: *provisionBinary,
		RotateExisting:  *rotateExisting,
	})
	if err != nil {
		fmt.Fprintln(stderr, "node deployment plan rejected:", err)
		return 1
	}
	if err := json.NewEncoder(stdout).Encode(plan); err != nil {
		fmt.Fprintln(stderr, "write deployment plan:", err)
		return 1
	}
	if *dryRun {
		fmt.Fprintln(stderr, "dry run: no SSH or SCP command was executed")
		return 0
	}
	if err := plan.Execute(context.Background(), deploy.ExecRunner{}); err != nil {
		fmt.Fprintln(stderr, "node deployment failed:", err)
		return 1
	}
	fmt.Fprintln(stderr, "node package deployed and service restarted")
	return 0
}
