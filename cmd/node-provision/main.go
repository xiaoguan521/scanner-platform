package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strings"

	"scanner-platform/internal/provision"
)

type nodeFlags []provision.NodeSpec

func (n *nodeFlags) String() string {
	values := make([]string, 0, len(*n))
	for _, item := range *n {
		values = append(values, item.ID+"="+item.Kind)
	}
	return strings.Join(values, ",")
}

func (n *nodeFlags) Set(value string) error {
	id, kind, ok := strings.Cut(strings.TrimSpace(value), "=")
	if !ok || strings.TrimSpace(id) == "" || strings.TrimSpace(kind) == "" {
		return errors.New("node must use id=worker or id=updater")
	}
	*n = append(*n, provision.NodeSpec{ID: id, Kind: kind})
	return nil
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	certLife, caLife := provision.Defaults()
	flags := flag.NewFlagSet("sec-node-provision", flag.ContinueOnError)
	flags.SetOutput(stderr)
	outputDir := flags.String("output-dir", "", "new directory for Server and node material")
	splitFrom := flags.String("split-from", "", "complete material directory to split into a role-scoped package")
	splitOutput := flags.String("split-output-dir", "", "new directory for a role-scoped package")
	packageRole := flags.String("package-role", "", "role for --split-from: server, worker or updater")
	packageNodeID := flags.String("node-id", "", "node ID for a worker or updater package")
	rotateDir := flags.String("rotate-dir", "", "existing material directory to rotate in place")
	verifyDir := flags.String("verify-dir", "", "transferred material directory to verify without changing it")
	caDir := flags.String("ca-dir", "", "directory containing ca-key.pem and ca-cert.pem")
	serverIP := flags.String("server-ip", "", "explicit numeric Server node IP")
	serverPort := flags.Uint("server-port", 8443, "Server node HTTPS port")
	validFor := flags.Duration("valid-for", certLife, "Server and client certificate lifetime")
	caValidFor := flags.Duration("ca-valid-for", caLife, "new CA certificate lifetime")
	generateCA := flags.Bool("generate-ca", false, "create a new CA in --ca-dir")
	var nodes nodeFlags
	flags.Var(&nodes, "node", "node to provision, repeated as id=worker or id=updater")
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
	modeCount := 0
	for _, value := range []string{*outputDir, *rotateDir, *verifyDir, *splitFrom} {
		if strings.TrimSpace(value) != "" {
			modeCount++
		}
	}
	if modeCount != 1 {
		fmt.Fprintln(stderr, "use exactly one of --output-dir, --rotate-dir, --verify-dir or --split-from")
		return 2
	}
	if strings.TrimSpace(*splitFrom) != "" {
		if strings.TrimSpace(*splitOutput) == "" || strings.TrimSpace(*packageRole) == "" {
			fmt.Fprintln(stderr, "--split-from requires --split-output-dir and --package-role")
			return 2
		}
		if strings.TrimSpace(*caDir) != "" || strings.TrimSpace(*serverIP) != "" || len(nodes) != 0 || *generateCA || strings.TrimSpace(*rotateDir) != "" || strings.TrimSpace(*verifyDir) != "" {
			fmt.Fprintln(stderr, "--split-from cannot be combined with CA, Server IP, node or other mode options")
			return 2
		}
		result, err := provision.Package(provision.PackageOptions{
			SourceDir: *splitFrom,
			OutputDir: *splitOutput,
			Role:      provision.PackageRole(strings.TrimSpace(*packageRole)),
			NodeID:    strings.TrimSpace(*packageNodeID),
		})
		if err != nil {
			fmt.Fprintln(stderr, "node package creation failed:", err)
			return 1
		}
		if err := json.NewEncoder(stdout).Encode(result); err != nil {
			fmt.Fprintln(stderr, "write package result:", err)
			return 1
		}
		fmt.Fprintf(stderr, "Created %s node material package; run --verify-dir before service restart.\n", result.Role)
		return 0
	}
	if strings.TrimSpace(*splitOutput) != "" || strings.TrimSpace(*packageRole) != "" || strings.TrimSpace(*packageNodeID) != "" {
		fmt.Fprintln(stderr, "--split-output-dir, --package-role and --node-id require --split-from")
		return 2
	}
	if strings.TrimSpace(*verifyDir) != "" {
		if strings.TrimSpace(*caDir) != "" || strings.TrimSpace(*serverIP) != "" || len(nodes) != 0 || *generateCA {
			fmt.Fprintln(stderr, "--verify-dir cannot be combined with CA, Server IP, or node provisioning options")
			return 2
		}
		result, err := provision.Verify(provision.VerifyOptions{OutputDir: *verifyDir})
		if err != nil {
			fmt.Fprintln(stderr, "node material verification failed:", err)
			return 1
		}
		if err := json.NewEncoder(stdout).Encode(result); err != nil {
			fmt.Fprintln(stderr, "write verification result:", err)
			return 1
		}
		fmt.Fprintf(stderr, "Verified %d node(s) and %d material file(s); no files changed.\n", len(result.NodeIDs), result.FileCount)
		return 0
	}
	if strings.TrimSpace(*caDir) == "" {
		fmt.Fprintln(stderr, "--ca-dir is required for provisioning or rotation")
		return 2
	}
	if strings.TrimSpace(*rotateDir) != "" {
		result, err := provision.Rotate(provision.RotateOptions{OutputDir: *rotateDir, CADir: *caDir, ValidFor: *validFor})
		if err != nil {
			fmt.Fprintln(stderr, "node material rotation failed:", err)
			return 1
		}
		if err := json.NewEncoder(stdout).Encode(result); err != nil {
			fmt.Fprintln(stderr, "write rotation result:", err)
			return 1
		}
		fmt.Fprintln(stderr, "Rotated server and client certificates; reload the affected services after transferring the files.")
		return 0
	}
	if len(nodes) == 0 || strings.TrimSpace(*outputDir) == "" || strings.TrimSpace(*serverIP) == "" || *serverPort == 0 || *serverPort > 65535 {
		fmt.Fprintln(stderr, "--output-dir, --ca-dir, --server-ip and at least one --node are required; server port must be 1-65535")
		return 2
	}
	ip, err := netip.ParseAddr(strings.TrimSpace(*serverIP))
	if err != nil {
		fmt.Fprintln(stderr, "--server-ip must be a numeric IP")
		return 2
	}
	result, err := provision.Provision(provision.Options{
		OutputDir:  *outputDir,
		CADir:      *caDir,
		ServerIP:   ip,
		ServerPort: uint16(*serverPort),
		Nodes:      nodes,
		ValidFor:   *validFor,
		CAValidFor: *caValidFor,
		GenerateCA: *generateCA,
	})
	if err != nil {
		fmt.Fprintln(stderr, "node provisioning failed:", err)
		return 1
	}
	if err := json.NewEncoder(stdout).Encode(result); err != nil {
		fmt.Fprintln(stderr, "write provisioning result:", err)
		return 1
	}
	fmt.Fprintf(stderr, "Provisioned %d node(s); copy secret files through an owner-managed deployment channel.\n", len(result.Nodes))
	return 0
}
