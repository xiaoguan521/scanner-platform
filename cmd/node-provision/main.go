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
	if flags.NArg() != 0 || len(nodes) == 0 || strings.TrimSpace(*outputDir) == "" || strings.TrimSpace(*caDir) == "" || strings.TrimSpace(*serverIP) == "" || *serverPort == 0 || *serverPort > 65535 {
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
