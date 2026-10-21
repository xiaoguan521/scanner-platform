// Package provision creates the file material required by an explicitly
// configured Server/Worker/Updater node deployment. It never contacts a
// network and never prints bearer tokens or private keys.
package provision

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	defaultServerPort = 8443
	defaultCertLife   = 90 * 24 * time.Hour
	defaultCALife     = 365 * 24 * time.Hour
	minTokenBytes     = 32
	maxNodeIDLength   = 64
)

var nodeIDPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$`)

// NodeSpec identifies one node that will receive a client certificate and a
// single bearer-token file. Only the node roles accepted by the runtime are
// allowed here.
type NodeSpec struct {
	ID   string
	Kind string
}

// Options controls a local, offline provisioning run. Existing output files
// are never overwritten. When GenerateCA is false, CADir must contain an
// owner-only ca-key.pem and its matching ca-cert.pem.
type Options struct {
	OutputDir  string
	CADir      string
	ServerIP   netip.Addr
	ServerPort uint16
	Nodes      []NodeSpec
	ValidFor   time.Duration
	CAValidFor time.Duration
	GenerateCA bool
	Now        func() time.Time
}

// Result describes generated paths without including secret values.
type Result struct {
	OutputDir         string       `json:"outputDir"`
	CACert            string       `json:"caCert"`
	ServerCert        string       `json:"serverCert"`
	ServerKey         string       `json:"serverKey"`
	NodeTokenRegistry string       `json:"nodeTokenRegistry"`
	ServerURL         string       `json:"serverUrl"`
	Nodes             []NodeResult `json:"nodes"`
	Manifest          string       `json:"manifest"`
}

// PackageRole identifies the least-privilege material package for one
// deployment role. A server package contains the server key and token
// registry; a worker/updater package contains only that node's client key,
// certificate and token plus the CA certificate.
type PackageRole string

const (
	PackageRoleServer  PackageRole = "server"
	PackageRoleWorker  PackageRole = "worker"
	PackageRoleUpdater PackageRole = "updater"
)

// PackageOptions controls creation of a role-scoped material package from a
// complete offline provisioning directory. The source is verified before any
// output is published. Package creation never contacts a network.
type PackageOptions struct {
	SourceDir string
	OutputDir string
	Role      PackageRole
	NodeID    string
	Now       func() time.Time
}

// PackageResult contains only non-secret deployment metadata.
type PackageResult struct {
	OutputDir string      `json:"outputDir"`
	Role      PackageRole `json:"role"`
	NodeID    string      `json:"nodeId,omitempty"`
	ServerURL string      `json:"serverUrl"`
	Manifest  string      `json:"manifest"`
	Files     []string    `json:"files"`
}

// RotateOptions controls an offline replacement of an existing material
// directory. The CA private key remains in CADir and bearer-token files are
// copied unchanged; only the server and client certificate/key pairs change.
type RotateOptions struct {
	OutputDir string
	CADir     string
	ValidFor  time.Duration
	Now       func() time.Time
}

// VerifyOptions controls an offline verification of a transferred material
// directory. Verification never needs the CA private key and never prints
// bearer tokens or private key contents.
type VerifyOptions struct {
	OutputDir string
	Now       func() time.Time
}

// VerifyResult contains only non-secret deployment metadata. It is safe for
// the CLI to encode this structure as JSON for an operator or deployment
// system.
type VerifyResult struct {
	OutputDir                 string      `json:"outputDir"`
	Role                      PackageRole `json:"role,omitempty"`
	NodeID                    string      `json:"nodeId,omitempty"`
	ServerURL                 string      `json:"serverUrl"`
	FileCount                 int         `json:"fileCount"`
	NodeIDs                   []string    `json:"nodeIds"`
	CACertificateNotAfter     time.Time   `json:"caCertificateNotAfter"`
	ServerCertificateNotAfter time.Time   `json:"serverCertificateNotAfter"`
}

type manifestDocument struct {
	Version     int          `json:"version"`
	PackageRole PackageRole  `json:"packageRole,omitempty"`
	NodeID      string       `json:"nodeId,omitempty"`
	ServerURL   string       `json:"serverUrl"`
	Files       []string     `json:"files"`
	Nodes       []NodeResult `json:"nodes"`
}

// NodeResult describes the non-secret locations for one provisioned node.
type NodeResult struct {
	ID         string `json:"id"`
	Kind       string `json:"kind"`
	TokenFile  string `json:"tokenFile"`
	ClientCert string `json:"clientCert"`
	ClientKey  string `json:"clientKey"`
}

type certificateAuthority struct {
	key  *ecdsa.PrivateKey
	cert *x509.Certificate
}

// Provision creates a CA (when requested), a Server certificate, one client
// certificate per node, and token files. The generated CA private key stays
// in CADir and is never copied into OutputDir.
func Provision(opts Options) (Result, error) {
	now := time.Now
	if opts.Now != nil {
		now = opts.Now
	}
	when := now().UTC()
	if opts.ServerPort == 0 {
		opts.ServerPort = defaultServerPort
	}
	if err := validateOptions(opts); err != nil {
		return Result{}, err
	}
	outputDir, err := filepath.Abs(opts.OutputDir)
	if err != nil {
		return Result{}, fmt.Errorf("resolve output directory: %w", err)
	}
	caDir, err := filepath.Abs(opts.CADir)
	if err != nil {
		return Result{}, fmt.Errorf("resolve CA directory: %w", err)
	}
	if err := rejectNestedPaths(outputDir, caDir); err != nil {
		return Result{}, err
	}
	if err := ensureParent(outputDir); err != nil {
		return Result{}, err
	}
	if err := ensureDirAbsent(outputDir); err != nil {
		return Result{}, err
	}

	ca, err := loadOrCreateCA(caDir, opts.GenerateCA, when, opts.CAValidFor)
	if err != nil {
		return Result{}, err
	}
	if when.Add(opts.ValidFor).After(ca.cert.NotAfter) {
		return Result{}, errors.New("leaf certificate lifetime exceeds CA lifetime")
	}

	tmp, err := os.MkdirTemp(filepath.Dir(outputDir), ".scanner-node-materials-*")
	if err != nil {
		return Result{}, fmt.Errorf("create temporary output directory: %w", err)
	}
	if err := os.Chmod(tmp, 0700); err != nil {
		_ = os.RemoveAll(tmp)
		return Result{}, fmt.Errorf("protect temporary output directory: %w", err)
	}
	defer os.RemoveAll(tmp)

	result := Result{
		OutputDir:         outputDir,
		CACert:            filepath.Join(outputDir, "ca-cert.pem"),
		ServerCert:        filepath.Join(outputDir, "server-cert.pem"),
		ServerKey:         filepath.Join(outputDir, "server-key.pem"),
		NodeTokenRegistry: filepath.Join(outputDir, "node-tokens"),
		ServerURL:         fmt.Sprintf("https://%s:%d", opts.ServerIP.String(), opts.ServerPort),
		Nodes:             make([]NodeResult, 0, len(opts.Nodes)),
		Manifest:          filepath.Join(outputDir, "manifest.json"),
	}
	if err := writeFile(filepath.Join(tmp, "ca-cert.pem"), pemBytes("CERTIFICATE", ca.cert.Raw), 0644); err != nil {
		return Result{}, err
	}
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return Result{}, fmt.Errorf("generate server key: %w", err)
	}
	serverCert, err := issueCertificate(ca, serverKey, "scanner-platform-server", when, opts.ValidFor, true, false, opts.ServerIP)
	if err != nil {
		return Result{}, fmt.Errorf("issue server certificate: %w", err)
	}
	serverKeyPEM, err := marshalPrivateKey(serverKey)
	if err != nil {
		return Result{}, fmt.Errorf("marshal server key: %w", err)
	}
	if err := writeFile(filepath.Join(tmp, "server-key.pem"), serverKeyPEM, 0600); err != nil {
		return Result{}, err
	}
	if err := writeFile(filepath.Join(tmp, "server-cert.pem"), pemBytes("CERTIFICATE", serverCert.Raw), 0644); err != nil {
		return Result{}, err
	}

	registry := make([]string, 0, len(opts.Nodes))
	for _, node := range opts.Nodes {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return Result{}, fmt.Errorf("generate %s key: %w", node.ID, err)
		}
		cert, err := issueCertificate(ca, key, node.ID, when, opts.ValidFor, false, true, opts.ServerIP)
		if err != nil {
			return Result{}, fmt.Errorf("issue %s certificate: %w", node.ID, err)
		}
		token, err := newToken()
		if err != nil {
			return Result{}, fmt.Errorf("generate %s token: %w", node.ID, err)
		}
		prefix := filepath.Join(tmp, node.ID)
		clientKeyPEM, err := marshalPrivateKey(key)
		if err != nil {
			return Result{}, fmt.Errorf("marshal %s key: %w", node.ID, err)
		}
		if err := writeFile(prefix+"-client-key.pem", clientKeyPEM, 0600); err != nil {
			return Result{}, err
		}
		if err := writeFile(prefix+"-client-cert.pem", pemBytes("CERTIFICATE", cert.Raw), 0644); err != nil {
			return Result{}, err
		}
		if err := writeFile(prefix+"-token", []byte(token+"\n"), 0600); err != nil {
			return Result{}, err
		}
		registry = append(registry, node.ID+"="+token)
		result.Nodes = append(result.Nodes, NodeResult{
			ID:         node.ID,
			Kind:       node.Kind,
			TokenFile:  filepath.Join(outputDir, node.ID+"-token"),
			ClientCert: filepath.Join(outputDir, node.ID+"-client-cert.pem"),
			ClientKey:  filepath.Join(outputDir, node.ID+"-client-key.pem"),
		})
	}
	sort.Strings(registry)
	if err := writeFile(filepath.Join(tmp, "node-tokens"), []byte(strings.Join(registry, "\n")+"\n"), 0600); err != nil {
		return Result{}, err
	}
	files := []string{"ca-cert.pem", "server-cert.pem", "server-key.pem", "node-tokens", "manifest.json"}
	for _, node := range result.Nodes {
		files = append(files, filepath.Base(node.TokenFile), filepath.Base(node.ClientCert), filepath.Base(node.ClientKey))
	}
	sort.Strings(files)
	manifest, err := json.MarshalIndent(manifestDocument{Version: 1, ServerURL: result.ServerURL, Files: files, Nodes: result.Nodes}, "", "  ")
	if err != nil {
		return Result{}, fmt.Errorf("encode provisioning manifest: %w", err)
	}
	if err := writeFile(filepath.Join(tmp, "manifest.json"), append(manifest, '\n'), 0644); err != nil {
		return Result{}, err
	}
	if err := os.Rename(tmp, outputDir); err != nil {
		return Result{}, fmt.Errorf("publish node materials: %w", err)
	}
	return result, nil
}

// Package creates a role-scoped copy of a complete provisioning directory.
// The complete source is verified first, then only the files required by the
// selected role are copied into a new owner-only directory and published by a
// directory rename. Existing output is never overwritten.
func Package(opts PackageOptions) (PackageResult, error) {
	now := time.Now
	if opts.Now != nil {
		now = opts.Now
	}
	when := now().UTC()
	if err := validatePackageOptions(opts); err != nil {
		return PackageResult{}, err
	}
	sourceDir, err := filepath.Abs(opts.SourceDir)
	if err != nil {
		return PackageResult{}, fmt.Errorf("resolve source directory: %w", err)
	}
	outputDir, err := filepath.Abs(opts.OutputDir)
	if err != nil {
		return PackageResult{}, fmt.Errorf("resolve output directory: %w", err)
	}
	if err := rejectNestedPaths(sourceDir, outputDir); err != nil {
		return PackageResult{}, err
	}
	if _, err := Verify(VerifyOptions{OutputDir: sourceDir, Now: func() time.Time { return when }}); err != nil {
		return PackageResult{}, fmt.Errorf("verify source material: %w", err)
	}
	manifest, _, err := readManifest(sourceDir)
	if err != nil {
		return PackageResult{}, err
	}
	selected, err := selectPackageNodes(manifest, opts.Role, opts.NodeID)
	if err != nil {
		return PackageResult{}, err
	}
	files := packageFiles(opts.Role, opts.NodeID)
	if err := ensureParent(outputDir); err != nil {
		return PackageResult{}, err
	}
	if err := ensureDirAbsent(outputDir); err != nil {
		return PackageResult{}, err
	}
	tmp, err := os.MkdirTemp(filepath.Dir(outputDir), ".scanner-node-package-*")
	if err != nil {
		return PackageResult{}, fmt.Errorf("create package staging directory: %w", err)
	}
	if err := os.Chmod(tmp, 0700); err != nil {
		_ = os.RemoveAll(tmp)
		return PackageResult{}, fmt.Errorf("protect package staging directory: %w", err)
	}
	defer os.RemoveAll(tmp)
	for _, name := range files {
		secret := name == "server-key.pem" || name == "node-tokens" || strings.HasSuffix(name, "-client-key.pem") || strings.HasSuffix(name, "-token")
		data, err := readRegular(filepath.Join(sourceDir, name), secret)
		if err != nil {
			return PackageResult{}, fmt.Errorf("read source material %s: %w", name, err)
		}
		mode := os.FileMode(0644)
		if secret {
			mode = 0600
		}
		if err := writeFile(filepath.Join(tmp, name), data, mode); err != nil {
			return PackageResult{}, err
		}
	}
	packageNodes := make([]NodeResult, 0, len(selected))
	for _, node := range selected {
		packageNodes = append(packageNodes, NodeResult{
			ID:         node.ID,
			Kind:       node.Kind,
			TokenFile:  node.ID + "-token",
			ClientCert: node.ID + "-client-cert.pem",
			ClientKey:  node.ID + "-client-key.pem",
		})
	}
	manifestFiles := append(append([]string(nil), files...), "manifest.json")
	sort.Strings(manifestFiles)
	packageManifest := manifestDocument{
		Version:     2,
		PackageRole: opts.Role,
		NodeID:      opts.NodeID,
		ServerURL:   manifest.ServerURL,
		Files:       manifestFiles,
		Nodes:       packageNodes,
	}
	manifestBytes, err := json.MarshalIndent(packageManifest, "", "  ")
	if err != nil {
		return PackageResult{}, fmt.Errorf("encode package manifest: %w", err)
	}
	if err := writeFile(filepath.Join(tmp, "manifest.json"), append(manifestBytes, '\n'), 0644); err != nil {
		return PackageResult{}, err
	}
	if err := os.Rename(tmp, outputDir); err != nil {
		return PackageResult{}, fmt.Errorf("publish node package: %w", err)
	}
	return PackageResult{
		OutputDir: outputDir,
		Role:      opts.Role,
		NodeID:    opts.NodeID,
		ServerURL: manifest.ServerURL,
		Manifest:  filepath.Join(outputDir, "manifest.json"),
		Files:     manifestFiles,
	}, nil
}

func validatePackageOptions(opts PackageOptions) error {
	if strings.TrimSpace(opts.SourceDir) == "" || strings.TrimSpace(opts.OutputDir) == "" {
		return errors.New("source and output directories are required")
	}
	if opts.Role != PackageRoleServer && opts.Role != PackageRoleWorker && opts.Role != PackageRoleUpdater {
		return errors.New("package role must be server, worker or updater")
	}
	if opts.Role == PackageRoleServer && strings.TrimSpace(opts.NodeID) != "" {
		return errors.New("server package must not specify a node ID")
	}
	if opts.Role != PackageRoleServer && !nodeIDPattern.MatchString(opts.NodeID) {
		return errors.New("node package requires a valid node ID")
	}
	return nil
}

func selectPackageNodes(manifest manifestDocument, role PackageRole, nodeID string) ([]NodeResult, error) {
	if role == PackageRoleServer {
		return append([]NodeResult(nil), manifest.Nodes...), nil
	}
	for _, node := range manifest.Nodes {
		if node.ID == nodeID {
			if PackageRole(node.Kind) != role {
				return nil, fmt.Errorf("node %q has role %q, not %q", nodeID, node.Kind, role)
			}
			return []NodeResult{node}, nil
		}
	}
	return nil, fmt.Errorf("node %q is not present in source material", nodeID)
}

func packageFiles(role PackageRole, nodeID string) []string {
	if role == PackageRoleServer {
		return []string{"ca-cert.pem", "node-tokens", "server-cert.pem", "server-key.pem"}
	}
	return []string{"ca-cert.pem", nodeID + "-client-cert.pem", nodeID + "-client-key.pem", nodeID + "-token"}
}

// Rotate replaces an existing material directory in one directory-level
// swap. It is deliberately local and offline: callers still need to transfer
// the resulting files through their deployment channel and reload services.
func Rotate(opts RotateOptions) (Result, error) {
	now := time.Now
	if opts.Now != nil {
		now = opts.Now
	}
	when := now().UTC()
	if opts.ValidFor == 0 {
		opts.ValidFor = defaultCertLife
	}
	if strings.TrimSpace(opts.OutputDir) == "" || strings.TrimSpace(opts.CADir) == "" {
		return Result{}, errors.New("output and CA directories are required")
	}
	if opts.ValidFor <= 0 || opts.ValidFor > 397*24*time.Hour {
		return Result{}, errors.New("certificate lifetime must be between 1 hour and 397 days")
	}
	outputDir, err := filepath.Abs(opts.OutputDir)
	if err != nil {
		return Result{}, fmt.Errorf("resolve output directory: %w", err)
	}
	caDir, err := filepath.Abs(opts.CADir)
	if err != nil {
		return Result{}, fmt.Errorf("resolve CA directory: %w", err)
	}
	if err := rejectNestedPaths(outputDir, caDir); err != nil {
		return Result{}, err
	}
	manifest, originalManifest, err := readManifest(outputDir)
	if err != nil {
		return Result{}, err
	}
	serverIP, serverPort, err := parseServerURL(manifest.ServerURL)
	if err != nil {
		return Result{}, err
	}
	if err := validateManifestFiles(outputDir, manifest); err != nil {
		return Result{}, err
	}
	ca, err := loadOrCreateCA(caDir, false, when, 0)
	if err != nil {
		return Result{}, err
	}
	if err := validateOutputCACertificate(outputDir, ca.cert); err != nil {
		return Result{}, err
	}
	if when.Add(opts.ValidFor).After(ca.cert.NotAfter) {
		return Result{}, errors.New("leaf certificate lifetime exceeds CA lifetime")
	}

	result := Result{
		OutputDir:         outputDir,
		CACert:            filepath.Join(outputDir, "ca-cert.pem"),
		ServerCert:        filepath.Join(outputDir, "server-cert.pem"),
		ServerKey:         filepath.Join(outputDir, "server-key.pem"),
		NodeTokenRegistry: filepath.Join(outputDir, "node-tokens"),
		ServerURL:         manifest.ServerURL,
		Nodes:             append([]NodeResult(nil), manifest.Nodes...),
		Manifest:          filepath.Join(outputDir, "manifest.json"),
	}
	if err := stageRotatedDirectory(outputDir, manifest, originalManifest, ca, serverIP, serverPort, opts.ValidFor, when); err != nil {
		return Result{}, err
	}
	return result, nil
}

// Verify validates a node material directory after it has been copied to a
// deployment host. It checks the manifest, exact file set, permissions,
// token registry, certificate/key pairs and certificate chain. It does not
// contact the Server or change any file.
func Verify(opts VerifyOptions) (VerifyResult, error) {
	now := time.Now
	if opts.Now != nil {
		now = opts.Now
	}
	when := now().UTC()
	if strings.TrimSpace(opts.OutputDir) == "" {
		return VerifyResult{}, errors.New("output directory is required")
	}
	outputDir, err := filepath.Abs(opts.OutputDir)
	if err != nil {
		return VerifyResult{}, fmt.Errorf("resolve output directory: %w", err)
	}
	info, err := os.Lstat(outputDir)
	if err != nil {
		return VerifyResult{}, fmt.Errorf("inspect output directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return VerifyResult{}, errors.New("output directory must be a regular non-symlink directory")
	}
	if info.Mode().Perm()&0077 != 0 {
		return VerifyResult{}, errors.New("output directory must be owner-only")
	}
	manifest, _, err := readManifest(outputDir)
	if err != nil {
		return VerifyResult{}, err
	}
	if manifest.Version == 2 {
		return verifyRolePackage(outputDir, manifest, when)
	}
	serverIP, _, err := parseServerURL(manifest.ServerURL)
	if err != nil {
		return VerifyResult{}, err
	}
	if err := validateManifestFiles(outputDir, manifest); err != nil {
		return VerifyResult{}, err
	}
	ca, err := readCertificateFile(filepath.Join(outputDir, "ca-cert.pem"), "CA certificate")
	if err != nil {
		return VerifyResult{}, err
	}
	if !ca.IsCA || !ca.BasicConstraintsValid || ca.CheckSignature(ca.SignatureAlgorithm, ca.RawTBSCertificate, ca.Signature) != nil {
		return VerifyResult{}, errors.New("CA certificate is invalid")
	}
	if when.Before(ca.NotBefore) || !when.Before(ca.NotAfter) {
		return VerifyResult{}, errors.New("CA certificate is expired or not yet valid")
	}
	serverCert, err := readCertificateFile(filepath.Join(outputDir, "server-cert.pem"), "server certificate")
	if err != nil {
		return VerifyResult{}, err
	}
	if serverCert.Subject.CommonName != "scanner-platform-server" || len(serverCert.IPAddresses) != 1 || serverCert.IPAddresses[0].String() != serverIP.String() {
		return VerifyResult{}, errors.New("server certificate identity does not match the manifest")
	}
	if err := verifyLeafCertificate(serverCert, ca, x509.ExtKeyUsageServerAuth, when); err != nil {
		return VerifyResult{}, fmt.Errorf("verify server certificate: %w", err)
	}
	if err := verifyPrivateKeyPair(filepath.Join(outputDir, "server-key.pem"), serverCert, "server key"); err != nil {
		return VerifyResult{}, err
	}
	if err := validateNodeTokenRegistry(outputDir, manifest); err != nil {
		return VerifyResult{}, err
	}
	nodeIDs := make([]string, 0, len(manifest.Nodes))
	for _, node := range manifest.Nodes {
		cert, err := readCertificateFile(filepath.Join(outputDir, node.ID+"-client-cert.pem"), node.ID+" client certificate")
		if err != nil {
			return VerifyResult{}, err
		}
		if cert.Subject.CommonName != node.ID || len(cert.IPAddresses) != 0 {
			return VerifyResult{}, fmt.Errorf("client certificate identity for %s is invalid", node.ID)
		}
		if err := verifyLeafCertificate(cert, ca, x509.ExtKeyUsageClientAuth, when); err != nil {
			return VerifyResult{}, fmt.Errorf("verify client certificate for %s: %w", node.ID, err)
		}
		if err := verifyPrivateKeyPair(filepath.Join(outputDir, node.ID+"-client-key.pem"), cert, node.ID+" client key"); err != nil {
			return VerifyResult{}, err
		}
		nodeIDs = append(nodeIDs, node.ID)
	}
	sort.Strings(nodeIDs)
	return VerifyResult{
		OutputDir:                 outputDir,
		ServerURL:                 manifest.ServerURL,
		FileCount:                 len(manifest.Files),
		NodeIDs:                   nodeIDs,
		CACertificateNotAfter:     ca.NotAfter.UTC(),
		ServerCertificateNotAfter: serverCert.NotAfter.UTC(),
	}, nil
}

func validateOutputCACertificate(outputDir string, ca *x509.Certificate) error {
	data, err := readRegular(filepath.Join(outputDir, "ca-cert.pem"), false)
	if err != nil {
		return fmt.Errorf("read output CA certificate: %w", err)
	}
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" || len(strings.TrimSpace(string(rest))) != 0 {
		return errors.New("output CA certificate PEM is invalid")
	}
	output, err := x509.ParseCertificate(block.Bytes)
	if err != nil || !bytes.Equal(output.Raw, ca.Raw) {
		return errors.New("output CA certificate does not match the configured CA")
	}
	return nil
}

func readManifest(outputDir string) (manifestDocument, []byte, error) {
	info, err := os.Lstat(outputDir)
	if err != nil {
		return manifestDocument{}, nil, fmt.Errorf("inspect output directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return manifestDocument{}, nil, errors.New("output directory must be a regular non-symlink directory")
	}
	data, err := readRegular(filepath.Join(outputDir, "manifest.json"), false)
	if err != nil {
		return manifestDocument{}, nil, fmt.Errorf("read provisioning manifest: %w", err)
	}
	var manifest manifestDocument
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil || decoder.Decode(new(any)) != io.EOF {
		return manifestDocument{}, nil, errors.New("provisioning manifest is invalid")
	}
	if (manifest.Version != 1 && manifest.Version != 2) || manifest.ServerURL == "" || len(manifest.Files) == 0 || len(manifest.Nodes) == 0 {
		return manifestDocument{}, nil, errors.New("provisioning manifest is incomplete")
	}
	if manifest.Version == 2 {
		if manifest.PackageRole != PackageRoleServer && manifest.PackageRole != PackageRoleWorker && manifest.PackageRole != PackageRoleUpdater {
			return manifestDocument{}, nil, errors.New("provisioning package role is invalid")
		}
		if manifest.PackageRole == PackageRoleServer {
			if manifest.NodeID != "" {
				return manifestDocument{}, nil, errors.New("server package contains a node ID")
			}
		} else if !nodeIDPattern.MatchString(manifest.NodeID) {
			return manifestDocument{}, nil, errors.New("node package contains an invalid node ID")
		}
	}
	return manifest, data, nil
}

func parseServerURL(value string) (netip.Addr, uint16, error) {
	u, err := url.Parse(value)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return netip.Addr{}, 0, errors.New("provisioning manifest server URL is invalid")
	}
	portText := u.Port()
	if portText == "" {
		return netip.Addr{}, 0, errors.New("provisioning manifest server URL has no port")
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return netip.Addr{}, 0, errors.New("provisioning manifest server URL port is invalid")
	}
	ip, err := netip.ParseAddr(u.Hostname())
	if err != nil || ip.Zone() != "" || ip.IsUnspecified() || ip.IsMulticast() {
		return netip.Addr{}, 0, errors.New("provisioning manifest server URL must use a numeric unicast IP")
	}
	return ip, uint16(port), nil
}

func validateManifestFiles(outputDir string, manifest manifestDocument) error {
	expected := make(map[string]struct{}, len(manifest.Files))
	for _, name := range manifest.Files {
		if name == "" || filepath.Base(name) != name || filepath.Clean(name) != name || strings.ContainsAny(name, "\\:\x00") {
			return errors.New("provisioning manifest contains an unsafe file name")
		}
		if _, ok := expected[name]; ok {
			return errors.New("provisioning manifest contains duplicate files")
		}
		expected[name] = struct{}{}
		if _, err := readRegular(filepath.Join(outputDir, name), name == "server-key.pem" || strings.HasSuffix(name, "-client-key.pem") || name == "node-tokens" || strings.HasSuffix(name, "-token")); err != nil {
			return fmt.Errorf("validate material %s: %w", name, err)
		}
	}
	entries, err := os.ReadDir(outputDir)
	if err != nil {
		return fmt.Errorf("list material directory: %w", err)
	}
	for _, entry := range entries {
		if _, ok := expected[entry.Name()]; !ok {
			return fmt.Errorf("material directory contains unlisted file %q", entry.Name())
		}
	}
	for _, required := range []string{"ca-cert.pem", "server-cert.pem", "server-key.pem", "node-tokens", "manifest.json"} {
		if _, ok := expected[required]; !ok {
			return fmt.Errorf("provisioning manifest omits required file %q", required)
		}
	}
	nodeIDs := make(map[string]struct{}, len(manifest.Nodes))
	for _, node := range manifest.Nodes {
		if len(node.ID) == 0 || !nodeIDPattern.MatchString(node.ID) || (node.Kind != "worker" && node.Kind != "updater") {
			return errors.New("provisioning manifest contains an invalid node")
		}
		if _, exists := nodeIDs[node.ID]; exists {
			return fmt.Errorf("provisioning manifest contains duplicate node %q", node.ID)
		}
		nodeIDs[node.ID] = struct{}{}
		for _, name := range []string{node.ID + "-token", node.ID + "-client-cert.pem", node.ID + "-client-key.pem"} {
			if _, ok := expected[name]; !ok {
				return fmt.Errorf("provisioning manifest omits node file %q", name)
			}
		}
		if filepath.Base(node.TokenFile) != node.ID+"-token" || filepath.Base(node.ClientCert) != node.ID+"-client-cert.pem" || filepath.Base(node.ClientKey) != node.ID+"-client-key.pem" {
			return fmt.Errorf("provisioning manifest contains invalid paths for node %q", node.ID)
		}
	}
	return nil
}

func verifyRolePackage(outputDir string, manifest manifestDocument, when time.Time) (VerifyResult, error) {
	if err := validateRolePackageFiles(outputDir, manifest); err != nil {
		return VerifyResult{}, err
	}
	serverIP, _, err := parseServerURL(manifest.ServerURL)
	if err != nil {
		return VerifyResult{}, err
	}
	ca, err := readCertificateFile(filepath.Join(outputDir, "ca-cert.pem"), "CA certificate")
	if err != nil {
		return VerifyResult{}, err
	}
	if !ca.IsCA || !ca.BasicConstraintsValid || ca.CheckSignature(ca.SignatureAlgorithm, ca.RawTBSCertificate, ca.Signature) != nil {
		return VerifyResult{}, errors.New("CA certificate is invalid")
	}
	if when.Before(ca.NotBefore) || !when.Before(ca.NotAfter) {
		return VerifyResult{}, errors.New("CA certificate is expired or not yet valid")
	}
	if manifest.PackageRole == PackageRoleServer {
		serverCert, err := readCertificateFile(filepath.Join(outputDir, "server-cert.pem"), "server certificate")
		if err != nil {
			return VerifyResult{}, err
		}
		if serverCert.Subject.CommonName != "scanner-platform-server" || len(serverCert.IPAddresses) != 1 || serverCert.IPAddresses[0].String() != serverIP.String() {
			return VerifyResult{}, errors.New("server certificate identity does not match the manifest")
		}
		if err := verifyLeafCertificate(serverCert, ca, x509.ExtKeyUsageServerAuth, when); err != nil {
			return VerifyResult{}, fmt.Errorf("verify server certificate: %w", err)
		}
		if err := verifyPrivateKeyPair(filepath.Join(outputDir, "server-key.pem"), serverCert, "server key"); err != nil {
			return VerifyResult{}, err
		}
		if err := validateNodeTokenRegistryEntries(outputDir, manifest); err != nil {
			return VerifyResult{}, err
		}
		ids := make([]string, 0, len(manifest.Nodes))
		for _, node := range manifest.Nodes {
			ids = append(ids, node.ID)
		}
		sort.Strings(ids)
		return VerifyResult{OutputDir: outputDir, Role: manifest.PackageRole, ServerURL: manifest.ServerURL, FileCount: len(manifest.Files), NodeIDs: ids, CACertificateNotAfter: ca.NotAfter.UTC(), ServerCertificateNotAfter: serverCert.NotAfter.UTC()}, nil
	}
	if len(manifest.Nodes) != 1 || manifest.Nodes[0].ID != manifest.NodeID || PackageRole(manifest.Nodes[0].Kind) != manifest.PackageRole {
		return VerifyResult{}, errors.New("node package manifest does not match its node")
	}
	node := manifest.Nodes[0]
	cert, err := readCertificateFile(filepath.Join(outputDir, node.ID+"-client-cert.pem"), node.ID+" client certificate")
	if err != nil {
		return VerifyResult{}, err
	}
	if cert.Subject.CommonName != node.ID || len(cert.IPAddresses) != 0 {
		return VerifyResult{}, fmt.Errorf("client certificate identity for %s is invalid", node.ID)
	}
	if err := verifyLeafCertificate(cert, ca, x509.ExtKeyUsageClientAuth, when); err != nil {
		return VerifyResult{}, fmt.Errorf("verify client certificate for %s: %w", node.ID, err)
	}
	if err := verifyPrivateKeyPair(filepath.Join(outputDir, node.ID+"-client-key.pem"), cert, node.ID+" client key"); err != nil {
		return VerifyResult{}, err
	}
	token, err := readOwnerOnly(filepath.Join(outputDir, node.ID+"-token"))
	if err != nil || !validProvisionToken(string(trimProvisionLineEnding(token))) {
		if err == nil {
			err = errors.New("token has invalid format")
		}
		return VerifyResult{}, fmt.Errorf("validate node token: %w", err)
	}
	return VerifyResult{OutputDir: outputDir, Role: manifest.PackageRole, NodeID: manifest.NodeID, ServerURL: manifest.ServerURL, FileCount: len(manifest.Files), NodeIDs: []string{node.ID}, CACertificateNotAfter: ca.NotAfter.UTC()}, nil
}

func validateRolePackageFiles(outputDir string, manifest manifestDocument) error {
	expected := make(map[string]struct{}, len(manifest.Files))
	for _, name := range manifest.Files {
		if name == "" || filepath.Base(name) != name || filepath.Clean(name) != name || strings.ContainsAny(name, "\\:\x00") {
			return errors.New("provisioning package contains an unsafe file name")
		}
		if _, ok := expected[name]; ok {
			return errors.New("provisioning package contains duplicate files")
		}
		expected[name] = struct{}{}
		secret := name == "server-key.pem" || name == "node-tokens" || strings.HasSuffix(name, "-client-key.pem") || strings.HasSuffix(name, "-token")
		if _, err := readRegular(filepath.Join(outputDir, name), secret); err != nil {
			return fmt.Errorf("validate package material %s: %w", name, err)
		}
	}
	entries, err := os.ReadDir(outputDir)
	if err != nil {
		return fmt.Errorf("list package directory: %w", err)
	}
	for _, entry := range entries {
		if _, ok := expected[entry.Name()]; !ok {
			return fmt.Errorf("package directory contains unlisted file %q", entry.Name())
		}
	}
	if _, ok := expected["ca-cert.pem"]; !ok {
		return errors.New("provisioning package omits CA certificate")
	}
	if _, ok := expected["manifest.json"]; !ok {
		return errors.New("provisioning package omits manifest")
	}
	required := map[string]struct{}{"ca-cert.pem": {}, "manifest.json": {}}
	if manifest.PackageRole == PackageRoleServer {
		for _, name := range []string{"node-tokens", "server-cert.pem", "server-key.pem"} {
			required[name] = struct{}{}
		}
	} else {
		nodeID := manifest.NodeID
		for _, name := range []string{nodeID + "-client-cert.pem", nodeID + "-client-key.pem", nodeID + "-token"} {
			required[name] = struct{}{}
		}
	}
	if len(expected) != len(required) {
		return errors.New("provisioning package contains files outside its role")
	}
	for name := range required {
		if _, ok := expected[name]; !ok {
			return fmt.Errorf("provisioning package omits required file %q", name)
		}
	}
	if manifest.PackageRole == PackageRoleServer {
		if len(manifest.Nodes) == 0 {
			return errors.New("server package has no node descriptors")
		}
		seen := make(map[string]struct{}, len(manifest.Nodes))
		for _, node := range manifest.Nodes {
			if !nodeIDPattern.MatchString(node.ID) || (node.Kind != "worker" && node.Kind != "updater") {
				return errors.New("server package contains an invalid node descriptor")
			}
			if _, exists := seen[node.ID]; exists {
				return fmt.Errorf("server package contains duplicate node %q", node.ID)
			}
			seen[node.ID] = struct{}{}
		}
	} else if len(manifest.Nodes) != 1 || manifest.Nodes[0].ID != manifest.NodeID || PackageRole(manifest.Nodes[0].Kind) != manifest.PackageRole {
		return errors.New("node package descriptor is invalid")
	}
	return nil
}

func readCertificateFile(path, description string) (*x509.Certificate, error) {
	data, err := readRegular(path, false)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", description, err)
	}
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, fmt.Errorf("%s PEM is invalid", description)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", description, err)
	}
	return cert, nil
}

func verifyLeafCertificate(cert, ca *x509.Certificate, usage x509.ExtKeyUsage, now time.Time) error {
	if cert.IsCA || !cert.BasicConstraintsValid {
		return errors.New("certificate is not a leaf certificate")
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	if _, err := cert.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{usage}, CurrentTime: now}); err != nil {
		return err
	}
	return nil
}

func verifyPrivateKeyPair(path string, cert *x509.Certificate, description string) error {
	data, err := readOwnerOnly(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", description, err)
	}
	key, err := parsePrivateKey(data)
	if err != nil {
		return fmt.Errorf("parse %s: %w", description, err)
	}
	if !publicKeysEqual(&key.PublicKey, cert.PublicKey) {
		return fmt.Errorf("%s does not match its certificate", description)
	}
	return nil
}

func validateNodeTokenRegistry(outputDir string, manifest manifestDocument) error {
	if err := validateNodeTokenRegistryEntries(outputDir, manifest); err != nil {
		return err
	}
	for _, node := range manifest.Nodes {
		fileToken, err := readOwnerOnly(filepath.Join(outputDir, node.ID+"-token"))
		if err != nil {
			return fmt.Errorf("read token for %s: %w", node.ID, err)
		}
		registryToken, err := readRegistryToken(outputDir, node.ID)
		if err != nil {
			return err
		}
		if value := strings.TrimSuffix(strings.TrimSuffix(string(fileToken), "\n"), "\r"); value != registryToken {
			return fmt.Errorf("token file for %s does not match the registry", node.ID)
		}
	}
	return nil
}

func validateNodeTokenRegistryEntries(outputDir string, manifest manifestDocument) error {
	data, err := readOwnerOnly(filepath.Join(outputDir, "node-tokens"))
	if err != nil {
		return fmt.Errorf("read node token registry: %w", err)
	}
	data = trimProvisionLineEnding(data)
	if len(data) == 0 {
		return errors.New("node token registry is empty")
	}
	expected := make(map[string]struct{}, len(manifest.Nodes))
	for _, node := range manifest.Nodes {
		expected[node.ID] = struct{}{}
	}
	seen := make(map[string]string, len(expected))
	for lineNo, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSuffix(raw, "\r")
		if line == "" {
			continue
		}
		id, token, ok := strings.Cut(line, "=")
		if !ok || !nodeIDPattern.MatchString(id) || !validProvisionToken(token) {
			return fmt.Errorf("node token registry entry on line %d is invalid", lineNo+1)
		}
		if _, ok := expected[id]; !ok {
			return fmt.Errorf("node token registry contains unlisted node %q", id)
		}
		if _, ok := seen[id]; ok {
			return fmt.Errorf("node token registry contains duplicate node %q", id)
		}
		seen[id] = token
	}
	if len(seen) != len(expected) {
		return errors.New("node token registry does not match the manifest nodes")
	}
	return nil
}

func readRegistryToken(outputDir, nodeID string) (string, error) {
	data, err := readOwnerOnly(filepath.Join(outputDir, "node-tokens"))
	if err != nil {
		return "", fmt.Errorf("read node token registry: %w", err)
	}
	data = trimProvisionLineEnding(data)
	for lineNo, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSuffix(raw, "\r")
		if line == "" {
			continue
		}
		id, token, ok := strings.Cut(line, "=")
		if !ok || id != nodeID || !validProvisionToken(token) {
			if id == nodeID {
				return "", fmt.Errorf("node token registry entry on line %d is invalid", lineNo+1)
			}
			continue
		}
		return token, nil
	}
	return "", fmt.Errorf("node token registry has no entry for %s", nodeID)
}

func validProvisionToken(token string) bool {
	if len(token) < minTokenBytes || len(token) > 512 {
		return false
	}
	for _, b := range []byte(token) {
		if b < 0x21 || b > 0x7e {
			return false
		}
	}
	return true
}

func trimProvisionLineEnding(data []byte) []byte {
	if len(data) > 0 && data[len(data)-1] == '\n' {
		data = data[:len(data)-1]
		if len(data) > 0 && data[len(data)-1] == '\r' {
			data = data[:len(data)-1]
		}
	}
	return data
}

func stageRotatedDirectory(outputDir string, manifest manifestDocument, originalManifest []byte, ca certificateAuthority, serverIP netip.Addr, serverPort uint16, lifetime time.Duration, when time.Time) error {
	parent := filepath.Dir(outputDir)
	stage, err := os.MkdirTemp(parent, ".scanner-node-rotation-")
	if err != nil {
		return fmt.Errorf("create rotation staging directory: %w", err)
	}
	if err := os.Chmod(stage, 0700); err != nil {
		_ = os.RemoveAll(stage)
		return fmt.Errorf("protect rotation staging directory: %w", err)
	}
	defer os.RemoveAll(stage)
	for _, name := range manifest.Files {
		if name == "manifest.json" || name == "server-cert.pem" || name == "server-key.pem" || strings.HasSuffix(name, "-client-cert.pem") || strings.HasSuffix(name, "-client-key.pem") {
			continue
		}
		data, err := readRegular(filepath.Join(outputDir, name), name == "node-tokens" || strings.HasSuffix(name, "-token"))
		if err != nil {
			return fmt.Errorf("copy existing material %s: %w", name, err)
		}
		mode := os.FileMode(0644)
		if name == "node-tokens" || strings.HasSuffix(name, "-token") {
			mode = 0600
		}
		if err := writeFile(filepath.Join(stage, name), data, mode); err != nil {
			return err
		}
	}
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate rotated server key: %w", err)
	}
	serverCert, err := issueCertificate(ca, serverKey, "scanner-platform-server", when, lifetime, true, false, serverIP)
	if err != nil {
		return fmt.Errorf("issue rotated server certificate: %w", err)
	}
	serverKeyPEM, err := marshalPrivateKey(serverKey)
	if err != nil {
		return fmt.Errorf("marshal rotated server key: %w", err)
	}
	if err := writeFile(filepath.Join(stage, "server-key.pem"), serverKeyPEM, 0600); err != nil {
		return err
	}
	if err := writeFile(filepath.Join(stage, "server-cert.pem"), pemBytes("CERTIFICATE", serverCert.Raw), 0644); err != nil {
		return err
	}
	for _, node := range manifest.Nodes {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return fmt.Errorf("generate rotated %s key: %w", node.ID, err)
		}
		cert, err := issueCertificate(ca, key, node.ID, when, lifetime, false, true, serverIP)
		if err != nil {
			return fmt.Errorf("issue rotated %s certificate: %w", node.ID, err)
		}
		keyPEM, err := marshalPrivateKey(key)
		if err != nil {
			return fmt.Errorf("marshal rotated %s key: %w", node.ID, err)
		}
		if err := writeFile(filepath.Join(stage, node.ID+"-client-key.pem"), keyPEM, 0600); err != nil {
			return err
		}
		if err := writeFile(filepath.Join(stage, node.ID+"-client-cert.pem"), pemBytes("CERTIFICATE", cert.Raw), 0644); err != nil {
			return err
		}
	}
	if err := writeFile(filepath.Join(stage, "manifest.json"), originalManifest, 0644); err != nil {
		return err
	}
	backup, err := os.MkdirTemp(parent, ".scanner-node-previous-")
	if err != nil {
		return fmt.Errorf("create rotation backup path: %w", err)
	}
	if err := os.Remove(backup); err != nil {
		return fmt.Errorf("prepare rotation backup path: %w", err)
	}
	if err := os.Rename(outputDir, backup); err != nil {
		return fmt.Errorf("stage current node materials: %w", err)
	}
	if err := os.Rename(stage, outputDir); err != nil {
		_ = os.Rename(backup, outputDir)
		return fmt.Errorf("publish rotated node materials: %w", err)
	}
	if err := os.RemoveAll(backup); err != nil {
		return fmt.Errorf("remove previous node materials: %w", err)
	}
	return nil
}

func validateOptions(opts Options) error {
	if strings.TrimSpace(opts.OutputDir) == "" || strings.TrimSpace(opts.CADir) == "" {
		return errors.New("output and CA directories are required")
	}
	if !opts.ServerIP.IsValid() || opts.ServerIP.Zone() != "" || opts.ServerIP.IsUnspecified() || opts.ServerIP.IsMulticast() {
		return errors.New("server IP must be a specific numeric unicast address")
	}
	if opts.ServerPort == 0 {
		opts.ServerPort = defaultServerPort
	}
	if opts.ValidFor <= 0 || opts.ValidFor > 397*24*time.Hour {
		return errors.New("certificate lifetime must be between 1 hour and 397 days")
	}
	if opts.CAValidFor <= 0 || opts.CAValidFor > 10*365*24*time.Hour {
		return errors.New("CA lifetime must be between 1 hour and 10 years")
	}
	if len(opts.Nodes) == 0 || len(opts.Nodes) > 128 {
		return errors.New("at least one and at most 128 nodes are required")
	}
	seen := make(map[string]struct{}, len(opts.Nodes))
	for _, node := range opts.Nodes {
		if len(node.ID) == 0 || len(node.ID) > maxNodeIDLength || !nodeIDPattern.MatchString(node.ID) {
			return fmt.Errorf("invalid node id %q", node.ID)
		}
		if node.Kind != "worker" && node.Kind != "updater" {
			return fmt.Errorf("invalid node kind for %s", node.ID)
		}
		if _, ok := seen[node.ID]; ok {
			return fmt.Errorf("duplicate node id %q", node.ID)
		}
		seen[node.ID] = struct{}{}
	}
	return nil
}

func rejectNestedPaths(output, ca string) error {
	output, _ = filepath.Abs(output)
	ca, _ = filepath.Abs(ca)
	if output == ca {
		return errors.New("output and CA directories must be different")
	}
	if isPathInside(output, ca) || isPathInside(ca, output) {
		return errors.New("output and CA directories must not contain each other")
	}
	return nil
}

func isPathInside(path, parent string) bool {
	rel, err := filepath.Rel(parent, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func ensureParent(path string) error {
	parent := filepath.Dir(path)
	if err := os.MkdirAll(parent, 0755); err != nil {
		return fmt.Errorf("create parent directory: %w", err)
	}
	return nil
}

func ensureDirAbsent(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect output directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return errors.New("output directory must not be a symlink")
	}
	return errors.New("output directory already exists; refusing to overwrite")
}

func loadOrCreateCA(dir string, generate bool, now time.Time, lifetime time.Duration) (certificateAuthority, error) {
	certPath := filepath.Join(dir, "ca-cert.pem")
	keyPath := filepath.Join(dir, "ca-key.pem")
	if generate {
		if err := ensureParent(dir); err != nil {
			return certificateAuthority{}, err
		}
		if err := ensureDirAbsent(dir); err != nil {
			return certificateAuthority{}, err
		}
		if err := os.Mkdir(dir, 0700); err != nil {
			return certificateAuthority{}, fmt.Errorf("create CA directory: %w", err)
		}
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return certificateAuthority{}, fmt.Errorf("generate CA key: %w", err)
		}
		cert, err := issueCACertificate(key, "scanner-platform-node-ca", now, lifetime)
		if err != nil {
			return certificateAuthority{}, fmt.Errorf("issue CA certificate: %w", err)
		}
		keyPEM, err := marshalPrivateKey(key)
		if err != nil {
			return certificateAuthority{}, fmt.Errorf("marshal CA key: %w", err)
		}
		if err := writeFile(keyPath, keyPEM, 0600); err != nil {
			return certificateAuthority{}, err
		}
		if err := writeFile(certPath, pemBytes("CERTIFICATE", cert.Raw), 0644); err != nil {
			return certificateAuthority{}, err
		}
		return certificateAuthority{key: key, cert: cert}, nil
	}
	keyData, err := readOwnerOnly(keyPath)
	if err != nil {
		return certificateAuthority{}, fmt.Errorf("read CA key: %w", err)
	}
	certData, err := readRegular(certPath, false)
	if err != nil {
		return certificateAuthority{}, fmt.Errorf("read CA certificate: %w", err)
	}
	key, err := parsePrivateKey(keyData)
	if err != nil {
		return certificateAuthority{}, fmt.Errorf("parse CA key: %w", err)
	}
	certBlock, _ := pem.Decode(certData)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		return certificateAuthority{}, errors.New("CA certificate PEM is invalid")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil || !cert.IsCA || cert.BasicConstraintsValid == false {
		return certificateAuthority{}, errors.New("CA certificate is not a valid CA")
	}
	if now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) {
		return certificateAuthority{}, errors.New("CA certificate is expired or not yet valid")
	}
	if err := cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature); err != nil {
		return certificateAuthority{}, errors.New("CA certificate signature is invalid")
	}
	if !publicKeysEqual(&key.PublicKey, cert.PublicKey) {
		return certificateAuthority{}, errors.New("CA key does not match CA certificate")
	}
	return certificateAuthority{key: key, cert: cert}, nil
}

func issueCertificate(ca certificateAuthority, key *ecdsa.PrivateKey, commonName string, now time.Time, lifetime time.Duration, server, client bool, serverIP netip.Addr) (*x509.Certificate, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(lifetime),
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
	}
	if server {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		template.IPAddresses = []net.IP{net.ParseIP(serverIP.String())}
	} else if client {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	if ca.key == nil {
		template.IsCA = true
		template.KeyUsage |= x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	}
	signer := ca.key
	parent := ca.cert
	if parent == nil {
		parent = template
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, signer)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

func issueCACertificate(key *ecdsa.PrivateKey, commonName string, now time.Time, lifetime time.Duration) (*x509.Certificate, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(lifetime),
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

func newToken() (string, error) {
	data := make([]byte, minTokenBytes)
	if _, err := rand.Read(data); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}

func marshalPrivateKey(key *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pemBytes("PRIVATE KEY", der), nil
}

func parsePrivateKey(data []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, errors.New("private key PEM is invalid")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	ecdsaKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("private key is not ECDSA")
	}
	return ecdsaKey, nil
}

func publicKeysEqual(left, right any) bool {
	l, err := x509.MarshalPKIXPublicKey(left)
	if err != nil {
		return false
	}
	r, err := x509.MarshalPKIXPublicKey(right)
	return err == nil && string(l) == string(r)
}

func pemBytes(kind string, data []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: data})
}

func readOwnerOnly(path string) ([]byte, error) {
	return readRegular(path, true)
}

func readRegular(path string, ownerOnly bool) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, errors.New("file must be a regular non-symlink file")
	}
	if ownerOnly && info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("file must be owner-only")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func writeFile(path string, data []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return fmt.Errorf("create %s: %w", filepath.Base(path), err)
	}
	if err := file.Chmod(mode); err == nil {
		var written int
		written, err = file.Write(data)
		if err == nil && written != len(data) {
			err = errors.New("short write")
		}
	}
	if err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		_ = os.Remove(path)
		return fmt.Errorf("write %s: %w", filepath.Base(path), err)
	}
	return nil
}

// Defaults exposes the CLI defaults without exposing mutable package state.
func Defaults() (certLife, caLife time.Duration) {
	return defaultCertLife, defaultCALife
}

// FileDigest is useful to deployment tooling when it wants to record a
// non-secret checksum. It intentionally accepts only regular files.
func FileDigest(path string) (string, error) {
	data, err := readRegular(path, false)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return fmt.Sprintf("%x", sum[:]), nil
}
