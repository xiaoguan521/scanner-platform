// Package provision creates the file material required by an explicitly
// configured Server/Worker/Updater node deployment. It never contacts a
// network and never prints bearer tokens or private keys.
package provision

import (
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
	"math/big"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
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
	manifest, err := json.MarshalIndent(struct {
		Version   int          `json:"version"`
		ServerURL string       `json:"serverUrl"`
		Files     []string     `json:"files"`
		Nodes     []NodeResult `json:"nodes"`
	}{1, result.ServerURL, files, result.Nodes}, "", "  ")
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
