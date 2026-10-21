package provision

import (
	"crypto/x509"
	"encoding/pem"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestProvisionGeneratesVerifiableMaterialWithoutSecretsInManifest(t *testing.T) {
	root := t.TempDir()
	caDir := filepath.Join(root, "ca")
	outDir := filepath.Join(root, "node-materials")
	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	result, err := Provision(Options{
		OutputDir:  outDir,
		CADir:      caDir,
		ServerIP:   netip.MustParseAddr("192.0.2.10"),
		ServerPort: 8443,
		Nodes: []NodeSpec{
			{ID: "worker-a", Kind: "worker"},
			{ID: "updater-a", Kind: "updater"},
		},
		ValidFor:   24 * time.Hour,
		CAValidFor: 48 * time.Hour,
		GenerateCA: true,
		Now:        func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("Provision() error = %v", err)
	}
	if result.ServerURL != "https://192.0.2.10:8443" {
		t.Fatalf("server URL = %q", result.ServerURL)
	}
	for _, path := range []string{result.CACert, result.ServerCert, result.ServerKey, result.NodeTokenRegistry, result.Manifest} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("missing generated file %q: %v", path, err)
		}
	}
	if mode := fileMode(t, filepath.Join(caDir, "ca-key.pem")); mode.Perm() != 0600 {
		t.Fatalf("CA key mode = %o", mode.Perm())
	}
	if mode := fileMode(t, result.ServerKey); mode.Perm() != 0600 {
		t.Fatalf("server key mode = %o", mode.Perm())
	}
	if mode := fileMode(t, result.NodeTokenRegistry); mode.Perm() != 0600 {
		t.Fatalf("registry mode = %o", mode.Perm())
	}

	ca := parseCertificateFile(t, result.CACert)
	if !ca.IsCA {
		t.Fatal("generated CA is not marked as a CA")
	}
	server := parseCertificateFile(t, result.ServerCert)
	if len(server.IPAddresses) != 1 || server.IPAddresses[0].String() != "192.0.2.10" {
		t.Fatalf("server certificate IP SANs = %v", server.IPAddresses)
	}
	verifyCertificate(t, server, ca, x509.ExtKeyUsageServerAuth)

	registry, err := os.ReadFile(result.NodeTokenRegistry)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := os.ReadFile(result.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	for _, node := range result.Nodes {
		cert := parseCertificateFile(t, node.ClientCert)
		verifyCertificate(t, cert, ca, x509.ExtKeyUsageClientAuth)
		token, err := os.ReadFile(node.TokenFile)
		if err != nil {
			t.Fatal(err)
		}
		value := strings.TrimSpace(string(token))
		if len(value) < 43 || !strings.Contains(string(registry), node.ID+"="+value) {
			t.Fatalf("token for %s is not represented in the registry", node.ID)
		}
		if strings.Contains(string(manifest), value) {
			t.Fatalf("manifest leaked token for %s", node.ID)
		}
	}
	if _, err := os.Stat(filepath.Join(outDir, "ca-key.pem")); !os.IsNotExist(err) {
		t.Fatalf("CA private key was copied into output: err=%v", err)
	}
	if _, err := FileDigest(result.ServerCert); err != nil {
		t.Fatalf("FileDigest() error = %v", err)
	}
}

func TestProvisionReusesCAAndRefusesOverwrite(t *testing.T) {
	root := t.TempDir()
	caDir := filepath.Join(root, "ca")
	base := Options{
		OutputDir:  filepath.Join(root, "first"),
		CADir:      caDir,
		ServerIP:   netip.MustParseAddr("198.51.100.20"),
		Nodes:      []NodeSpec{{ID: "worker-a", Kind: "worker"}},
		ValidFor:   24 * time.Hour,
		CAValidFor: 48 * time.Hour,
		GenerateCA: true,
		Now:        func() time.Time { return time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC) },
	}
	first, err := Provision(base)
	if err != nil {
		t.Fatal(err)
	}
	caDigest, err := FileDigest(first.CACert)
	if err != nil {
		t.Fatal(err)
	}
	base.OutputDir = filepath.Join(root, "second")
	base.GenerateCA = false
	second, err := Provision(base)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := FileDigest(second.CACert); err != nil || got != caDigest {
		t.Fatalf("reused CA digest = %q, err=%v; want %q", got, err, caDigest)
	}
	if _, err := Provision(base); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("overwrite was accepted: %v", err)
	}
}

func TestProvisionRejectsUnsafeScopeAndPaths(t *testing.T) {
	root := t.TempDir()
	defaults, caLife := Defaults()
	cases := []Options{
		{OutputDir: filepath.Join(root, "out"), CADir: filepath.Join(root, "ca"), ServerIP: netip.MustParseAddr("0.0.0.0"), Nodes: []NodeSpec{{ID: "worker-a", Kind: "worker"}}, ValidFor: defaults, CAValidFor: caLife, GenerateCA: true},
		{OutputDir: filepath.Join(root, "out"), CADir: filepath.Join(root, "ca"), ServerIP: netip.MustParseAddr("192.0.2.10"), Nodes: []NodeSpec{{ID: "worker/a", Kind: "worker"}}, ValidFor: defaults, CAValidFor: caLife, GenerateCA: true},
		{OutputDir: filepath.Join(root, "ca", "out"), CADir: filepath.Join(root, "ca"), ServerIP: netip.MustParseAddr("192.0.2.10"), Nodes: []NodeSpec{{ID: "worker-a", Kind: "worker"}}, ValidFor: defaults, CAValidFor: caLife, GenerateCA: true},
	}
	for i, in := range cases {
		if _, err := Provision(in); err == nil {
			t.Fatalf("case %d was accepted", i)
		}
	}
}

func parseCertificateFile(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatalf("no PEM certificate in %s", path)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse certificate %s: %v", path, err)
	}
	return cert
}

func verifyCertificate(t *testing.T, cert, ca *x509.Certificate, usage x509.ExtKeyUsage) {
	t.Helper()
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	if _, err := cert.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{usage}, CurrentTime: cert.NotBefore.Add(time.Minute)}); err != nil {
		t.Fatalf("certificate verification failed: %v", err)
	}
}

func fileMode(t *testing.T, path string) os.FileMode {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info.Mode()
}
