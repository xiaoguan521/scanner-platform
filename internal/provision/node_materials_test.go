package provision

import (
	"crypto/x509"
	"encoding/pem"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
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
	verified, err := Verify(VerifyOptions{OutputDir: outDir, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if verified.FileCount != 11 || len(verified.NodeIDs) != 2 || verified.ServerURL != result.ServerURL {
		t.Fatalf("unexpected verification result: %#v", verified)
	}
}

func TestVerifyRejectsTamperedTransferredMaterial(t *testing.T) {
	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	newFixture := func(t *testing.T) string {
		t.Helper()
		outDir := filepath.Join(t.TempDir(), "node-materials")
		_, err := Provision(Options{
			OutputDir: outDir, CADir: filepath.Join(filepath.Dir(outDir), "ca"), ServerIP: netip.MustParseAddr("192.0.2.10"),
			Nodes: []NodeSpec{{ID: "worker-a", Kind: "worker"}}, ValidFor: 24 * time.Hour, CAValidFor: 48 * time.Hour,
			GenerateCA: true, Now: func() time.Time { return now },
		})
		if err != nil {
			t.Fatal(err)
		}
		return outDir
	}

	t.Run("extra file", func(t *testing.T) {
		outDir := newFixture(t)
		if err := os.WriteFile(filepath.Join(outDir, "unexpected.txt"), []byte("x"), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := Verify(VerifyOptions{OutputDir: outDir, Now: func() time.Time { return now }}); err == nil {
			t.Fatal("Verify accepted an unlisted file")
		}
	})
	t.Run("mismatched key", func(t *testing.T) {
		outDir := newFixture(t)
		clientKey, err := os.ReadFile(filepath.Join(outDir, "worker-a-client-key.pem"))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(outDir, "server-key.pem"), clientKey, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := Verify(VerifyOptions{OutputDir: outDir, Now: func() time.Time { return now }}); err == nil {
			t.Fatal("Verify accepted a mismatched private key")
		}
	})
	t.Run("mismatched token", func(t *testing.T) {
		outDir := newFixture(t)
		if err := os.WriteFile(filepath.Join(outDir, "worker-a-token"), []byte("wrong-token\n"), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := Verify(VerifyOptions{OutputDir: outDir, Now: func() time.Time { return now }}); err == nil {
			t.Fatal("Verify accepted a mismatched token")
		}
	})
	t.Run("insecure directory", func(t *testing.T) {
		outDir := newFixture(t)
		if err := os.Chmod(outDir, 0750); err != nil {
			t.Fatal(err)
		}
		if _, err := Verify(VerifyOptions{OutputDir: outDir, Now: func() time.Time { return now }}); err == nil {
			t.Fatal("Verify accepted a group-accessible directory")
		}
	})
}

func TestPackageCreatesLeastPrivilegeRoleBundles(t *testing.T) {
	root := t.TempDir()
	when := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	source := filepath.Join(root, "complete")
	_, err := Provision(Options{
		OutputDir: source,
		CADir:     filepath.Join(root, "ca"),
		ServerIP:  netip.MustParseAddr("192.0.2.10"),
		Nodes: []NodeSpec{
			{ID: "worker-a", Kind: "worker"},
			{ID: "updater-a", Kind: "updater"},
		},
		ValidFor:   24 * time.Hour,
		CAValidFor: 48 * time.Hour,
		GenerateCA: true,
		Now:        func() time.Time { return when },
	})
	if err != nil {
		t.Fatal(err)
	}
	serverDir := filepath.Join(root, "server")
	_, err = Package(PackageOptions{SourceDir: source, OutputDir: serverDir, Role: PackageRoleServer, Now: func() time.Time { return when }})
	if err != nil {
		t.Fatalf("server package: %v", err)
	}
	if _, err := Verify(VerifyOptions{OutputDir: serverDir, Now: func() time.Time { return when }}); err != nil {
		t.Fatalf("verify server package: %v", err)
	}
	assertPackageFiles(t, serverDir, []string{"ca-cert.pem", "manifest.json", "node-tokens", "server-cert.pem", "server-key.pem"})
	for _, forbidden := range []string{"worker-a-token", "worker-a-client-key.pem", "updater-a-token", "updater-a-client-key.pem"} {
		if _, err := os.Stat(filepath.Join(serverDir, forbidden)); !os.IsNotExist(err) {
			t.Fatalf("server package contains %s: %v", forbidden, err)
		}
	}
	workerDir := filepath.Join(root, "worker")
	worker, err := Package(PackageOptions{SourceDir: source, OutputDir: workerDir, Role: PackageRoleWorker, NodeID: "worker-a", Now: func() time.Time { return when }})
	if err != nil {
		t.Fatalf("worker package: %v", err)
	}
	if _, err := Verify(VerifyOptions{OutputDir: workerDir, Now: func() time.Time { return when }}); err != nil {
		t.Fatalf("verify worker package: %v", err)
	}
	if worker.NodeID != "worker-a" || worker.Role != PackageRoleWorker {
		t.Fatalf("unexpected worker package metadata: %#v", worker)
	}
	assertPackageFiles(t, workerDir, []string{"ca-cert.pem", "manifest.json", "worker-a-client-cert.pem", "worker-a-client-key.pem", "worker-a-token"})
	for _, forbidden := range []string{"server-key.pem", "node-tokens", "updater-a-token", "updater-a-client-key.pem"} {
		if _, err := os.Stat(filepath.Join(workerDir, forbidden)); !os.IsNotExist(err) {
			t.Fatalf("worker package contains %s: %v", forbidden, err)
		}
	}
	token, err := os.ReadFile(filepath.Join(source, "worker-a-token"))
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := os.ReadFile(filepath.Join(workerDir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(manifest), strings.TrimSpace(string(token))) {
		t.Fatal("role package manifest leaked the node token")
	}
	if _, err := Package(PackageOptions{SourceDir: source, OutputDir: filepath.Join(root, "bad"), Role: PackageRoleWorker, NodeID: "updater-a", Now: func() time.Time { return when }}); err == nil {
		t.Fatal("worker package accepted an updater node")
	}
}

func assertPackageFiles(t *testing.T, dir string, want []string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	got := make([]string, 0, len(entries))
	for _, entry := range entries {
		got = append(got, entry.Name())
	}
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("package files = %v, want %v", got, want)
	}
}

func FuzzValidProvisionToken(f *testing.F) {
	f.Add("a-token-with-printable-characters-01234567890123456789")
	f.Add("short")
	f.Fuzz(func(t *testing.T, token string) {
		_ = validProvisionToken(token)
	})
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

func TestRotateReplacesCertificatesPreservesTokensAndManifest(t *testing.T) {
	root := t.TempDir()
	caDir := filepath.Join(root, "ca")
	outDir := filepath.Join(root, "node-materials")
	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	first, err := Provision(Options{
		OutputDir: outDir, CADir: caDir, ServerIP: netip.MustParseAddr("192.0.2.10"), ServerPort: 8443,
		Nodes:    []NodeSpec{{ID: "worker-a", Kind: "worker"}, {ID: "updater-a", Kind: "updater"}},
		ValidFor: 24 * time.Hour, CAValidFor: 48 * time.Hour, GenerateCA: true, Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	oldServer, err := FileDigest(first.ServerCert)
	if err != nil {
		t.Fatal(err)
	}
	oldClient, err := FileDigest(first.Nodes[0].ClientCert)
	if err != nil {
		t.Fatal(err)
	}
	oldRegistry, err := os.ReadFile(first.NodeTokenRegistry)
	if err != nil {
		t.Fatal(err)
	}
	oldManifest, err := os.ReadFile(first.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	rotated, err := Rotate(RotateOptions{OutputDir: outDir, CADir: caDir, ValidFor: 12 * time.Hour, Now: func() time.Time { return now.Add(time.Hour) }})
	if err != nil {
		t.Fatal(err)
	}
	if rotated.ServerURL != first.ServerURL || len(rotated.Nodes) != len(first.Nodes) {
		t.Fatalf("rotation metadata changed: %#v", rotated)
	}
	newServer, err := FileDigest(rotated.ServerCert)
	if err != nil {
		t.Fatal(err)
	}
	newClient, err := FileDigest(rotated.Nodes[0].ClientCert)
	if err != nil {
		t.Fatal(err)
	}
	if newServer == oldServer || newClient == oldClient {
		t.Fatal("rotation did not replace certificate material")
	}
	newRegistry, err := os.ReadFile(rotated.NodeTokenRegistry)
	if err != nil {
		t.Fatal(err)
	}
	if string(newRegistry) != string(oldRegistry) {
		t.Fatal("rotation changed node bearer tokens")
	}
	newManifest, err := os.ReadFile(rotated.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	if string(newManifest) != string(oldManifest) {
		t.Fatal("rotation changed deployment manifest")
	}
	ca := parseCertificateFile(t, rotated.CACert)
	verifyCertificate(t, parseCertificateFile(t, rotated.ServerCert), ca, x509.ExtKeyUsageServerAuth)
	for _, node := range rotated.Nodes {
		verifyCertificate(t, parseCertificateFile(t, node.ClientCert), ca, x509.ExtKeyUsageClientAuth)
		if mode := fileMode(t, node.ClientKey); mode.Perm() != 0600 {
			t.Fatalf("rotated client key mode = %o", mode.Perm())
		}
	}
}

func TestRotateRejectsManifestBeforeChangingMaterial(t *testing.T) {
	root := t.TempDir()
	caDir := filepath.Join(root, "ca")
	outDir := filepath.Join(root, "node-materials")
	result, err := Provision(Options{
		OutputDir: outDir, CADir: caDir, ServerIP: netip.MustParseAddr("198.51.100.20"),
		Nodes: []NodeSpec{{ID: "worker-a", Kind: "worker"}}, ValidFor: 24 * time.Hour, CAValidFor: 48 * time.Hour,
		GenerateCA: true, Now: func() time.Time { return time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatal(err)
	}
	old, err := FileDigest(result.ServerCert)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outDir, "unexpected.txt"), []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Rotate(RotateOptions{OutputDir: outDir, CADir: caDir}); err == nil {
		t.Fatal("rotation accepted an unlisted file")
	}
	if got, err := FileDigest(result.ServerCert); err != nil || got != old {
		t.Fatalf("failed rotation changed certificate: got=%q old=%q err=%v", got, old, err)
	}
}

func TestRotateRejectsMismatchedOutputCA(t *testing.T) {
	root := t.TempDir()
	caDir := filepath.Join(root, "ca")
	outDir := filepath.Join(root, "node-materials")
	result, err := Provision(Options{
		OutputDir: outDir, CADir: caDir, ServerIP: netip.MustParseAddr("203.0.113.10"),
		Nodes: []NodeSpec{{ID: "worker-a", Kind: "worker"}}, ValidFor: 24 * time.Hour, CAValidFor: 48 * time.Hour,
		GenerateCA: true, Now: func() time.Time { return time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatal(err)
	}
	otherRoot := t.TempDir()
	other, err := Provision(Options{
		OutputDir: filepath.Join(otherRoot, "node-materials"), CADir: filepath.Join(otherRoot, "ca"),
		ServerIP: netip.MustParseAddr("203.0.113.11"), Nodes: []NodeSpec{{ID: "worker-b", Kind: "worker"}},
		ValidFor: 24 * time.Hour, CAValidFor: 48 * time.Hour, GenerateCA: true,
		Now: func() time.Time { return time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatal(err)
	}
	caData, err := os.ReadFile(other.CACert)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(result.CACert, caData, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := Rotate(RotateOptions{OutputDir: outDir, CADir: caDir}); err == nil {
		t.Fatal("rotation accepted an output CA that does not match the CA directory")
	}
}

func TestProvisionRejectsUnsafeScopeAndPaths(t *testing.T) {
	root := t.TempDir()
	defaults, caLife := Defaults()
	cases := []Options{
		{OutputDir: filepath.Join(root, "out"), CADir: filepath.Join(root, "ca"), ServerIP: netip.MustParseAddr("0.0.0.0"), Nodes: []NodeSpec{{ID: "worker-a", Kind: "worker"}}, ValidFor: defaults, CAValidFor: caLife, GenerateCA: true},
		{OutputDir: filepath.Join(root, "out"), CADir: filepath.Join(root, "ca"), ServerIP: netip.MustParseAddr("192.0.2.10"), Nodes: []NodeSpec{{ID: "worker/a", Kind: "worker"}}, ValidFor: defaults, CAValidFor: caLife, GenerateCA: true},
		{OutputDir: filepath.Join(root, "ca", "out"), CADir: filepath.Join(root, "ca"), ServerIP: netip.MustParseAddr("192.0.2.10"), Nodes: []NodeSpec{{ID: "worker-a", Kind: "worker"}}, ValidFor: defaults, CAValidFor: caLife, GenerateCA: true},
		{OutputDir: filepath.Join(root, "out-lifetime"), CADir: filepath.Join(root, "ca-lifetime"), ServerIP: netip.MustParseAddr("192.0.2.10"), Nodes: []NodeSpec{{ID: "worker-a", Kind: "worker"}}, ValidFor: 48 * time.Hour, CAValidFor: 24 * time.Hour, GenerateCA: true},
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
