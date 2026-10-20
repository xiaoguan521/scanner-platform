package rules

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// Interop uses only disposable signing inputs and standard signing tools. It
// starts no platform service, scanner, listener or network client.
func TestPackageScriptEd25519InteropAndPrivateKeyExclusion(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 unavailable")
	}
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl unavailable")
	}
	publicPath, private := signingKeyFixture(t)
	privateDER, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})
	privatePath := filepath.Join(t.TempDir(), "test-private.pem")
	if err := os.WriteFile(privatePath, privatePEM, 0600); err != nil {
		t.Fatal(err)
	}
	engineDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(engineDir, "example.json"), []byte("local package fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	script, err := filepath.Abs(filepath.Join("..", "..", "scripts", "package_rules.py"))
	if err != nil {
		t.Fatal(err)
	}
	run := func(key, output string) ([]byte, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		command := exec.CommandContext(ctx, python, script, "--version", "20261016.01", "--nuclei-dir", engineDir,
			"--signing-private-key", key, "--output", output)
		command.Env = append(os.Environ(), "PYTHONDONTWRITEBYTECODE=1")
		return command.CombinedOutput()
	}
	archivePath := filepath.Join(t.TempDir(), "signed.zip")
	if output, err := run(privatePath, archivePath); err != nil {
		t.Fatalf("package fixture failed: %v: %s", err, output)
	}
	archive, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	files := zipFiles(t, archive)
	if len(files[signatureName]) != ed25519.SignatureSize || !ed25519.Verify(private.Public().(ed25519.PublicKey), files[manifestName], files[signatureName]) {
		t.Fatal("Python/OpenSSL did not produce a raw64 signature over manifest bytes")
	}
	m, err := NewVerifiedManager(t.TempDir(), publicPath)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := m.Import(context.Background(), archive)
	if err != nil || !bundle.SignatureVerified {
		t.Fatalf("Python/OpenSSL to Go import: %#v %v", bundle, err)
	}
	if err := m.Activate(context.Background(), bundle.Version, false); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"inside", "hardlink"} {
		t.Run(kind, func(t *testing.T) {
			inside := filepath.Join(engineDir, "private.pem")
			key := privatePath
			if kind == "inside" {
				if err := os.WriteFile(inside, privatePEM, 0600); err != nil {
					t.Fatal(err)
				}
				key = inside
			} else if err := os.Link(privatePath, inside); err != nil {
				t.Skipf("hardlinks unavailable: %v", err)
			}
			defer func() { _ = os.Remove(inside) }()
			outputPath := filepath.Join(t.TempDir(), "must-not-exist.zip")
			if _, err := run(key, outputPath); err == nil {
				t.Fatal("packaged signing private key")
			}
			if _, err := os.Lstat(outputPath); !os.IsNotExist(err) {
				t.Fatal("private key rejection left an archive")
			}
		})
	}
}
