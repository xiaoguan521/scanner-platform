package bootstrap

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestValidateNodeListenRequiresSpecificNumericAddress(t *testing.T) {
	for _, test := range []struct {
		name string
		addr string
		good bool
	}{
		{name: "ipv4", addr: "127.0.0.1:8443", good: true},
		{name: "ipv6", addr: "[::1]:8443", good: true},
		{name: "hostname", addr: "node.example.test:8443"},
		{name: "missing port", addr: "127.0.0.1"},
		{name: "zero port", addr: "127.0.0.1:0"},
		{name: "unspecified", addr: "0.0.0.0:8443"},
		{name: "multicast", addr: "224.0.0.1:8443"},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := validateNodeListen(test.addr)
			if test.good && err != nil {
				t.Fatalf("validateNodeListen(%q) = %v", test.addr, err)
			}
			if !test.good && err == nil {
				t.Fatalf("validateNodeListen(%q) unexpectedly succeeded", test.addr)
			}
		})
	}
}

func TestLoadNodeTLSConfigRequiresOwnerOnlyPrivateKey(t *testing.T) {
	dir := t.TempDir()
	certPEM, keyPEM := tlsFixturePEM(t)
	certPath := filepath.Join(dir, "node.crt")
	keyPath := filepath.Join(dir, "node.key")
	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		t.Fatal(err)
	}
	config, err := loadNodeTLSConfig(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if config.MinVersion != 0x0304 { // tls.VersionTLS13 without importing crypto/tls in the assertion.
		t.Fatalf("minimum TLS version = %d, want TLS 1.3", config.MinVersion)
	}

	if err := os.Chmod(keyPath, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadNodeTLSConfig(certPath, keyPath); err == nil || !strings.Contains(err.Error(), "owner-only") {
		t.Fatalf("insecure key error = %v, want owner-only rejection", err)
	}

	linkPath := filepath.Join(dir, "node-link.key")
	if err := os.Symlink(keyPath, linkPath); err != nil {
		t.Fatal(err)
	}
	if _, err := loadNodeTLSConfig(certPath, linkPath); err == nil || !strings.Contains(err.Error(), "non-symlink") {
		t.Fatalf("symlink key error = %v, want symlink rejection", err)
	}
}

func TestLoadNodeTLSConfigWithClientCARequiresVerifiedCertificates(t *testing.T) {
	dir := t.TempDir()
	certPEM, keyPEM := tlsFixturePEM(t)
	certPath := filepath.Join(dir, "node.crt")
	keyPath := filepath.Join(dir, "node.key")
	caPath := filepath.Join(dir, "client-ca.pem")
	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(caPath, certPEM, 0644); err != nil {
		t.Fatal(err)
	}
	config, err := loadNodeTLSConfigWithClientCA(certPath, keyPath, caPath)
	if err != nil {
		t.Fatal(err)
	}
	if config.ClientAuth != tls.RequireAndVerifyClientCert || config.ClientCAs == nil {
		t.Fatalf("client auth = %v, client CAs nil=%v", config.ClientAuth, config.ClientCAs == nil)
	}
	badCA := filepath.Join(dir, "bad-ca.pem")
	if err := os.WriteFile(badCA, []byte("not a certificate"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadNodeTLSConfigWithClientCA(certPath, keyPath, badCA); err == nil || !strings.Contains(err.Error(), "no certificate") {
		t.Fatalf("invalid client CA error = %v", err)
	}
}

func TestNodeTLSReloaderKeepsLastKnownGoodConfig(t *testing.T) {
	dir := t.TempDir()
	certPEM, keyPEM := tlsFixturePEM(t)
	certPath := filepath.Join(dir, "node.crt")
	keyPath := filepath.Join(dir, "node.key")
	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		t.Fatal(err)
	}
	reloader, err := newNodeTLSReloader(certPath, keyPath, "")
	if err != nil {
		t.Fatal(err)
	}
	outer := reloader.TLSConfig()
	if outer.GetConfigForClient == nil {
		t.Fatal("reloader did not install config callback")
	}
	if _, err := outer.GetConfigForClient(&tls.ClientHelloInfo{}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, []byte("invalid"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := reloader.Reload(); err == nil {
		t.Fatal("invalid replacement certificate was accepted")
	}
	if _, err := outer.GetConfigForClient(&tls.ClientHelloInfo{}); err != nil {
		t.Fatalf("last known-good config was lost: %v", err)
	}
}

func TestLoadNodeClientTLSConfigRequiresCompletePair(t *testing.T) {
	if _, err := loadNodeClientTLSConfig("", "client.crt", ""); err == nil || !strings.Contains(err.Error(), "provided together") {
		t.Fatalf("incomplete client pair error = %v", err)
	}
	if _, err := loadNodeClientTLSConfig("", "", ""); err != nil {
		t.Fatalf("empty optional client TLS config: %v", err)
	}
}

func tlsFixturePEM(t *testing.T) ([]byte, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "node-fixture"},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(time.Hour),
		DNSNames:     []string{"node-fixture"},
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM
}
