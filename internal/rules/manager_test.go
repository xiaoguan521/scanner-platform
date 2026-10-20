package rules

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func packageZIP(t *testing.T, key ed25519.PrivateKey, version, name string, badHash bool) []byte {
	t.Helper()
	body := []byte("local integrity test fixture\n")
	hash := hashBytes(body)
	if badHash {
		hash = hashBytes([]byte("other"))
	}
	manifest := Manifest{Version: version, Engines: []string{"nuclei"}, Files: map[string]string{name: hash}}
	data, _ := json.Marshal(manifest)
	var out bytes.Buffer
	writer := zip.NewWriter(&out)
	for name, data := range map[string][]byte{manifestName: data, signatureName: ed25519.Sign(key, data), name: body} {
		file, err := writer.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := file.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}
func TestImportHashFailureTraversalAndExplicitRollback(t *testing.T) {
	ctx := context.Background()
	manager, key := verifiedFixture(t)
	for _, version := range []string{"20261016.01", "20261016.02"} {
		if _, err := manager.Import(ctx, packageZIP(t, key, version, "nuclei/templates/example.yaml", false)); err != nil {
			t.Fatal(err)
		}
	}
	if err := manager.Activate(ctx, "20261016.02", false); err != nil {
		t.Fatal(err)
	}
	if err := manager.Activate(ctx, "20261016.01", false); err == nil {
		t.Fatal("implicit rollback accepted")
	}
	if _, err := manager.Import(ctx, packageZIP(t, key, "20261016.03", "nuclei/templates/example.yaml", true)); err == nil {
		t.Fatal("bad hash accepted")
	}
	if _, err := manager.Import(ctx, packageZIP(t, key, "20261016.03", "../escaped.yaml", false)); err == nil {
		t.Fatal("traversal accepted")
	}
	current, err := os.ReadFile(filepath.Join(manager.Root, "CURRENT"))
	if err != nil || string(current) != "20261016.02\n" {
		t.Fatalf("failed import changed CURRENT %s %v", current, err)
	}
	if err := manager.Activate(ctx, "20261016.01", true); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(manager.Root, "releases", "20261016.02", "nuclei", "templates", "example.yaml"), []byte("tampered"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := manager.Activate(ctx, "20261016.02", false); err == nil {
		t.Fatal("tampered installed bundle activated")
	}
}
func TestHTTPSUpdateAndArchiveChecksum(t *testing.T) {
	manager, key := verifiedFixture(t)
	data := packageZIP(t, key, "20261016.01", "nuclei/templates/example.yaml", false)
	source := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(data) }))
	defer source.Close()
	manager.Client = source.Client()
	if _, err := manager.Fetch(context.Background(), source.URL, hashBytes(data)); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Fetch(context.Background(), source.URL, hashBytes([]byte("wrong"))); err == nil {
		t.Fatal("wrong archive hash accepted")
	}
	if _, err := manager.Fetch(context.Background(), "http://rules.example.com/package.zip", hashBytes(data)); err == nil {
		t.Fatal("HTTP source accepted")
	}
	if _, err := manager.Fetch(context.Background(), "https://rules.example.com/package.zip?token=example", hashBytes(data)); err == nil {
		t.Fatal("credential-bearing source accepted")
	}
}
