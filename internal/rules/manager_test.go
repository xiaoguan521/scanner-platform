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
	manifest := Manifest{Version: version, Engines: []string{"nuclei"}, EngineCompatibility: PinnedEngineCompatibility([]string{"nuclei"}, false), Files: map[string]string{name: hash}}
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

func TestActivationRejectsLegacyManifestWithoutCompatibility(t *testing.T) {
	manager, key := verifiedFixture(t)
	files := zipFiles(t, packageZIP(t, key, "20261022.02", "nuclei/templates/example.yaml", false))
	var manifest Manifest
	if err := json.Unmarshal(files[manifestName], &manifest); err != nil {
		t.Fatal(err)
	}
	manifest.EngineCompatibility = nil
	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	files[manifestName] = data
	files[signatureName] = ed25519.Sign(key, data)
	bundle, err := manager.Import(context.Background(), zipFixture(t, files))
	if err != nil || bundle.EngineValidated {
		t.Fatalf("legacy manifest should remain unvalidated: %#v %v", bundle, err)
	}
	if err := manager.Activate(context.Background(), bundle.Version, false); err == nil {
		t.Fatal("legacy manifest activated without compatibility")
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
	if leftovers, err := filepath.Glob(filepath.Join(manager.Root, ".fetch-*.zip")); err != nil || len(leftovers) != 0 {
		t.Fatalf("fetch temporary file not cleaned: %v %v", leftovers, err)
	}
	if _, err := manager.Fetch(context.Background(), "http://rules.example.com/package.zip", hashBytes(data)); err == nil {
		t.Fatal("HTTP source accepted")
	}
	if _, err := manager.Fetch(context.Background(), "https://rules.example.com/package.zip?token=example", hashBytes(data)); err == nil {
		t.Fatal("credential-bearing source accepted")
	}
}

func TestLargeSignedArchiveFilePath(t *testing.T) {
	manager, key := verifiedFixture(t)
	archive := packageZIP(t, key, "20261016.04", "nuclei/templates/example.yaml", false)
	archivePath := filepath.Join(t.TempDir(), "signed-rules.zip")
	if err := os.WriteFile(archivePath, archive, 0600); err != nil {
		t.Fatal(err)
	}
	bundle, err := manager.ImportFile(context.Background(), archivePath)
	if err != nil || !bundle.SignatureVerified {
		t.Fatalf("large signed file import: %#v %v", bundle, err)
	}
	if err := manager.Activate(context.Background(), bundle.Version, false); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.ImportFile(context.Background(), filepath.Join(filepath.Dir(archivePath), "missing.zip")); err == nil {
		t.Fatal("missing archive accepted")
	}
	files := map[string][]byte{"vuln-data/CURRENT": []byte("20261016.05\n"), "README-漏洞库.md": []byte("fixture")}
	for name, body := range zipFiles(t, packageZIP(t, key, "20261016.05", "nuclei/templates/example.yaml", false)) {
		files[filepath.ToSlash(filepath.Join("vuln-data", "releases", "20261016.05", name))] = body
	}
	artifactPath := filepath.Join(filepath.Dir(archivePath), "actions-artifact.zip")
	if err := os.WriteFile(artifactPath, zipFixture(t, files), 0600); err != nil {
		t.Fatal(err)
	}
	artifact, err := manager.ImportFile(context.Background(), artifactPath)
	if err != nil || artifact.Version != "20261016.05" || !artifact.SignatureVerified {
		t.Fatalf("Actions artifact import: %#v %v", artifact, err)
	}
}

func TestLargeSignedArchiveFileRejectsOversizedAndSymlink(t *testing.T) {
	manager, key := verifiedFixture(t)
	directory := t.TempDir()
	oversized := filepath.Join(directory, "oversized.zip")
	file, err := os.OpenFile(oversized, os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(MaxSignedArchive + 1); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.ImportFile(context.Background(), oversized); err == nil {
		t.Fatal("oversized archive accepted")
	}
	archive := packageZIP(t, key, "20261016.05", "nuclei/templates/example.yaml", false)
	realPath := filepath.Join(directory, "real.zip")
	if err := os.WriteFile(realPath, archive, 0600); err != nil {
		t.Fatal(err)
	}
	linkPath := filepath.Join(directory, "link.zip")
	if err := os.Symlink(realPath, linkPath); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := manager.ImportFile(context.Background(), linkPath); err == nil {
		t.Fatal("symlink archive accepted")
	}
}
