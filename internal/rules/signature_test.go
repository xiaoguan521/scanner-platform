package rules

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func signingKeyFixture(t *testing.T) (string, ed25519.PrivateKey) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "trusted.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	return path, private
}

func verifiedFixture(t *testing.T) (*Manager, ed25519.PrivateKey) {
	t.Helper()
	path, key := signingKeyFixture(t)
	m, err := NewVerifiedManager(t.TempDir(), path)
	if err != nil {
		t.Fatal(err)
	}
	return m, key
}

func zipFiles(t *testing.T, data []byte) map[string][]byte {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	files := make(map[string][]byte)
	for _, f := range zr.File {
		r, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		files[f.Name], err = io.ReadAll(r)
		_ = r.Close()
		if err != nil {
			t.Fatal(err)
		}
	}
	return files
}

func zipFixture(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var out bytes.Buffer
	w := zip.NewWriter(&out)
	for name, data := range files {
		f, err := w.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func TestPublicKeyTrustFileParsing(t *testing.T) {
	validPath, private := signingKeyFixture(t)
	valid, err := os.ReadFile(validPath)
	if err != nil {
		t.Fatal(err)
	}
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecDER, _ := x509.MarshalPKIXPublicKey(&ec.PublicKey)
	privateDER, _ := x509.MarshalPKCS8PrivateKey(private)
	for _, tc := range []struct {
		name string
		data []byte
	}{
		{"empty", nil}, {"garbage", []byte("not a key")},
		{"prefix", append([]byte("untrusted prefix\n"), valid...)},
		{"suffix", append(append([]byte(nil), valid...), []byte("untrusted suffix")...)},
		{"multiple", append(append([]byte(nil), valid...), valid...)},
		{"malformed preceding block", append([]byte("-----BEGIN PUBLIC KEY-----\nbroken\n-----END PUBLIC KEY-----\n"), valid...)},
		{"oversized", bytes.Repeat([]byte(" "), 4097)},
		{"wrong algorithm", pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: ecDER})},
		{"private", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})},
		{"bad DER", pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte("bad")})},
		{"headers", pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Headers: map[string]string{"Test": "header"}, Bytes: []byte("bad")})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "key.pem")
			if err := os.WriteFile(path, tc.data, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := NewVerifiedManager(t.TempDir(), path); err == nil {
				t.Fatal("invalid trust file accepted")
			}
		})
	}
	for _, kind := range []string{"missing", "directory", "symlink", "inside root", "inside root via parent alias"} {
		t.Run(kind, func(t *testing.T) {
			root, path := t.TempDir(), validPath
			switch kind {
			case "missing":
				path = filepath.Join(t.TempDir(), "missing.pem")
			case "directory":
				path = t.TempDir()
			case "symlink":
				path = filepath.Join(t.TempDir(), "link.pem")
				if err := os.Symlink(validPath, path); err != nil {
					t.Skipf("symlinks unavailable: %v", err)
				}
			case "inside root", "inside root via parent alias":
				path = filepath.Join(root, "key.pem")
				if err := os.WriteFile(path, valid, 0600); err != nil {
					t.Fatal(err)
				}
				if kind == "inside root via parent alias" {
					alias := filepath.Join(t.TempDir(), "alias")
					if err := os.Symlink(root, alias); err != nil {
						t.Skipf("symlinks unavailable: %v", err)
					}
					path = filepath.Join(alias, "key.pem")
				}
			}
			if _, err := NewVerifiedManager(root, path); err == nil {
				t.Fatal("unsafe trust path accepted")
			}
		})
	}
	root := filepath.Join(t.TempDir(), "not-created", "rules")
	m, err := NewVerifiedManager(root, validPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatal("loading key created rule directories")
	}
	// Loading takes a private copy; changing the file is not implicit rotation.
	if err := os.WriteFile(validPath, []byte("replaced"), 0600); err != nil {
		t.Fatal(err)
	}
	if b, err := m.Import(context.Background(), packageZIP(t, private, "20261016.01", "nuclei/test.json", false)); err != nil || !b.SignatureVerified {
		t.Fatalf("loaded key changed: %#v %v", b, err)
	}
}

func TestMultipleTrustedKeysSupportRotationOverlap(t *testing.T) {
	oldPath, oldPrivate := signingKeyFixture(t)
	newPath, newPrivate := signingKeyFixture(t)
	root := t.TempDir()
	m, err := NewVerifiedManagerWithKeys(root, []string{oldPath, newPath})
	if err != nil {
		t.Fatal(err)
	}
	if bundle, err := m.Import(context.Background(), packageZIP(t, oldPrivate, "20261016.01", "nuclei/old.json", false)); err != nil || !bundle.SignatureVerified {
		t.Fatalf("retiring key package rejected: %#v %v", bundle, err)
	}
	if bundle, err := m.Import(context.Background(), packageZIP(t, newPrivate, "20261016.02", "nuclei/new.json", false)); err != nil || !bundle.SignatureVerified {
		t.Fatalf("replacement key package rejected: %#v %v", bundle, err)
	}
	if _, err := NewVerifiedManagerWithKeys(t.TempDir(), []string{oldPath, oldPath}); err == nil {
		t.Fatal("duplicate trusted key accepted")
	}
	tooMany := make([]string, 0, maxTrustedKeys+1)
	for range maxTrustedKeys + 1 {
		path, _ := signingKeyFixture(t)
		tooMany = append(tooMany, path)
	}
	if _, err := NewVerifiedManagerWithKeys(t.TempDir(), tooMany); err == nil {
		t.Fatal("more than the bounded trust set accepted")
	}
}

func TestImportRequiresRawSignatureBeforeManifestOrExtraction(t *testing.T) {
	for _, kind := range []string{"missing key", "missing signature", "wrong key", "whitespace", "short", "long", "base64", "hex", "invalid manifest", "extra file"} {
		t.Run(kind, func(t *testing.T) {
			m, key := verifiedFixture(t)
			files := zipFiles(t, packageZIP(t, key, "20261016.01", "nuclei/test.json", false))
			switch kind {
			case "missing key":
				m = &Manager{Root: m.Root}
			case "missing signature":
				delete(files, signatureName)
			case "wrong key":
				_, other := signingKeyFixture(t)
				files[signatureName] = ed25519.Sign(other, files[manifestName])
			case "whitespace":
				files[manifestName] = append(files[manifestName], '\n')
			case "short":
				files[signatureName] = files[signatureName][:63]
			case "long":
				files[signatureName] = append(files[signatureName], 0)
			case "base64":
				files[signatureName] = []byte(base64.StdEncoding.EncodeToString(files[signatureName]))
			case "hex":
				files[signatureName] = []byte(hex.EncodeToString(files[signatureName]))
			case "invalid manifest":
				files[manifestName] = []byte("not JSON")
			case "extra file":
				files["extra"] = []byte("extra")
			}
			_, err := m.Import(context.Background(), zipFixture(t, files))
			if err == nil {
				t.Fatal("untrusted import succeeded")
			}
			if kind == "invalid manifest" && !strings.Contains(err.Error(), "签名") {
				t.Fatalf("decoded before signature check: %v", err)
			}
			stages, _ := filepath.Glob(filepath.Join(m.Root, ".import-*"))
			if len(stages) != 0 {
				t.Fatal("failed signature extracted payload")
			}
			if _, err := os.Stat(filepath.Join(m.Root, "releases", "20261016.01")); !os.IsNotExist(err) {
				t.Fatal("untrusted release published")
			}
		})
	}
}

func TestPublicKeyCannotUseCaseAliasOfRuleRoot(t *testing.T) {
	path, _ := signingKeyFixture(t)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	parent := t.TempDir()
	root := filepath.Join(parent, "Rules")
	alias := filepath.Join(parent, "rules")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	rootInfo, err := os.Stat(root)
	if err != nil {
		t.Fatal(err)
	}
	aliasInfo, err := os.Stat(alias)
	if os.IsNotExist(err) || err == nil && !os.SameFile(rootInfo, aliasInfo) {
		t.Skip("filesystem distinguishes case")
	}
	if err != nil {
		t.Fatal(err)
	}
	inside := filepath.Join(root, "key.pem")
	if err := os.WriteFile(inside, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewVerifiedManager(alias, inside); err == nil {
		t.Fatal("case alias allowed an internal trust file")
	}
}

func TestActivateRechecksSignatureBeforePayloadHash(t *testing.T) {
	for _, kind := range []string{"missing key", "missing signature", "wrong signature", "manifest whitespace", "manifest symlink", "signature symlink"} {
		t.Run(kind, func(t *testing.T) {
			m, key := verifiedFixture(t)
			ctx := context.Background()
			for _, version := range []string{"20261016.01", "20261016.02"} {
				if _, err := m.Import(ctx, packageZIP(t, key, version, "nuclei/test.json", false)); err != nil {
					t.Fatal(err)
				}
			}
			if err := m.Activate(ctx, "20261016.01", false); err != nil {
				t.Fatal(err)
			}
			dir := filepath.Join(m.Root, "releases", "20261016.02")
			switch kind {
			case "missing key":
				m = &Manager{Root: m.Root}
			case "missing signature":
				if err := os.Remove(filepath.Join(dir, signatureName)); err != nil {
					t.Fatal(err)
				}
			case "wrong signature":
				if err := os.WriteFile(filepath.Join(dir, signatureName), make([]byte, 64), 0600); err != nil {
					t.Fatal(err)
				}
			case "manifest whitespace":
				data, err := os.ReadFile(filepath.Join(dir, manifestName))
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, manifestName), append(data, '\n'), 0600); err != nil {
					t.Fatal(err)
				}
			case "manifest symlink", "signature symlink":
				name := manifestName
				if kind == "signature symlink" {
					name = signatureName
				}
				path := filepath.Join(dir, name)
				if err := os.Rename(path, path+".real"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(path+".real", path); err != nil {
					t.Skipf("symlinks unavailable: %v", err)
				}
			}
			if err := os.Remove(filepath.Join(dir, "nuclei", "test.json")); err != nil {
				t.Fatal(err)
			}
			err := m.Activate(ctx, "20261016.02", false)
			if err == nil || strings.Contains(err.Error(), "规则路径缺失") {
				t.Fatalf("failed signature reached payload or activated: %v", err)
			}
			current, err := os.ReadFile(filepath.Join(m.Root, "CURRENT"))
			if err != nil || string(current) != "20261016.01\n" {
				t.Fatalf("failed activation changed CURRENT: %q %v", current, err)
			}
		})
	}
}

func TestSignedImportCannotUpgradeExistingUnsignedVersion(t *testing.T) {
	m, key := verifiedFixture(t)
	local := Manager{Root: m.Root}
	if _, err := local.PrepareDefault(context.Background(), "20261016.01", "", false); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(m.Root, "releases", "20261016.01")
	manifest, err := os.ReadFile(filepath.Join(dir, manifestName))
	if err != nil {
		t.Fatal(err)
	}
	files := BaselineTemplates()
	files[manifestName] = manifest
	files[signatureName] = ed25519.Sign(key, manifest)
	if _, err := m.Import(context.Background(), zipFixture(t, files)); err == nil {
		t.Fatal("signed import replaced existing unsigned version")
	}
	if _, err := os.Lstat(filepath.Join(dir, signatureName)); !os.IsNotExist(err) {
		t.Fatal("unsigned release acquired signature")
	}
	b, err := m.Inspect(context.Background(), "20261016.01")
	if err != nil || !b.IntegrityVerified || b.SignatureVerified {
		t.Fatalf("historical unsigned inspection: %#v %v", b, err)
	}
}

func TestInspectionReportsOnlyPerformedSignatureVerification(t *testing.T) {
	m, key := verifiedFixture(t)
	archive := packageZIP(t, key, "20261016.01", "nuclei/test.json", false)
	for range 2 {
		b, err := m.Import(context.Background(), archive)
		if err != nil || !b.SignatureVerified {
			t.Fatalf("signed idempotent import: %#v %v", b, err)
		}
	}
	reader := Manager{Root: m.Root}
	b, err := reader.Inspect(context.Background(), "20261016.01")
	if err != nil || !b.IntegrityVerified || b.SignatureVerified {
		t.Fatalf("reader claimed signature verification: %#v %v", b, err)
	}
	if _, err := reader.List(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(m.Root, "releases", b.Version, signatureName), make([]byte, 64), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Inspect(context.Background(), b.Version); err == nil {
		t.Fatal("trusted inspection accepted bad signature")
	}
	if _, err := m.List(context.Background()); err == nil {
		t.Fatal("trusted catalog accepted bad signature")
	}
}

func TestFetchCannotBypassMissingTrust(t *testing.T) {
	m, key := verifiedFixture(t)
	data := packageZIP(t, key, "20261016.01", "nuclei/test.json", false)
	calls := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; _, _ = w.Write(data) }))
	defer server.Close()
	reader := Manager{Root: m.Root, Client: server.Client()}
	if _, err := reader.Fetch(context.Background(), server.URL, hashBytes(data)); err == nil || calls != 0 {
		t.Fatalf("missing trust fetched package: calls %d, %v", calls, err)
	}
}

func TestPreparedLocalCapabilityIsOneUseAndInstanceBound(t *testing.T) {
	for _, kind := range []string{"instance", "root", "manifest", "payload", "repeat", "repeat prepare", "rollback", "canceled", "ordinary", "signed import"} {
		t.Run(kind, func(t *testing.T) {
			m, key := verifiedFixture(t)
			ctx := context.Background()
			version := "20261016.02"
			if _, err := m.PrepareDefault(ctx, version, "", false); err != nil {
				t.Fatal(err)
			}
			originalRoot := m.Root
			dir := filepath.Join(m.Root, "releases", version)
			switch kind {
			case "instance":
				m = &Manager{Root: originalRoot}
			case "root":
				m.Root = t.TempDir()
			case "manifest":
				data, err := os.ReadFile(filepath.Join(dir, manifestName))
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, manifestName), append(data, '\n'), 0600); err != nil {
					t.Fatal(err)
				}
			case "payload":
				if err := os.WriteFile(filepath.Join(dir, "nuclei", "templates", "baseline-csp.json"), []byte("tampered"), 0600); err != nil {
					t.Fatal(err)
				}
			case "repeat":
				if err := m.ActivatePreparedLocal(ctx, version); err != nil {
					t.Fatal(err)
				}
			case "repeat prepare":
				if _, err := m.PrepareDefault(ctx, version, "", false); err == nil {
					t.Fatal("repreparing an existing unsigned version succeeded")
				}
			case "rollback":
				if _, err := m.PrepareDefault(ctx, "20261016.03", "", false); err != nil {
					t.Fatal(err)
				}
				if err := m.ActivatePreparedLocal(ctx, "20261016.03"); err != nil {
					t.Fatal(err)
				}
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "ordinary":
				if err := m.Activate(ctx, version, false); err == nil {
					t.Fatal("ordinary activation accepted local unsigned bundle")
				}
				return
			case "signed import":
				version = "20261016.03"
				if _, err := m.Import(ctx, packageZIP(t, key, version, "nuclei/test.json", false)); err != nil {
					t.Fatal(err)
				}
			}
			if err := m.ActivatePreparedLocal(ctx, version); err == nil {
				t.Fatal("invalid local capability activated")
			}
			m.Root = originalRoot
			if err := m.ActivatePreparedLocal(context.Background(), version); err == nil {
				t.Fatal("failed attempt did not consume local capability")
			}
		})
	}
}

func TestPreparedDigestCannotBeReplacedByConsistentTamperedFiles(t *testing.T) {
	m := Manager{Root: t.TempDir()}
	b, err := m.PrepareDefault(context.Background(), "20261016.01", "", false)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(m.Root, "releases", b.Version)
	data, err := os.ReadFile(filepath.Join(dir, manifestName))
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := decodeManifest(data)
	if err != nil {
		t.Fatal(err)
	}
	for name := range manifest.Files {
		body := []byte("replacement with matching hash")
		if err := os.WriteFile(filepath.Join(dir, filepath.FromSlash(name)), body, 0600); err != nil {
			t.Fatal(err)
		}
		manifest.Files[name] = hashBytes(body)
		break
	}
	data, _ = json.Marshal(manifest)
	if err := os.WriteFile(filepath.Join(dir, manifestName), data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := m.ActivatePreparedLocal(context.Background(), b.Version); err == nil {
		t.Fatal("consistent content replacement bypassed remembered digest")
	}
}
