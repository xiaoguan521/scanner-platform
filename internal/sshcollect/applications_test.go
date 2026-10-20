package sshcollect

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestApplicationConfigurationIsExplicitAndBounded(t *testing.T) {
	valid := Application{Alias: "demo", Directory: "/opt/demo", IncludeJava: true}
	if err := validateApplications([]Application{valid}); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{"/", "/opt", "/usr/local", "/var/lib", "relative", "/opt/demo/../other", "/opt/./demo", "/opt/demo/", "/opt//demo", "/proc/demo", "/tmp/app", "/mnt/app", "/opt/a\napp", "/opt/a\u0085app", strings.Repeat("a", 513)} {
		app := valid
		app.Directory = dir
		if validateApplications([]Application{app}) == nil {
			t.Errorf("accepted %q", dir)
		}
	}
	for _, apps := range [][]Application{{{Alias: "bad/name", Directory: "/opt/demo", IncludeJava: true}}, {{Alias: "demo", Directory: "/opt/demo"}}, {valid, valid}, make([]Application, 9)} {
		if validateApplications(apps) == nil {
			t.Fatal("accepted invalid app list")
		}
	}
	token, err := applicationToken([]Application{valid})
	if err != nil {
		t.Fatal(err)
	}
	data, err := base64.RawURLEncoding.DecodeString(token[1:])
	if err != nil || !strings.Contains(string(data), "/opt/demo") {
		t.Fatal("token does not round trip")
	}
}

func applicationEntries(t *testing.T, target string, app Application) []tarEntry {
	t.Helper()
	var buffer bytes.Buffer
	zipWriter := zip.NewWriter(&buffer)
	content, err := zipWriter.Create("META-INF/MANIFEST.MF")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = content.Write([]byte("Manifest-Version: 1.0\n"))
	if err := zipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	payload := buffer.Bytes()
	digest := sha256.Sum256(payload)
	snapshot, _ := json.Marshal(map[string]any{"schemaVersion": 1, "source": applicationSource(target, app), "kind": "artifact", "collectedAt": "2026-10-20T00:00:00Z", "files": map[string]string{"artifact.jar": hex.EncodeToString(digest[:])}})
	return []tarEntry{{name: "apps/" + app.Alias + "/0000/artifact.jar", mode: tar.TypeReg, data: payload}, {name: "apps/" + app.Alias + "/0000/.scanner-input.json", mode: tar.TypeReg, data: snapshot}}
}

func TestApplicationSSHChecksScopeBeforeConnectingAndEncodesDirectories(t *testing.T) {
	app := Application{Alias: "demo", Directory: "/opt/demo;$(ignored)", IncludeJava: true}
	c := &Collector{knownHosts: "fixture", profiles: map[string]Profile{"192.0.2.10": {IP: "192.0.2.10", SSHPort: 2222, User: "scanner", Auth: "agent", Apps: []Application{app}}}}
	calls := 0
	c.runApplications = func(_ context.Context, args []string, out, stderr io.Writer) error {
		calls++
		for _, arg := range args {
			if strings.Contains(arg, app.Directory) {
				t.Fatal("raw remote directory entered SSH argv")
			}
		}
		if args[len(args)-1][:16] != "--ssh-apps-b64=x" {
			t.Fatal("missing encoded payload")
		}
		root := t.TempDir()
		archive := filepath.Join(root, "apps.tar.gz")
		writeArchive(t, archive, applicationEntries(t, "192.0.2.10", app))
		file, err := os.Open(archive)
		if err != nil {
			return err
		}
		defer file.Close()
		_, err = io.Copy(out, file)
		return err
	}
	root := t.TempDir()
	runtime := filepath.Join(root, "runtime")
	inputsDir := filepath.Join(root, "inputs")
	for _, tc := range []struct {
		selected, open []int
		status         string
		fail           bool
	}{{[]int{80}, []int{2222}, "port_out_of_scope", false}, {[]int{2222}, nil, "collection_failed", true}} {
		_, cleanup, status, err := c.CollectApplications(context.Background(), "192.0.2.10", tc.selected, tc.open, runtime, inputsDir)
		cleanup()
		if status != tc.status || (err != nil) != tc.fail {
			t.Fatalf("status=%q err=%v", status, err)
		}
	}
	if calls != 0 {
		t.Fatal("scope failure started SSH")
	}
	inputs, cleanup, status, err := c.CollectApplications(context.Background(), "192.0.2.10", []int{2222}, []int{2222}, runtime, inputsDir)
	if err != nil || status != "collected" || len(inputs) != 1 {
		t.Fatalf("inputs=%+v status=%q err=%v", inputs, status, err)
	}
	artifactDir := filepath.Join(inputsDir, filepath.FromSlash(inputs[0].InputPath))
	cleanup()
	if _, err := os.Stat(artifactDir); !os.IsNotExist(err) {
		t.Fatal("cleanup kept application input")
	}
}

func TestApplicationArchiveRejectsUnconfiguredAdditionalAndUnverifiedInputs(t *testing.T) {
	app := Application{Alias: "demo", Directory: "/opt/demo", IncludeJava: true}
	cases := map[string]func([]tarEntry) []tarEntry{
		"traversal": func(e []tarEntry) []tarEntry {
			return append(e, tarEntry{name: "apps/demo/../other", mode: tar.TypeReg})
		},
		"unknown-alias": func(e []tarEntry) []tarEntry { e[0].name = "apps/other/0000/artifact.jar"; return e },
		"symlink":       func(e []tarEntry) []tarEntry { e[0].mode = tar.TypeSymlink; e[0].link = "/etc/example"; return e },
		"hardlink": func(e []tarEntry) []tarEntry {
			e[0].mode = tar.TypeLink
			e[0].link = "apps/demo/0000/.scanner-input.json"
			return e
		},
		"duplicate": func(e []tarEntry) []tarEntry { return append(e, e[0]) },
		"extra-file": func(e []tarEntry) []tarEntry {
			return append(e, tarEntry{name: "apps/demo/0000/config.yaml", mode: tar.TypeReg})
		},
		"no-manifest": func(e []tarEntry) []tarEntry { return e[:1] },
		"wrong-hash":  func(e []tarEntry) []tarEntry { e[0].data = []byte("changed"); return e },
		"sequence-gap": func(e []tarEntry) []tarEntry {
			for i := range e {
				e[i].name = strings.ReplaceAll(e[i].name, "0000", "0001")
			}
			return e
		},
		"unsupported-elf": func(e []tarEntry) []tarEntry { e[0].name = "apps/demo/0000/artifact.elf"; return e },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			archive := filepath.Join(root, "apps.tar.gz")
			writeArchive(t, archive, mutate(applicationEntries(t, "192.0.2.10", app)))
			destination := filepath.Join(root, "out")
			if err := os.Mkdir(destination, 0700); err != nil {
				t.Fatal(err)
			}
			if _, err := extractApplications(archive, destination, "192.0.2.10", []Application{app}); err == nil {
				t.Fatal("accepted malicious application archive")
			}
		})
	}
}

func FuzzApplicationDirectoryValidation(f *testing.F) {
	for _, seed := range []string{"/opt/demo", "/", "/opt/../etc", "/mnt/demo", "/srv/service"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, value string) {
		if len(value) > 8192 {
			return
		}
		if validApplicationDirectory(value) {
			token, err := applicationToken([]Application{{Alias: "demo", Directory: value, IncludeJava: true}})
			if err != nil {
				t.Fatal(err)
			}
			if strings.ContainsAny(token, " ;\n\r$()`\\") {
				t.Fatal("unsafe token characters")
			}
		}
	})
}

func TestApplicationJavaExpandedBudgetAndMalformedArchive(t *testing.T) {
	root := t.TempDir()
	entries := applicationEntries(t, "192.0.2.10", Application{Alias: "demo", Directory: "/opt/demo", IncludeJava: true})
	filename := filepath.Join(root, "artifact.jar")
	if err := os.WriteFile(filename, entries[0].data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := validateJavaArchive(filename, &javaBudget{bytes: maxApplicationTotal - 1}); err == nil {
		t.Fatal("accepted expanded archive over budget")
	}
	if err := validateJavaArchive(filename, &javaBudget{entries: 4096}); err == nil {
		t.Fatal("accepted too many archive entries")
	}
	if err := os.WriteFile(filename, []byte("not a Java ZIP archive"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := validateJavaArchive(filename, &javaBudget{}); err == nil {
		t.Fatal("accepted malformed Java artifact")
	}
}

func TestApplicationArchiveRejectsNativeELFWithoutGoBuildInfo(t *testing.T) {
	app := Application{Alias: "demo", Directory: "/opt/demo", IncludeGo: true}
	payload := []byte("\x7fELFsynthetic native binary")
	digest := sha256.Sum256(payload)
	manifest, _ := json.Marshal(map[string]any{"schemaVersion": 1, "source": applicationSource("192.0.2.10", app), "kind": "artifact", "collectedAt": "2026-10-20T00:00:00Z", "files": map[string]string{"artifact.elf": hex.EncodeToString(digest[:])}})
	root := t.TempDir()
	archive := filepath.Join(root, "apps.tar.gz")
	writeArchive(t, archive, []tarEntry{{name: "apps/demo/0000/artifact.elf", mode: tar.TypeReg, data: payload}, {name: "apps/demo/0000/.scanner-input.json", mode: tar.TypeReg, data: manifest}})
	destination := filepath.Join(root, "out")
	if err := os.Mkdir(destination, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := extractApplications(archive, destination, "192.0.2.10", []Application{app}); err == nil {
		t.Fatal("native ELF accepted as Go")
	}
}

func TestApplicationFailedSnapshotRemovesTemporaryInput(t *testing.T) {
	app := Application{Alias: "demo", Directory: "/opt/demo", IncludeJava: true}
	c := &Collector{profiles: map[string]Profile{"192.0.2.10": {IP: "192.0.2.10", SSHPort: 22, User: "scanner", Auth: "agent", Apps: []Application{app}}}}
	c.runApplications = func(_ context.Context, _ []string, out, _ io.Writer) error {
		root := t.TempDir()
		archive := filepath.Join(root, "bad.tar.gz")
		writeArchive(t, archive, applicationEntries(t, "192.0.2.10", app)[:1])
		file, err := os.Open(archive)
		if err != nil {
			return err
		}
		defer file.Close()
		_, err = io.Copy(out, file)
		return err
	}
	root := t.TempDir()
	runtime := filepath.Join(root, "runtime")
	inputs := filepath.Join(root, "inputs")
	_, cleanup, _, err := c.CollectApplications(context.Background(), "192.0.2.10", []int{22}, []int{22}, runtime, inputs)
	cleanup()
	if err == nil {
		t.Fatal("missing manifest accepted")
	}
	for _, directory := range []string{runtime, inputs} {
		entries, err := os.ReadDir(directory)
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != 0 {
			t.Fatal("failed collection retained temporary files")
		}
	}
}

func TestApplicationJavaRejectsUnsafeAndDuplicateArchivePaths(t *testing.T) {
	for _, names := range [][]string{{"../escape"}, {"/absolute"}, {"folder/../escape"}, {"a\\b"}, {"a:b"}, {"a\nfile"}, {"a\u0085file"}, {"a//b"}, {"same", "same"}, {"folder/", "folder"}, {strings.Repeat("x", 1025)}} {
		root := t.TempDir()
		filename := filepath.Join(root, "artifact.jar")
		var buffer bytes.Buffer
		writer := zip.NewWriter(&buffer)
		for _, name := range names {
			entry, err := writer.Create(name)
			if err != nil {
				t.Fatal(err)
			}
			_, _ = entry.Write([]byte("fixture"))
		}
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filename, buffer.Bytes(), 0600); err != nil {
			t.Fatal(err)
		}
		if err := validateJavaArchive(filename, &javaBudget{}); err == nil {
			t.Fatalf("accepted paths %q", names)
		}
	}
}
