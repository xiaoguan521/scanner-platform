package sshcollect

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestLoadSupportsLocalAgentAndPrivateKeyProfiles(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "known_hosts"), []byte("[192.0.2.10]:22 ssh-ed25519 AAAA\n"), 0600); err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(root, "id_ed25519")
	if err := os.WriteFile(key, []byte("local-key-placeholder"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := fileConfig{KnownHostsFile: "known_hosts", Targets: []Profile{
		{IP: "192.0.2.10", SSHPort: 22, User: "scanner", Auth: "agent"},
		{IP: "2001:db8::10", SSHPort: 2222, User: "svc_scan", Auth: "private-key", PrivateKeyFile: "id_ed25519"},
	}}
	writeConfig(t, root, cfg)
	collector, err := Load(filepath.Join(root, "ssh.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !collector.Configured("192.0.2.10") || !collector.Configured("2001:db8::10") {
		t.Fatal("expected numeric target profiles")
	}
	if port, ok := collector.ProfilePort("2001:db8::10"); !ok || port != 2222 {
		t.Fatalf("port=%d configured=%t", port, ok)
	}
}

func TestLoadRejectsCredentialsHostsDuplicatesAndInsecureKeys(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*testing.T, string, *fileConfig)
	}{
		{name: "hostname", edit: func(_ *testing.T, _ string, cfg *fileConfig) { cfg.Targets[0].IP = "server.example" }},
		{name: "duplicate", edit: func(_ *testing.T, _ string, cfg *fileConfig) { cfg.Targets = append(cfg.Targets, cfg.Targets[0]) }},
		{name: "password-field", edit: func(t *testing.T, root string, _ *fileConfig) {
			_ = os.WriteFile(filepath.Join(root, "ssh.json"), []byte(`{"knownHostsFile":"known_hosts","targets":[{"ip":"192.0.2.10","sshPort":22,"user":"scanner","auth":"agent","password":"secret"}]}`), 0600)
		}},
		{name: "insecure-key", edit: func(t *testing.T, root string, cfg *fileConfig) {
			if runtime.GOOS == "windows" {
				t.Skip("POSIX key permission bits do not apply on Windows")
			}
			key := filepath.Join(root, "id_ed25519")
			if err := os.WriteFile(key, []byte("local-key-placeholder"), 0644); err != nil {
				t.Fatal(err)
			}
			cfg.Targets[0].Auth, cfg.Targets[0].PrivateKeyFile = "private-key", "id_ed25519"
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			if err := os.WriteFile(filepath.Join(root, "known_hosts"), []byte("fixture\n"), 0600); err != nil {
				t.Fatal(err)
			}
			cfg := fileConfig{KnownHostsFile: "known_hosts", Targets: []Profile{{IP: "192.0.2.10", SSHPort: 22, User: "scanner", Auth: "agent"}}}
			tc.edit(t, root, &cfg)
			if tc.name != "password-field" {
				writeConfig(t, root, cfg)
			}
			if _, err := Load(filepath.Join(root, "ssh.json")); err == nil {
				t.Fatal("invalid SSH config was accepted")
			}
		})
	}
}

func TestExtractSnapshotAcceptsOnlyBoundedRegularSnapshotFiles(t *testing.T) {
	root := t.TempDir()
	archive := filepath.Join(root, "snapshot.tar.gz")
	writeArchive(t, archive, []tarEntry{
		{name: "os/", mode: tar.TypeDir},
		{name: "os/.scanner-input.json", mode: tar.TypeReg, data: []byte(`{"schemaVersion":1}`)},
		{name: "os/etc/", mode: tar.TypeDir},
		{name: "os/etc/os-release", mode: tar.TypeReg, data: []byte("ID=centos\nVERSION_ID=7\n")},
		{name: "runtime-services.json", mode: tar.TypeReg, data: []byte(`{"schemaVersion":1,"services":[{"name":"sshd","manager":"process","state":"running"}]}`)},
	})
	destination := filepath.Join(root, "ssh-abc123")
	if err := extractSnapshot(archive, destination); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(filepath.Join(destination, "os", "etc", "os-release")); err != nil || !strings.Contains(string(got), "ID=centos") {
		t.Fatalf("got=%q err=%v", got, err)
	}
	services, err := readRuntimeServices(destination)
	if err != nil || len(services) != 1 || services[0].Name != "sshd" {
		t.Fatalf("runtime services=%+v err=%v", services, err)
	}
}

func TestReadRuntimeServicesRejectsInvalidPayloads(t *testing.T) {
	for _, tc := range []struct {
		name string
		data string
	}{
		{name: "unknown field", data: `{"schemaVersion":1,"services":[],"extra":true}`},
		{name: "wrong schema", data: `{"schemaVersion":2,"services":[]}`},
		{name: "missing services", data: `{"schemaVersion":1}`},
		{name: "duplicate", data: `{"schemaVersion":1,"services":[{"name":"sshd","manager":"process","state":"running"},{"name":"sshd","manager":"process","state":"running"}]}`},
		{name: "unsafe name", data: `{"schemaVersion":1,"services":[{"name":"sshd --bad","manager":"process","state":"running"}]}`},
		{name: "container missing image", data: `{"schemaVersion":1,"services":[{"name":"web","manager":"container","runtime":"docker","state":"running"}]}`},
		{name: "container unsafe image", data: `{"schemaVersion":1,"services":[{"name":"web","manager":"container","runtime":"docker","image":"nginx\tlatest","state":"running"}]}`},
		{name: "trailing data", data: `{"schemaVersion":1,"services":[]} {}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			if err := os.WriteFile(filepath.Join(root, "runtime-services.json"), []byte(tc.data), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := readRuntimeServices(root); err == nil {
				t.Fatal("invalid runtime service inventory was accepted")
			}
		})
	}
}

func TestReadRuntimeServicesAcceptsContainerWorkload(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "runtime-services.json"), []byte(`{"schemaVersion":1,"services":[{"name":"web","manager":"container","runtime":"docker","image":"nginx:1.27","state":"running"}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	services, err := readRuntimeServices(root)
	if err != nil || len(services) != 1 || services[0].Runtime != "docker" || services[0].Image != "nginx:1.27" {
		t.Fatalf("services=%+v err=%v", services, err)
	}
}

func FuzzReadRuntimeServices(f *testing.F) {
	f.Add([]byte(`{"schemaVersion":1,"services":[]}`))
	f.Add([]byte(`{"schemaVersion":1,"services":[{"name":"sshd","manager":"process","state":"running"}]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		root := t.TempDir()
		if err := os.WriteFile(filepath.Join(root, "runtime-services.json"), data, 0600); err != nil {
			t.Fatal(err)
		}
		_, _ = readRuntimeServices(root)
	})
}

func TestExtractSnapshotRejectsTraversalLinksAndUnexpectedFiles(t *testing.T) {
	for _, entry := range []tarEntry{
		{name: "../escape", mode: tar.TypeReg, data: []byte("x")},
		{name: "os/etc/link", mode: tar.TypeSymlink, link: "../../etc/shadow"},
		{name: "other/private", mode: tar.TypeReg, data: []byte("x")},
	} {
		t.Run(entry.name, func(t *testing.T) {
			root := t.TempDir()
			archive := filepath.Join(root, "bad.tar.gz")
			writeArchive(t, archive, []tarEntry{entry})
			if err := extractSnapshot(archive, filepath.Join(root, "out")); err == nil {
				t.Fatal("unsafe archive was accepted")
			}
		})
	}
}

func TestLimitedWriterRejectsOversizedOutput(t *testing.T) {
	var dst strings.Builder
	writer := limitedWriter{dst: &dst, remaining: 3}
	if _, err := writer.Write([]byte("123")); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write([]byte("4")); err == nil {
		t.Fatal("oversized output was accepted")
	}
}

func writeConfig(t *testing.T, root string, cfg fileConfig) {
	t.Helper()
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "ssh.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
}

type tarEntry struct {
	name string
	mode byte
	data []byte
	link string
}

func writeArchive(t *testing.T, filename string, entries []tarEntry) {
	t.Helper()
	file, err := os.Create(filename)
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(file)
	archive := tar.NewWriter(gz)
	for _, entry := range entries {
		header := &tar.Header{Name: entry.name, Typeflag: entry.mode, Mode: 0600, Size: int64(len(entry.data)), Linkname: entry.link}
		if entry.mode == tar.TypeDir {
			header.Size = 0
		}
		if err := archive.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if entry.mode == tar.TypeReg {
			if _, err := archive.Write(entry.data); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}
