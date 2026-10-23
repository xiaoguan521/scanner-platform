package sshcollect

import (
	"os"
	"path/filepath"
	"testing"
)

// testdata/ui-generated-ssh-config.json is byte-for-byte what the web SSH
// config generator produces (web/src/pages/Assets/sshProfile.test.mjs checks
// that side). The Worker must load it unchanged.
func TestLoadAcceptsWebGeneratedConfig(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "ui-generated-ssh-config.json"))
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "ssh-config.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "known_hosts"), []byte("[192.0.2.10]:22 ssh-ed25519 AAAA\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "keys"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "keys", "scan_ed25519"), []byte("local-key-placeholder"), 0600); err != nil {
		t.Fatal(err)
	}
	collector, err := Load(filepath.Join(root, "ssh-config.json"))
	if err != nil {
		t.Fatalf("web-generated config rejected: %v", err)
	}
	if port, ok := collector.ProfilePort("2001:db8::11"); !ok || port != 2222 {
		t.Fatalf("port=%d configured=%t", port, ok)
	}
	if !collector.Configured("192.0.2.10") || len(collector.profiles["192.0.2.10"].Apps) != 1 {
		t.Fatal("agent profile with one application expected")
	}
}
