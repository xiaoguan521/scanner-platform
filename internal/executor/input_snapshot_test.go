package executor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeSnapshot(t *testing.T, root, kind string, files map[string]string) {
	t.Helper()
	snapshot := inputSnapshot{SchemaVersion: 1, Source: "lab-a", Kind: kind, CollectedAt: "2026-10-19T10:00:00Z", Files: files}
	data, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	name := filepath.Join(root, snapshotName)
	if kind == "image-archive" {
		name = root + snapshotName
	}
	if err := os.WriteFile(name, data, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestInputSnapshotCompletenessAndCancellation(t *testing.T) {
	root := t.TempDir()
	payload := []byte("Package: fixture\nVersion: 1.0\n")
	digest := sha256.Sum256(payload)
	file := filepath.Join(root, "status")
	if err := os.WriteFile(file, payload, 0600); err != nil {
		t.Fatal(err)
	}
	writeSnapshot(t, root, "rootfs", map[string]string{"status": hex.EncodeToString(digest[:])})
	description, err := verifyInputSnapshot(context.Background(), root, "rootfs")
	if err != nil || !strings.Contains(description, "lab-a") || !strings.Contains(description, "2026-10-19") {
		t.Fatal(description, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := verifyInputSnapshot(ctx, root, "rootfs"); !errors.Is(err, context.Canceled) {
		t.Fatal("hash verification must preserve cancellation", err)
	}
	if _, err := verifyInputSnapshot(context.Background(), root, "filesystem"); err == nil {
		t.Fatal("snapshot accepted as another input kind")
	}
	if err := os.WriteFile(file, []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyInputSnapshot(context.Background(), root, "rootfs"); err == nil {
		t.Fatal("changed package database accepted")
	}
	if err := os.Remove(file); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyInputSnapshot(context.Background(), root, "rootfs"); err == nil {
		t.Fatal("incomplete transfer accepted")
	}
}

func TestInputSnapshotRejectsUnexpectedFilesAndSymlinks(t *testing.T) {
	for _, link := range []bool{false, true} {
		root := t.TempDir()
		digest := sha256.Sum256([]byte("fixture"))
		if err := os.WriteFile(filepath.Join(root, "lock"), []byte("fixture"), 0600); err != nil {
			t.Fatal(err)
		}
		writeSnapshot(t, root, "filesystem", map[string]string{"lock": hex.EncodeToString(digest[:])})
		if link {
			if err := os.Remove(filepath.Join(root, "lock")); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(filepath.Join(t.TempDir(), "elsewhere"), filepath.Join(root, "lock")); err != nil {
				t.Skip("symlinks unavailable")
			}
		} else if err := os.WriteFile(filepath.Join(root, "unexpected"), []byte("unlisted"), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := verifyInputSnapshot(context.Background(), root, "filesystem"); err == nil {
			t.Fatal("unlisted file or symlink accepted")
		}
	}
}

func TestImageSnapshotDescribesOnlyItsArchive(t *testing.T) {
	image := filepath.Join(t.TempDir(), "image.tar")
	data := []byte("fixture archive")
	if err := os.WriteFile(image, data, 0600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(data)
	writeSnapshot(t, image, "image-archive", map[string]string{"image.tar": hex.EncodeToString(digest[:])})
	if _, err := verifyInputSnapshot(context.Background(), image, "image-archive"); err != nil {
		t.Fatal(err)
	}
	writeSnapshot(t, image, "image-archive", map[string]string{"other.tar": hex.EncodeToString(digest[:])})
	if _, err := verifyInputSnapshot(context.Background(), image, "image-archive"); err == nil {
		t.Fatal("another archive accepted")
	}
}

func TestSnapshotSchemaRejectsUnsafePaths(t *testing.T) {
	for _, name := range []string{"../outside", "/absolute", "a/../b", `a\b`, "a:b", snapshotName} {
		snapshot := inputSnapshot{SchemaVersion: 1, Source: "lab-a", Kind: "rootfs", CollectedAt: "2026-10-19T10:00:00Z", Files: map[string]string{name: strings.Repeat("a", 64)}}
		data, _ := json.Marshal(snapshot)
		if _, err := decodeInputSnapshot(data, "rootfs"); err == nil {
			t.Fatal("unsafe snapshot path accepted", name)
		}
	}
}

func FuzzInputSnapshot(f *testing.F) {
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"schemaVersion":1,"kind":"rootfs","source":"lab-a","collectedAt":"2026-10-19T10:00:00Z","files":{"status":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 2<<20 {
			t.Skip()
		}
		_, _ = decodeInputSnapshot(data, "rootfs")
	})
}
