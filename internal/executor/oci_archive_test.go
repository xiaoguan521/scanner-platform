package executor

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type ociTestEntry struct {
	name     string
	body     []byte
	typeflag byte
}

func ociFixture() []ociTestEntry {
	manifest := []byte(`{"schemaVersion":2,"fixture":true}`)
	digest := sha256.Sum256(manifest)
	index, _ := json.Marshal(map[string]any{"schemaVersion": 2, "manifests": []any{map[string]string{"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": "sha256:" + hex.EncodeToString(digest[:])}}})
	return []ociTestEntry{{"oci-layout", []byte(`{"imageLayoutVersion":"1.0.0"}`), tar.TypeReg}, {"index.json", index, tar.TypeReg}, {"blobs/sha256/" + hex.EncodeToString(digest[:]), manifest, tar.TypeReg}}
}

func writeOCIFixture(t *testing.T, root string, entries []ociTestEntry) string {
	t.Helper()
	input := filepath.Join(root, "fixture.tar")
	file, err := os.Create(input)
	if err != nil {
		t.Fatal(err)
	}
	writer := tar.NewWriter(file)
	for _, entry := range entries {
		header := &tar.Header{Name: entry.name, Mode: 0600, Size: int64(len(entry.body)), Typeflag: entry.typeflag}
		if entry.typeflag == tar.TypeSymlink {
			header.Linkname = "../outside"
			header.Size = 0
		}
		if err := writer.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if entry.typeflag != tar.TypeSymlink {
			if _, err := writer.Write(entry.body); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	return input
}

func TestOCILayoutExtractedOnlyIntoPrivateDestination(t *testing.T) {
	root := t.TempDir()
	input := writeOCIFixture(t, root, ociFixture())
	destination := filepath.Join(root, "private-oci")
	got, err := prepareImageInput(context.Background(), input, destination)
	if err != nil || got != destination {
		t.Fatal(got, err)
	}
	if info, err := os.Stat(filepath.Join(destination, "index.json")); err != nil || info.Mode().Perm() != 0600 {
		t.Fatal(info, err)
	}
}

func TestOCIRejectsTraversalLinksDuplicatesAndChangedBlobs(t *testing.T) {
	for _, kind := range []string{"traversal", "absolute", "symlink", "duplicate", "hash", "missing", "multi-platform"} {
		t.Run(kind, func(t *testing.T) {
			entries := ociFixture()
			switch kind {
			case "traversal":
				entries = append(entries, ociTestEntry{"../outside", []byte("fixture"), tar.TypeReg})
			case "absolute":
				entries = append(entries, ociTestEntry{"/outside", []byte("fixture"), tar.TypeReg})
			case "symlink":
				entries[2].typeflag = tar.TypeSymlink
			case "duplicate":
				entries = append(entries, entries[0])
			case "hash":
				entries[2].body = []byte("changed")
			case "missing":
				entries = entries[:1]
			case "multi-platform":
				entries[1].body = []byte(`{"schemaVersion":2,"manifests":[{},{}]}`)
			}
			root := t.TempDir()
			input := writeOCIFixture(t, root, entries)
			if _, err := prepareImageInput(context.Background(), input, filepath.Join(root, "private")); err == nil {
				t.Fatal("unsafe OCI archive accepted")
			}
			if _, err := os.Stat(filepath.Join(root, "outside")); !os.IsNotExist(err) {
				t.Fatal("archive escaped destination")
			}
		})
	}
}

func TestDockerArchiveIsNotExtractedByOCIAdapter(t *testing.T) {
	root := t.TempDir()
	input := writeOCIFixture(t, root, []ociTestEntry{{"manifest.json", []byte(`[]`), tar.TypeReg}})
	destination := filepath.Join(root, "private")
	got, err := prepareImageInput(context.Background(), input, destination)
	if err != nil || got != input {
		t.Fatal(got, err)
	}
	if _, err := os.Stat(destination); !os.IsNotExist(err) {
		t.Fatal("Docker archive was extracted")
	}
}

func FuzzOCIArchive(f *testing.F) {
	f.Add([]byte("invalid tar fixture"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			t.Skip()
		}
		root := t.TempDir()
		input := filepath.Join(root, "fixture.tar")
		if err := os.WriteFile(input, data, 0600); err != nil {
			t.Fatal(err)
		}
		_, _ = prepareImageInput(context.Background(), input, filepath.Join(root, "private"))
	})
}
