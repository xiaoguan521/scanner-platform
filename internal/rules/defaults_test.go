package rules

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func dbCacheFixture(t *testing.T, java bool) string {
	t.Helper()
	root := t.TempDir()
	files := map[string]string{"db/trivy.db": "main DB fixture", "db/metadata.json": `{"Version":2}`}
	if java {
		files["java-db/trivy-java.db"] = "Java index fixture"
		files["java-db/metadata.json"] = `{"Version":1}`
	}
	for name, data := range files {
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestStreamingPreparationIncludesJavaAndRequiresExplicitActivation(t *testing.T) {
	manager := Manager{Root: t.TempDir()}
	cache := dbCacheFixture(t, true)
	bundle, err := manager.PrepareDefault(context.Background(), "20261019.01", cache, true)
	if err != nil || !bundle.IntegrityVerified {
		t.Fatal(bundle, err)
	}
	if _, err := os.Stat(filepath.Join(manager.Root, "CURRENT")); !os.IsNotExist(err) {
		t.Fatal("preparation changed CURRENT")
	}
	data, err := os.ReadFile(filepath.Join(manager.Root, "releases", bundle.Version, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest Manifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	for name, digest := range manifest.Files {
		body, err := os.ReadFile(filepath.Join(manager.Root, "releases", bundle.Version, filepath.FromSlash(name)))
		if err != nil || hashBytes(body) != digest {
			t.Fatal(name, err)
		}
	}
	if manifest.Files["trivy/java-db/trivy-java.db"] == "" || len(manifest.Files) != 8 {
		t.Fatal("Java index missing from manifest", manifest)
	}
	if err := manager.ActivatePreparedLocal(context.Background(), bundle.Version); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cache, "db", "trivy.db"), []byte("changed DB fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.PrepareDefault(context.Background(), bundle.Version, cache, true); err == nil {
		t.Fatal("existing prepared release was overwritten")
	}
	if _, err := manager.Inspect(context.Background(), bundle.Version); err != nil {
		t.Fatal("existing release was damaged", err)
	}
}

func TestPreparationFailureDoesNotPublishOrSwitchCurrent(t *testing.T) {
	for _, kind := range []string{"missing-java", "symlink", "canceled", "oversize"} {
		t.Run(kind, func(t *testing.T) {
			manager := Manager{Root: t.TempDir()}
			cache := dbCacheFixture(t, kind != "missing-java")
			if _, err := manager.PrepareDefault(context.Background(), "20261019.01", cache, false); err != nil {
				t.Fatal(err)
			}
			if err := manager.ActivatePreparedLocal(context.Background(), "20261019.01"); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if kind == "canceled" {
				cancel()
			}
			if kind == "oversize" {
				// Sparse file: reject from metadata without reading/allocating GiB.
				if err := os.Truncate(filepath.Join(cache, "db", "trivy.db"), MaxRuleFile+1); err != nil {
					t.Fatal(err)
				}
			}
			if kind == "symlink" {
				file := filepath.Join(cache, "java-db", "trivy-java.db")
				if err := os.Remove(file); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Join(cache, "db", "trivy.db"), file); err != nil {
					t.Skip("symlinks unavailable")
				}
			}
			if _, err := manager.PrepareDefault(ctx, "20261019.02", cache, true); err == nil {
				t.Fatal("invalid preparation succeeded")
			}
			data, err := os.ReadFile(filepath.Join(manager.Root, "CURRENT"))
			if err != nil || string(data) != "20261019.01\n" {
				t.Fatal("CURRENT changed on failure", string(data), err)
			}
			if _, err := os.Stat(filepath.Join(manager.Root, "releases", "20261019.02")); !os.IsNotExist(err) {
				t.Fatal("failed release published")
			}
			stages, _ := filepath.Glob(filepath.Join(manager.Root, ".prepare-*"))
			if len(stages) != 0 {
				t.Fatal("staging files leaked")
			}
		})
	}
}
