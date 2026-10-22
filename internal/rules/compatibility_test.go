package rules

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEngineCompatibilityMatchesPinnedRuntimeAndSchemas(t *testing.T) {
	dir := t.TempDir()
	metadata := filepath.Join(dir, "trivy", "db", "metadata.json")
	if err := os.MkdirAll(filepath.Dir(metadata), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(metadata, []byte(`{"Version":2}`), 0600); err != nil {
		t.Fatal(err)
	}
	manifest := Manifest{
		Version:             "20261022.01",
		Engines:             []string{"nuclei", "trivy"},
		EngineCompatibility: PinnedEngineCompatibility([]string{"nuclei", "trivy"}, false),
		Files: map[string]string{
			"nuclei/templates/example.json": "fixture",
			"trivy/db/metadata.json":        "fixture",
			"trivy/db/trivy.db":             "fixture",
		},
	}
	ok, err := validateEngineCompatibility(manifest, dir)
	if err != nil || !ok {
		t.Fatalf("pinned compatibility rejected: %v, %v", ok, err)
	}

	manifest.EngineCompatibility["trivy"] = EngineCompatibility{Min: "0.75.0", Max: "0.75.0", DBSchema: 2}
	ok, err = validateEngineCompatibility(manifest, dir)
	if err != nil || ok {
		t.Fatalf("out-of-range compatibility accepted: %v, %v", ok, err)
	}
	manifest.EngineCompatibility["trivy"] = EngineCompatibility{Min: "0.76.0", Max: "0.76.0", DBSchema: 3}
	ok, err = validateEngineCompatibility(manifest, dir)
	if err != nil || ok {
		t.Fatalf("schema mismatch accepted: %v, %v", ok, err)
	}
	manifest.EngineCompatibility["trivy"] = EngineCompatibility{Min: "bad", Max: "0.76.0", DBSchema: 2}
	if _, err = validateEngineCompatibility(manifest, dir); err == nil {
		t.Fatal("malformed compatibility range accepted")
	}
}

func TestEngineCompatibilityRequiresMatchingJavaMetadata(t *testing.T) {
	dir := t.TempDir()
	for name, data := range map[string]string{
		"trivy/db/metadata.json":      `{"Version":2}`,
		"trivy/java-db/metadata.json": `{"Version":1}`,
		"trivy/java-db/trivy-java.db": "java fixture",
	} {
		path := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	manifest := Manifest{
		Version:             "20261022.01",
		Engines:             []string{"trivy"},
		EngineCompatibility: PinnedEngineCompatibility([]string{"trivy"}, true),
		Files: map[string]string{
			"trivy/db/metadata.json":      "fixture",
			"trivy/db/trivy.db":           "fixture",
			"trivy/java-db/metadata.json": "fixture",
			"trivy/java-db/trivy-java.db": "fixture",
		},
	}
	ok, err := validateEngineCompatibility(manifest, dir)
	if err != nil || !ok {
		t.Fatalf("Java compatibility rejected: %v, %v", ok, err)
	}
	manifest.EngineCompatibility["trivy"] = PinnedEngineCompatibility([]string{"trivy"}, false)["trivy"]
	if _, err := validateEngineCompatibility(manifest, dir); err == nil {
		t.Fatal("Java files without java_db_schema accepted")
	}
}
