package rules

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// These versions are the only engine versions accepted by the current
// worker package. Keep them in the rules package so the updater and Worker
// apply the same manifest compatibility decision without an import cycle.
const (
	NucleiVersion = "3.11.1"
	TrivyVersion  = "0.76.0"
)

type EngineCompatibility struct {
	Min          string `json:"min"`
	Max          string `json:"max"`
	DBSchema     int    `json:"db_schema,omitempty"`
	JavaDBSchema int    `json:"java_db_schema,omitempty"`
}

// PinnedEngineCompatibility returns the compatibility declaration emitted by
// local preparation and CI packaging. The values are deliberately exact
// ranges until a later CI run proves a broader range safe.
func PinnedEngineCompatibility(engines []string, includeJava bool) map[string]EngineCompatibility {
	out := make(map[string]EngineCompatibility, len(engines))
	for _, engine := range engines {
		switch engine {
		case "nuclei":
			out[engine] = EngineCompatibility{Min: NucleiVersion, Max: NucleiVersion}
		case "trivy":
			compatibility := EngineCompatibility{Min: TrivyVersion, Max: TrivyVersion, DBSchema: 2}
			if includeJava {
				compatibility.JavaDBSchema = 1
			}
			out[engine] = compatibility
		}
	}
	return out
}

func validateCompatibilityShape(manifest Manifest) error {
	if len(manifest.EngineCompatibility) == 0 {
		return nil
	}
	if len(manifest.EngineCompatibility) != len(manifest.Engines) {
		return fmt.Errorf("engine compatibility must declare exactly the packaged engines")
	}
	declared := make(map[string]bool, len(manifest.Engines))
	for _, engine := range manifest.Engines {
		declared[engine] = true
		compatibility, ok := manifest.EngineCompatibility[engine]
		if !ok || !validVersionRange(compatibility.Min, compatibility.Max) {
			return fmt.Errorf("engine compatibility range is invalid for %s", engine)
		}
		switch engine {
		case "nuclei":
			if compatibility.DBSchema != 0 || compatibility.JavaDBSchema != 0 {
				return fmt.Errorf("nuclei compatibility cannot declare database schemas")
			}
		case "trivy":
			if compatibility.DBSchema <= 0 {
				return fmt.Errorf("trivy compatibility must declare a positive db_schema")
			}
			if compatibility.JavaDBSchema < 0 {
				return fmt.Errorf("trivy java_db_schema cannot be negative")
			}
		default:
			return fmt.Errorf("engine compatibility contains unsupported engine %q", engine)
		}
	}
	for engine := range manifest.EngineCompatibility {
		if !declared[engine] {
			return fmt.Errorf("engine compatibility contains undeclared engine %q", engine)
		}
	}
	if trivyCompatibility := manifest.EngineCompatibility["trivy"]; trivyCompatibility.DBSchema > 0 {
		if _, ok := manifest.Files["trivy/db/metadata.json"]; !ok {
			return fmt.Errorf("trivy compatibility requires trivy/db/metadata.json")
		}
		if _, ok := manifest.Files["trivy/db/trivy.db"]; !ok {
			return fmt.Errorf("trivy compatibility requires trivy/db/trivy.db")
		}
		javaFiles := hasManifestFile(manifest, "trivy/java-db/")
		if javaFiles != (trivyCompatibility.JavaDBSchema > 0) {
			return fmt.Errorf("trivy Java database files and java_db_schema do not match")
		}
		if trivyCompatibility.JavaDBSchema > 0 {
			if _, ok := manifest.Files["trivy/java-db/metadata.json"]; !ok {
				return fmt.Errorf("trivy Java compatibility requires metadata.json")
			}
			if _, ok := manifest.Files["trivy/java-db/trivy-java.db"]; !ok {
				return fmt.Errorf("trivy Java compatibility requires trivy-java.db")
			}
		}
	}
	return nil
}

func hasManifestFile(manifest Manifest, prefix string) bool {
	for name := range manifest.Files {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

func validVersionRange(minimum, maximum string) bool {
	if _, err := parseEngineVersion(minimum); err != nil {
		return false
	}
	if _, err := parseEngineVersion(maximum); err != nil {
		return false
	}
	return compareEngineVersions(minimum, maximum) <= 0
}

func parseEngineVersion(version string) ([]int, error) {
	parts := strings.Split(version, ".")
	if len(parts) < 2 || len(parts) > 4 {
		return nil, fmt.Errorf("engine version must have 2–4 numeric components")
	}
	parsed := make([]int, len(parts))
	for i, part := range parts {
		if part == "" || (len(part) > 1 && part[0] == '0') {
			return nil, fmt.Errorf("engine version component is not canonical")
		}
		value, err := strconv.Atoi(part)
		if err != nil || value < 0 {
			return nil, fmt.Errorf("engine version component is not numeric")
		}
		parsed[i] = value
	}
	return parsed, nil
}

func compareEngineVersions(left, right string) int {
	a, _ := parseEngineVersion(left)
	b, _ := parseEngineVersion(right)
	for len(a) < len(b) {
		a = append(a, 0)
	}
	for len(b) < len(a) {
		b = append(b, 0)
	}
	for i := range a {
		if a[i] < b[i] {
			return -1
		}
		if a[i] > b[i] {
			return 1
		}
	}
	return 0
}

func readSchemaVersion(path string) (int, error) {
	file, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer file.Close()
	data, err := readLimited(file, 1<<20)
	if err != nil {
		return 0, err
	}
	var metadata struct {
		Version int `json:"Version"`
	}
	if err := json.Unmarshal(data, &metadata); err != nil || metadata.Version <= 0 {
		return 0, fmt.Errorf("metadata Version is invalid")
	}
	return metadata.Version, nil
}

// validateEngineCompatibility returns false for a well-formed declaration
// that does not match this pinned runtime. Malformed declarations and broken
// metadata are errors so callers fail closed instead of treating them as an
// ordinary unsupported version.
func validateEngineCompatibility(manifest Manifest, releaseDir string) (bool, error) {
	if len(manifest.EngineCompatibility) == 0 {
		return false, nil
	}
	if err := validateCompatibilityShape(manifest); err != nil {
		return false, err
	}
	pinned := map[string]string{"nuclei": NucleiVersion, "trivy": TrivyVersion}
	for _, engine := range manifest.Engines {
		compatibility := manifest.EngineCompatibility[engine]
		actual := pinned[engine]
		if actual == "" || compareEngineVersions(actual, compatibility.Min) < 0 || compareEngineVersions(actual, compatibility.Max) > 0 {
			return false, nil
		}
	}
	if compatibility, ok := manifest.EngineCompatibility["trivy"]; ok {
		mainSchema, err := readSchemaVersion(filepath.Join(releaseDir, "trivy", "db", "metadata.json"))
		if err != nil {
			return false, fmt.Errorf("trivy database metadata is invalid: %w", err)
		}
		if mainSchema != compatibility.DBSchema {
			return false, nil
		}
		if compatibility.JavaDBSchema > 0 {
			javaSchema, err := readSchemaVersion(filepath.Join(releaseDir, "trivy", "java-db", "metadata.json"))
			if err != nil {
				return false, fmt.Errorf("trivy Java database metadata is invalid: %w", err)
			}
			if javaSchema != compatibility.JavaDBSchema {
				return false, nil
			}
		}
	}
	return true, nil
}
