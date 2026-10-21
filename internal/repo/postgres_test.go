package repo

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPostgresMigrationCatalogIsEmbeddedAndOrdered(t *testing.T) {
	migrations, err := PostgresMigrations()
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"0001_core", "0002_scanning", "0003_rules_sbom", "0004_report_inventory", "0005_task_archive", "0006_task_pause", "0007_asset_catalog", "0008_task_projection", "0009_finding_projection", "0010_rule_catalog_projection", "0011_rule_jobs", "0012_schedules", "0013_notifications", "0014_product_catalog"}
	if len(migrations) != len(want) {
		t.Fatalf("migration count=%d, want %d", len(migrations), len(want))
	}
	for i, migration := range migrations {
		if migration.Version != want[i] {
			t.Fatalf("migration[%d]=%q, want %q", i, migration.Version, want[i])
		}
		if !strings.Contains(string(migration.SQL), "INSERT INTO schema_migrations") {
			t.Fatalf("migration %s does not record itself", migration.Version)
		}
	}
	first := migrations[0].SQL
	first[0] ^= 0xff
	again, err := PostgresMigrations()
	if err != nil {
		t.Fatal(err)
	}
	if string(first) == string(again[0].SQL) {
		t.Fatal("migration catalog returned mutable embedded bytes")
	}
}

func TestReadPostgresDSNFileRequiresProtectedSingleLine(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dsn")
	write := func(value string, mode os.FileMode) {
		t.Helper()
		if err := os.WriteFile(path, []byte(value), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
	}
	write("postgres://scanner:secret@localhost/scanner_platform\n", 0600)
	got, err := ReadPostgresDSNFile(path)
	if err != nil || got != "postgres://scanner:secret@localhost/scanner_platform" {
		t.Fatalf("read protected DSN=%q err=%v", got, err)
	}
	for _, test := range []struct {
		name  string
		value string
		mode  os.FileMode
	}{
		{name: "group readable", value: "postgres://localhost/db", mode: 0640},
		{name: "empty", value: " \n", mode: 0600},
		{name: "multiple lines", value: "postgres://localhost/db\nsecond", mode: 0600},
		{name: "control", value: "postgres://localhost/\x01", mode: 0600},
	} {
		t.Run(test.name, func(t *testing.T) {
			write(test.value, test.mode)
			if _, err := ReadPostgresDSNFile(path); !errors.Is(err, ErrPostgresDSNFile) {
				t.Fatalf("expected protected DSN error, got %v", err)
			}
		})
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadPostgresDSNFile(path); !errors.Is(err, ErrPostgresDSNFile) {
		t.Fatalf("missing file error=%v", err)
	}
	if err := os.WriteFile(path, []byte("postgres://localhost/db"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "dsn-link")
	if err := os.Symlink(path, link); err == nil {
		if _, err := ReadPostgresDSNFile(link); !errors.Is(err, ErrPostgresDSNFile) {
			t.Fatalf("symlink error=%v", err)
		}
	}
}

func TestPostgresConfigValidation(t *testing.T) {
	if err := (PostgresConfig{}).validate(); !errors.Is(err, ErrPostgresDSNRequired) {
		t.Fatalf("empty config error=%v", err)
	}
	if err := (PostgresConfig{DSN: "postgres://localhost/db", MaxOpenConns: -1}).validate(); err == nil {
		t.Fatal("negative pool setting accepted")
	}
}
