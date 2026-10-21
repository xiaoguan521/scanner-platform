package bootstrap

import (
	"bytes"
	"strings"
	"testing"
)

func TestRunServerRejectsUnknownStorage(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if got := RunServer([]string{"--storage", "mysql"}, &stdout, &stderr); got != 2 {
		t.Fatalf("exit=%d, want 2; stderr=%q", got, stderr.String())
	}
	if !strings.Contains(stderr.String(), "--storage must be sqlite or postgres") {
		t.Fatalf("stderr=%q", stderr.String())
	}
}

func TestRunServerRequiresProtectedPostgresDSN(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if got := RunServer([]string{"--storage", "postgres"}, &stdout, &stderr); got != 2 {
		t.Fatalf("exit=%d, want 2; stderr=%q", got, stderr.String())
	}
	if !strings.Contains(stderr.String(), "--storage=postgres requires --postgres-dsn-file") {
		t.Fatalf("stderr=%q", stderr.String())
	}
}

func TestRunServerRejectsPostgresDSNInSQLiteMode(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if got := RunServer([]string{"--postgres-dsn-file", "/tmp/example.dsn"}, &stdout, &stderr); got != 2 {
		t.Fatalf("exit=%d, want 2; stderr=%q", got, stderr.String())
	}
	if !strings.Contains(stderr.String(), "--postgres-dsn-file requires --storage=postgres") {
		t.Fatalf("stderr=%q", stderr.String())
	}
}
