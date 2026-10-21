package repo

import (
	"errors"
	"strings"
	"testing"
	"time"

	"scanner-platform/internal/taskflow"
)

func TestNewPostgresFindingStoreRejectsNilDatabase(t *testing.T) {
	if _, err := NewPostgresFindingStore(nil); !errors.Is(err, ErrPostgresDSNRequired) {
		t.Fatalf("expected postgres DSN error, got %v", err)
	}
}

func TestNormalizePostgresFindingRequiresStableIdentity(t *testing.T) {
	base := taskflow.Finding{
		ID: "finding-1", TaskID: "task-1", AssetID: "asset-1",
		Fingerprint: stablePostgresFindingFingerprint("192.0.2.10:8080", "trivy", "CVE-2026-0001", "", "apache2", "1"),
		Severity:    "HIGH", Title: "fixture", Engine: "trivy", TemplateOrCVE: "CVE-2026-0001", Target: "192.0.2.10:8080",
	}
	if _, err := normalizePostgresFinding(base, testPostgresFindingTime()); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*taskflow.Finding){
		func(f *taskflow.Finding) { f.Fingerprint = "not-a-sha256" },
		func(f *taskflow.Finding) { f.AssetID = "" },
		func(f *taskflow.Finding) { f.Status = "UNKNOWN" },
		func(f *taskflow.Finding) { f.Target = "" },
	} {
		candidate := base
		mutate(&candidate)
		if _, err := normalizePostgresFinding(candidate, testPostgresFindingTime()); !errors.Is(err, ErrPostgresFindingInvalid) {
			t.Fatalf("normalize error=%v, want %v", err, ErrPostgresFindingInvalid)
		}
	}
}

func TestPostgresFindingWhereUsesBoundValues(t *testing.T) {
	where, args := postgresFindingWhere(FindingListQuery{Search: "100%_safe", Severity: "HIGH", Status: "OPEN", AssetID: "asset-1"})
	if len(args) != 7 {
		t.Fatalf("args=%d, want 7", len(args))
	}
	if strings.Count(where, "$1") != 1 || strings.Count(where, "$4") != 1 || strings.Count(where, "$5") != 1 || strings.Count(where, "$7") != 1 {
		t.Fatalf("unexpected placeholders in %q", where)
	}
	if args[0] != `%100\%\_safe%` {
		t.Fatalf("escaped search=%q", args[0])
	}
}

func TestPostgresFindingSortIsFixed(t *testing.T) {
	for _, value := range []string{"first_seen", "-severity", "title", "unknown"} {
		expr, direction := postgresFindingSort(value)
		if expr == "" || (direction != "ASC" && direction != "DESC") || strings.ContainsAny(expr, ";\n") {
			t.Fatalf("unsafe sort for %q: %q %q", value, expr, direction)
		}
	}
}

func testPostgresFindingTime() time.Time {
	return time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
}
