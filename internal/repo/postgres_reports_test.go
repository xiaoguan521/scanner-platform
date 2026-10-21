package repo

import (
	"errors"
	"strings"
	"testing"

	"scanner-platform/internal/reporting"
)

func TestNewPostgresReportStoreRejectsNilDatabase(t *testing.T) {
	if _, err := NewPostgresReportStore(nil); !errors.Is(err, ErrPostgresDSNRequired) {
		t.Fatalf("expected postgres DSN error, got %v", err)
	}
}

func TestPostgresReportWhereUsesBoundValues(t *testing.T) {
	where, args := postgresReportWhere(ReportListQuery{Status: "READY", Format: "json", Search: "100%_safe"})
	if len(args) != 6 {
		t.Fatalf("args=%d, want 6", len(args))
	}
	if strings.Count(where, "$1") != 1 || strings.Count(where, "$2") != 1 || strings.Count(where, "$3") != 1 || strings.Count(where, "$6") != 1 {
		t.Fatalf("unexpected placeholders in %q", where)
	}
	for index := 2; index < len(args); index++ {
		if args[index] != `%100\%\_safe%` {
			t.Fatalf("search arg[%d]=%q", index, args[index])
		}
	}
}

func TestPostgresReportSortIsFixed(t *testing.T) {
	for _, value := range []string{"name", "-format", "created_at", "drop_table"} {
		expr, direction := postgresReportSort(value)
		if expr == "" || (direction != "ASC" && direction != "DESC") || strings.ContainsAny(expr, ";\n") {
			t.Fatalf("unsafe report sort for %q: %q %q", value, expr, direction)
		}
	}
}

func TestPostgresReportRequestStillUsesSharedValidation(t *testing.T) {
	if err := reporting.ValidateRequest(reporting.Request{Format: "yaml"}); err == nil {
		t.Fatal("unsupported report format accepted")
	}
}
