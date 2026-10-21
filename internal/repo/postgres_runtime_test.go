package repo

import (
	"context"
	"errors"
	"strings"
	"testing"

	"scanner-platform/internal/rules"
)

func TestNewPostgresRuntimeRejectsNilDatabase(t *testing.T) {
	if _, err := NewPostgresRuntime(nil); !errors.Is(err, ErrPostgresDSNRequired) {
		t.Fatalf("nil database error=%v, want %v", err, ErrPostgresDSNRequired)
	}
}

func TestPostgresRuntimeTaskWhereIsBounded(t *testing.T) {
	where, args := postgresRuntimeTaskWhere(TaskListQuery{
		Status:   "RUNNING",
		Engine:   "port-probe",
		Search:   `task_%\\'`,
		Archived: "false",
	})
	if len(args) != 3 {
		t.Fatalf("args=%d, want 3", len(args))
	}
	if !strings.Contains(where, "t.status=$1") || !strings.Contains(where, "p.data::jsonb") || !strings.Contains(where, "ILIKE $3") {
		t.Fatalf("unexpected bounded query=%q", where)
	}
	if got := args[2].(string); !strings.Contains(got, `\_`) || !strings.Contains(got, `\%`) || !strings.Contains(got, `\\`) {
		t.Fatalf("escaped search=%q", got)
	}
}

func TestPostgresRuntimeMode(t *testing.T) {
	store := &PostgresRuntimeStore{}
	if got := store.RuntimeMode(); got != "postgres" {
		t.Fatalf("runtime mode=%q", got)
	}
}

func TestPostgresSyncRulesRejectsUnverifiedMetadataShape(t *testing.T) {
	store := &PostgresRuntimeStore{}
	base := rules.Bundle{
		Version:        "20261021.01",
		Engines:        []string{"nuclei"},
		Channel:        "local",
		ManifestSHA256: strings.Repeat("a", 64),
		PublishedAt:    "2026-10-21T12:00:00Z",
	}
	for name, input := range map[string]rules.Bundle{
		"bad version": func() rules.Bundle { v := base; v.Version = "latest"; return v }(),
		"bad hash":    func() rules.Bundle { v := base; v.ManifestSHA256 = "short"; return v }(),
		"bad time":    func() rules.Bundle { v := base; v.PublishedAt = "yesterday"; return v }(),
		"bad engine":  func() rules.Bundle { v := base; v.Engines = []string{"zap"}; return v }(),
	} {
		t.Run(name, func(t *testing.T) {
			if err := store.SyncRules(context.Background(), []rules.Bundle{input}); !errors.Is(err, ErrInvalidTask) {
				t.Fatalf("error=%v, want ErrInvalidTask", err)
			}
		})
	}
}

func TestPostgresRuleListRejectsInvalidQueryBeforeDatabaseAccess(t *testing.T) {
	store := &PostgresRuntimeStore{}
	if _, err := store.ListRulesPage(context.Background(), RuleListQuery{Page: 1, Sort: "unknown"}); !errors.Is(err, ErrInvalidRuleListQuery) {
		t.Fatalf("error=%v, want ErrInvalidRuleListQuery", err)
	}
}
