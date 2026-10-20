package executor

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"scanner-platform/internal/versionmgr"
)

func TestCurrentRuleVersionReadOnlyReadiness(t *testing.T) {
	root := t.TempDir()
	runner := Runner{RulesDir: root}
	if _, err := runner.CurrentRuleVersion(context.Background()); !errors.Is(err, versionmgr.ErrWaitingForRules) {
		t.Fatalf("missing CURRENT error=%v", err)
	}
	if err := os.MkdirAll(filepath.Join(root, "releases", "20261020.05"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := versionmgr.WriteLocalCurrent(context.Background(), root, "20261020.05"); err != nil {
		t.Fatal(err)
	}
	version, err := runner.CurrentRuleVersion(context.Background())
	if err != nil || version != "20261020.05" {
		t.Fatalf("valid CURRENT version=%q err=%v", version, err)
	}
	if err := os.WriteFile(filepath.Join(root, "CURRENT"), []byte("bad\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := runner.CurrentRuleVersion(context.Background()); !errors.Is(err, versionmgr.ErrInvalidCurrent) {
		t.Fatalf("invalid CURRENT accepted: %v", err)
	}
}

func TestCurrentRuleVersionDoesNotCreateRuleFiles(t *testing.T) {
	root := filepath.Join(t.TempDir(), "missing")
	runner := Runner{RulesDir: root}
	if _, err := runner.CurrentRuleVersion(context.Background()); !errors.Is(err, versionmgr.ErrWaitingForRules) {
		t.Fatalf("missing rule root should wait for rules, error=%v", err)
	}
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatalf("readiness check created rule root: %v", err)
	}
}
