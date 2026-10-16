//go:build windows

package versionmgr

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// Run on windows-latest and windows-11-arm runners. This tests the precise
// Windows errors used for bounded retries; real sharing-lock replacement
// behavior still requires the operating system integration test.
func TestWindowsRenameErrorClassification(t *testing.T) {
	for _, code := range []syscall.Errno{5, 32, 33} {
		if !retryableWindowsRename(&os.LinkError{
			Op: "rename", Old: "old", New: "new", Err: fmt.Errorf("wrapped: %w", code),
		}) {
			t.Fatalf("transient Windows error %d not retried", code)
		}
	}
	for _, err := range []error{syscall.Errno(2), syscall.Errno(3), errors.New("unrelated")} {
		if retryableWindowsRename(err) {
			t.Fatalf("non-transient error %v was retried", err)
		}
	}
}

func TestWindowsCurrentReplaceRealFilesystem(t *testing.T) {
	root := t.TempDir()
	src := filepath.Join(root, "tmp")
	dst := filepath.Join(root, "CURRENT")
	if err := os.WriteFile(dst, []byte("20261016.01\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(src, []byte("20261016.02\n"), 0600); err != nil {
		t.Fatal(err)
	}
	// A successful replace must never expose a missing CURRENT intermediary.
	if err := replaceCurrent(t.Context(), src, dst); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(dst)
	if err != nil || string(b) != "20261016.02\n" {
		t.Fatalf("Windows replacement failed: %q, %v", b, err)
	}
}
