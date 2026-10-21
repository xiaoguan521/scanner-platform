package execguard

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestValidatePinnedExecutable(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "worker")
	if err := os.WriteFile(path, []byte("worker"), 0700); err != nil {
		t.Fatal(err)
	}
	trusted, err := exec.LookPath("dash")
	if err != nil {
		t.Skip("dash is not installed")
	}
	trusted, err = filepath.Abs(trusted)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidatePinnedExecutable(trusted); err != nil {
		t.Fatalf("trusted executable rejected: %v", err)
	}
	for _, mode := range []os.FileMode{0600, 0675} {
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		if ValidatePinnedExecutable(path) == nil {
			t.Fatalf("accepted worker mode %o", mode)
		}
	}
	if ValidatePinnedExecutable(filepath.Join(root, "missing")) == nil {
		t.Fatal("accepted missing worker")
	}
	if err := os.Chmod(root, 0777); err != nil {
		t.Fatal(err)
	}
	if ValidatePinnedExecutable(path) == nil {
		t.Fatal("accepted executable below writable directory")
	}
}
