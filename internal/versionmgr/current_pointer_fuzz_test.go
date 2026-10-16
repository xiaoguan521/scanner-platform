package versionmgr

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// FuzzCurrentPointer is deliberately local and never accepts a network path
// or external rule bundle. Any syntactically invalid contents must fail closed.
func FuzzCurrentPointer(f *testing.F) {
	for _, data := range []string{
		"20261016.01\n", "20261016.02\n", "20261016.01",
		"20261016.01\r\n", "../20261016.01\n", "20261016.01\n20261015.01\n",
		"", "CURRENT\n", "20261016.01\x00\n", "20261016.12345678\n",
	} {
		f.Add(data)
	}
	f.Fuzz(func(t *testing.T, data string) {
		if len(data) > 128 {
			t.Skip()
		}
		root := t.TempDir()
		if err := os.WriteFile(filepath.Join(root, "CURRENT"), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		version, err := readCurrent(context.Background(), root)
		expectValid := strings.HasSuffix(data, "\n") &&
			strings.Count(data, "\n") == 1 &&
			validBundleVersion(strings.TrimSuffix(data, "\n"))
		if expectValid {
			if err != nil || version+"\n" != data {
				t.Fatalf("valid pointer rejected: %q -> %q, %v", data, version, err)
			}
		} else if !errors.Is(err, ErrInvalidCurrent) {
			t.Fatalf("invalid pointer accepted: %q -> %q, %v", data, version, err)
		}
	})
}
