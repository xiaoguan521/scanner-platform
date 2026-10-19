package executor

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLinuxReleaseDoesNotSubstituteVendorFeeds(t *testing.T) {
	for _, test := range []struct {
		name, release string
		ok            bool
	}{
		{"centos7", "ID=centos\nNAME=\"CentOS Linux\"\nVERSION_ID=\"7\"\n", true},
		{"debian", "ID=debian\nVERSION_ID=12\n", true},
		{"kylin", "ID=kylin\nID_LIKE=centos\nVERSION_ID=V10\n", false},
		{"neokylin", "ID=neokylin\nID_LIKE=rhel\nVERSION_ID=7\n", false},
		{"stream", "ID=centos\nNAME=\"CentOS Stream\"\nVERSION_ID=8\n", false},
		{"rhel10", "ID=rhel\nVERSION_ID=10.0\n", false},
		{"duplicate", "ID=kylin\nID=centos\nVERSION_ID=7\n", false},
		{"missing", "", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			if err := os.MkdirAll(filepath.Join(root, "etc"), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, "etc", "os-release"), []byte(test.release), 0600); err != nil {
				t.Fatal(err)
			}
			if err := validateLinuxRelease(root); (err == nil) != test.ok {
				t.Fatalf("coverage validation: %v", err)
			}
		})
	}
}

func FuzzLinuxRelease(f *testing.F) {
	f.Add([]byte("ID=centos\nVERSION_ID=7\n"))
	f.Add([]byte("ID=kylin\nID_LIKE=centos\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 64<<10 {
			t.Skip()
		}
		_ = checkLinuxRelease(data)
	})
}
