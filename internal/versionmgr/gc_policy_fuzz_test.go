package versionmgr

import (
	"context"
	"strings"
	"testing"
)

// FuzzGCVersionNeverAuthorizesPathTraversal validates that an arbitrary
// server-supplied version identifier cannot bypass GC eligibility checks.
func FuzzGCVersionNeverAuthorizesPathTraversal(f *testing.F) {
	for _, version := range []string{
		"20261015.01", "20261015.01/other", "../20261015.01",
		"20261015.01\\..\\", ".", "", "20261016.02", "20261015.12345",
	} {
		f.Add(version)
	}
	f.Fuzz(func(t *testing.T, candidate string) {
		p, r, now := fixture()
		p.Running = runningCounter(func(context.Context, string, string) (int, error) { return 0, nil })
		r.Version = candidate
		err := p.Check(context.Background(), r, now)
		if err == nil && (!validBundleVersion(candidate) ||
			strings.ContainsAny(candidate, "/\\") || candidate == r.CurrentVersion ||
			candidate == r.BackupVersion) {
			t.Fatalf("unsafe candidate accepted: %q", candidate)
		}
	})
}
