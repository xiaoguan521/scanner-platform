//go:build windows

package versionmgr

import "os"

// Windows directory fsync durability still requires platform lab validation,
// matching CURRENT's existing documented limitation.
func gcSyncDir(_ *os.Root) error { return nil }
