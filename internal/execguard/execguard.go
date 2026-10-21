// Package execguard contains the small, portable checks used before a
// privileged process starts a trusted executable.
package execguard

import (
	"errors"
	"os"
	"path/filepath"
)

// ValidatePinnedExecutable accepts only a canonical, regular executable whose
// file and every parent directory are not writable by group or other users.
// The check deliberately rejects symlink traversal so a later replacement
// cannot redirect a trusted supervisor to an unexpected binary.
func ValidatePinnedExecutable(filename string) error {
	if filename == "" || !filepath.IsAbs(filename) || filepath.Clean(filename) != filename {
		return errors.New("executable path must be absolute and canonical")
	}
	resolved, err := filepath.EvalSymlinks(filename)
	if err != nil || resolved != filename {
		return errors.New("executable path must not traverse symlinks")
	}
	info, err := os.Lstat(filename)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 || info.Mode()&0111 == 0 {
		return errors.New("executable must be a pinned non-writable regular file")
	}
	for directory := filepath.Dir(filename); ; directory = filepath.Dir(directory) {
		directoryInfo, directoryErr := os.Lstat(directory)
		if directoryErr != nil || !directoryInfo.IsDir() || directoryInfo.Mode()&os.ModeSymlink != 0 || directoryInfo.Mode().Perm()&0022 != 0 {
			return errors.New("executable parent directories must be non-writable")
		}
		parent := filepath.Dir(directory)
		if parent == directory {
			break
		}
	}
	return nil
}
