//go:build windows

package versionmgr

import (
	"context"
	"errors"
	"os"
	"syscall"
)

func replaceCurrent(ctx context.Context, temp, current string) error {
	return renameWithRetry(ctx, temp, current, os.Rename, retryableWindowsRename)
}

// Windows can reject replacement while a reader holds CURRENT without
// FILE_SHARE_DELETE. Retry only known sharing/locking/access errors, for a
// bounded number of attempts. Never remove CURRENT before retrying.
func retryableWindowsRename(err error) bool {
	return errors.Is(err, syscall.Errno(32)) || // ERROR_SHARING_VIOLATION
		errors.Is(err, syscall.Errno(33)) || // ERROR_LOCK_VIOLATION
		errors.Is(err, syscall.Errno(5)) // ERROR_ACCESS_DENIED may be a sharing lock
}

func syncCurrentDir(root string) error {
	// Windows MoveFileEx(REPLACE_EXISTING) does not provide durable directory
	// fsync through os.File.Sync on directories. The file itself is synced
	// prior to rename. Power-loss durability still requires Windows lab proof.
	return nil
}
