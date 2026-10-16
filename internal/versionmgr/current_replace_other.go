//go:build !windows

package versionmgr

import (
	"context"
	"os"
)

func replaceCurrent(ctx context.Context, temp, current string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return os.Rename(temp, current)
}

func syncCurrentDir(root string) error {
	d, err := os.Open(root)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
