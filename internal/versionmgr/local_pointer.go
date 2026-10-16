package versionmgr

import "context"

// WriteLocalCurrent is used only by the early-development Updater after file
// integrity validation. It makes no claim about signatures or engine validation.
func WriteLocalCurrent(ctx context.Context, root, version string) error {
	return writeCurrentAtomic(ctx, root, version)
}
func ReadLocalCurrent(ctx context.Context, root string) (string, error) {
	return readCurrent(ctx, root)
}
