package executor

import (
	"context"
	"io"
	"os"
	"scanner-platform/internal/executor/engineflags"
)

// DownloadTrivyDB is called only by Updater's explicit preparation command.
// Scan runners never invoke download flags.
func DownloadTrivyDB(ctx context.Context, binDir, cacheDir, runtimeDir string) error {
	if err := os.MkdirAll(runtimeDir, 0700); err != nil {
		return err
	}
	r := Runner{BinDir: binDir}
	return runProcess(ctx, r.binary("trivy"), engineflags.TrivyDownloadArgs(cacheDir), runtimeDir, io.Discard)
}
