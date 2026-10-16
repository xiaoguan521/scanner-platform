package versionmgr

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

var (
	// ErrWaitingForRules means there is no CURRENT pointer yet.
	// Workers should report WAITING_FOR_RULES and back off without scanning.
	ErrWaitingForRules = errors.New("CURRENT not present; waiting for rules")
	ErrInvalidCurrent  = errors.New("invalid CURRENT pointer")
)

// This guards simultaneous writes by the same Updater process only. Production
// deployments must additionally guarantee a single Updater writer per bundle
// root, and must keep the directory inaccessible to untrusted processes.
var currentWriteMu sync.Mutex

// currentRoot resolves a trusted, absolute, non-symlink bundle directory.
// Its ancestors can contain OS-managed symlinks (e.g. macOS /var).
func currentRoot(root string) (string, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return "", fmt.Errorf("%w: bundle root must be a clean absolute path", ErrInvalidCurrent)
	}
	info, err := os.Lstat(root)
	if err != nil {
		return "", fmt.Errorf("%w: stat bundle root: %w", ErrInvalidCurrent, err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("%w: bundle root must be a real directory", ErrInvalidCurrent)
	}
	canonical, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", fmt.Errorf("%w: resolve bundle root: %w", ErrInvalidCurrent, err)
	}
	return canonical, nil
}

func checkCurrentEntry(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("%w: inspect CURRENT: %w", ErrInvalidCurrent, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%w: CURRENT must be a regular file", ErrInvalidCurrent)
	}
	return nil
}

// readCurrent reads only a single newline-terminated bundle version from a
// regular file. It intentionally does not activate anything.
func readCurrent(ctx context.Context, root string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	root, err := currentRoot(root)
	if err != nil {
		return "", err
	}
	path := filepath.Join(root, "CURRENT")
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return "", ErrWaitingForRules
	}
	if err != nil {
		return "", fmt.Errorf("%w: stat CURRENT: %w", ErrInvalidCurrent, err)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("%w: CURRENT must be a regular file", ErrInvalidCurrent)
	}
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("%w: open CURRENT: %w", ErrInvalidCurrent, err)
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !opened.Mode().IsRegular() {
		return "", fmt.Errorf("%w: CURRENT changed during open: %v", ErrInvalidCurrent, err)
	}
	// Guard against oversized and multi-line pointer files.
	data, err := io.ReadAll(io.LimitReader(f, 20))
	if err != nil {
		return "", fmt.Errorf("%w: read CURRENT: %w", ErrInvalidCurrent, err)
	}
	value := string(data)
	if !strings.HasSuffix(value, "\n") || strings.Count(value, "\n") != 1 {
		return "", fmt.Errorf("%w: expected one newline-terminated version", ErrInvalidCurrent)
	}
	version := strings.TrimSuffix(value, "\n")
	if !validBundleVersion(version) {
		return "", fmt.Errorf("%w: invalid version", ErrInvalidCurrent)
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	return version, nil
}

// writeCurrentAtomic is deliberately NOT exported. Signature/hash/engine
// compatibility/anti-rollback checks do not exist yet, so exposing a
// production activation API here would bypass mandatory validation.
// This primitive is only for internal tests and a future verified Updater.
func writeCurrentAtomic(ctx context.Context, root, version string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !validBundleVersion(version) {
		return fmt.Errorf("%w: invalid target version", ErrInvalidCurrent)
	}
	currentWriteMu.Lock()
	defer currentWriteMu.Unlock()

	root, err := currentRoot(root)
	if err != nil {
		return err
	}
	path := filepath.Join(root, "CURRENT")
	if err := checkCurrentEntry(path); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(root, ".CURRENT-*")
	if err != nil {
		return fmt.Errorf("create CURRENT temporary file: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() {
		// Nothing to delete after successful rename; on failure, remove the
		// incomplete temporary file without touching an existing CURRENT.
		if tmpPath != "" {
			_ = os.Remove(tmpPath)
		}
	}()
	if err := tmp.Chmod(0600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod temporary CURRENT: %w", err)
	}
	if _, err := io.WriteString(tmp, version+"\n"); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temporary CURRENT: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("fsync temporary CURRENT: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temporary CURRENT: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := checkCurrentEntry(path); err != nil {
		return err
	}
	if err := replaceCurrent(ctx, tmpPath, path); err != nil {
		return fmt.Errorf("replace CURRENT: %w", err)
	}
	tmpPath = ""
	// For POSIX, sync the parent directory after the rename. On Windows,
	// the directory fsync behavior differs and is verified separately.
	if err := syncCurrentDir(root); err != nil {
		return fmt.Errorf("CURRENT was replaced but directory durability is unconfirmed: %w", err)
	}
	return nil
}
