package versionmgr

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestCurrentRoundTripAndReplace(t *testing.T) {
	root := t.TempDir()
	ctx := context.Background()
	if _, err := readCurrent(ctx, root); !errors.Is(err, ErrWaitingForRules) {
		t.Fatalf("missing CURRENT must wait: %v", err)
	}
	for _, version := range []string{"20261016.01", "20261016.02", "20261016.03"} {
		if err := writeCurrentAtomic(ctx, root, version); err != nil {
			t.Fatal(err)
		}
		got, err := readCurrent(ctx, root)
		if err != nil || got != version {
			t.Fatalf("read CURRENT = %q, %v; want %s", got, err, version)
		}
		raw, err := os.ReadFile(filepath.Join(root, "CURRENT"))
		if err != nil || string(raw) != version+"\n" {
			t.Fatalf("non-plaintext CURRENT: %q, %v", raw, err)
		}
	}
	matches, err := filepath.Glob(filepath.Join(root, ".CURRENT-*"))
	if err != nil || len(matches) != 0 {
		t.Fatalf("temporary files leaked: %v, %v", matches, err)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(filepath.Join(root, "CURRENT"))
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatalf("CURRENT permissions: %v, %v", info, err)
		}
	}
}

func TestCurrentReadersSeeOnlyWholeVersions(t *testing.T) {
	root := t.TempDir()
	ctx := context.Background()
	if err := writeCurrentAtomic(ctx, root, "20261016.01"); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	stop := make(chan struct{})
	failures := make(chan error, 1)
	var reads atomic.Int64
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				version, err := readCurrent(ctx, root)
				if err != nil || (version != "20261016.01" && version != "20261016.02") {
					select {
					case failures <- fmt.Errorf("reader observed partial CURRENT %q: %w", version, err):
					default:
					}
					return
				}
				reads.Add(1)
			}
		}()
	}
	for i := 0; i < 60; i++ {
		version := "20261016.02"
		if i%2 == 1 {
			version = "20261016.01"
		}
		if err := writeCurrentAtomic(ctx, root, version); err != nil {
			close(stop)
			wg.Wait()
			t.Fatal(err)
		}
	}
	close(stop)
	wg.Wait()
	select {
	case err := <-failures:
		t.Fatal(err)
	default:
	}
	if reads.Load() == 0 {
		t.Fatal("readers never observed CURRENT")
	}
}

func TestCurrentInvalidVersionFailsWithoutChangingPointer(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	if err := writeCurrentAtomic(ctx, root, "20261016.01"); err != nil {
		t.Fatal(err)
	}
	for _, candidate := range []string{
		"", "../20261016.02", "20261016.02/other", "20261016.02\n",
		"20261016.02\x00", "2026.01", "20261016.20261016.2",
	} {
		if err := writeCurrentAtomic(ctx, root, candidate); !errors.Is(err, ErrInvalidCurrent) {
			t.Fatalf("unsafe version %q was accepted: %v", candidate, err)
		}
		got, err := readCurrent(ctx, root)
		if err != nil || got != "20261016.01" {
			t.Fatalf("invalid version replaced CURRENT: %s, %v", got, err)
		}
	}
}

func TestReadCurrentRejectsCorruptionAndSymlink(t *testing.T) {
	ctx := context.Background()
	for _, contents := range []string{
		"20261016.01", "20261016.01\n20261016.02\n",
		"20261016.01\r\n", strings.Repeat("9", 50), "bad\n",
	} {
		t.Run(fmt.Sprintf("bad-%q", contents[:min(len(contents), 12)]), func(t *testing.T) {
			root := t.TempDir()
			if err := os.WriteFile(filepath.Join(root, "CURRENT"), []byte(contents), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := readCurrent(ctx, root); !errors.Is(err, ErrInvalidCurrent) {
				t.Fatalf("invalid content accepted: %q: %v", contents, err)
			}
		})
	}
	root := t.TempDir()
	real := filepath.Join(root, "victim")
	if err := os.WriteFile(real, []byte("20261016.01\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, filepath.Join(root, "CURRENT")); err != nil {
		t.Skipf("symlink not supported in this environment: %v", err)
	}
	if _, err := readCurrent(ctx, root); !errors.Is(err, ErrInvalidCurrent) {
		t.Fatalf("CURRENT symlink accepted: %v", err)
	}
	if err := writeCurrentAtomic(ctx, root, "20261016.02"); !errors.Is(err, ErrInvalidCurrent) {
		t.Fatalf("CURRENT symlink overwritten: %v", err)
	}
	b, err := os.ReadFile(real)
	if err != nil || string(b) != "20261016.01\n" {
		t.Fatalf("victim modified: %q, %v", b, err)
	}
}

func TestWriteCurrentRejectsDirectoryAndRootSymlink(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "CURRENT"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := writeCurrentAtomic(ctx, root, "20261016.01"); !errors.Is(err, ErrInvalidCurrent) {
		t.Fatalf("directory as CURRENT accepted: %v", err)
	}
	alias := filepath.Join(t.TempDir(), "bundle-symlink")
	if err := os.Symlink(root, alias); err != nil {
		t.Skipf("symlink not supported: %v", err)
	}
	if _, err := readCurrent(ctx, alias); !errors.Is(err, ErrInvalidCurrent) {
		t.Fatalf("symlink bundle root accepted: %v", err)
	}
	if err := writeCurrentAtomic(ctx, alias, "20261016.01"); !errors.Is(err, ErrInvalidCurrent) {
		t.Fatalf("symlink root allowed: %v", err)
	}
}

func TestCurrentCancelledContextLeavesPointerAlone(t *testing.T) {
	root := t.TempDir()
	if err := writeCurrentAtomic(context.Background(), root, "20261016.01"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := writeCurrentAtomic(ctx, root, "20261016.02"); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled write accepted: %v", err)
	}
	if _, err := readCurrent(ctx, root); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled read accepted: %v", err)
	}
	if got, _ := readCurrent(context.Background(), root); got != "20261016.01" {
		t.Fatalf("cancelled write modified CURRENT: %q", got)
	}
}

func TestRenameRetryHandlesTransientAndPermanentFailures(t *testing.T) {
	ctx := context.Background()
	temporary := errors.New("sharing violation")
	for _, tc := range []struct {
		name        string
		failures    int
		permanent   bool
		wantCalls   int
		shouldError bool
	}{
		{"success after sharing locks", 2, false, 3, false},
		{"never succeeds", 6, false, 5, true},
		{"permanent failure", 1, true, 1, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			rename := func(_, _ string) error {
				calls++
				if tc.permanent {
					return errors.New("permission denied")
				}
				if calls <= tc.failures {
					return temporary
				}
				return nil
			}
			err := renameWithRetry(ctx, "from", "to", rename, func(err error) bool {
				return errors.Is(err, temporary)
			})
			if calls != tc.wantCalls || (err != nil) != tc.shouldError {
				t.Fatalf("calls=%d err=%v", calls, err)
			}
		})
	}
}

func TestRenameRetryHonorsCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	calls := 0
	err := renameWithRetry(ctx, "from", "to", func(_, _ string) error {
		calls++
		return nil
	}, func(error) bool { return true })
	if !errors.Is(err, context.Canceled) || calls != 0 {
		t.Fatalf("cancelled rename attempted: %d, %v", calls, err)
	}
}

func TestCurrentRequiresAbsoluteCleanRoot(t *testing.T) {
	if _, err := readCurrent(context.Background(), "relative"); !errors.Is(err, ErrInvalidCurrent) {
		t.Fatalf("relative root accepted: %v", err)
	}
	if err := writeCurrentAtomic(context.Background(), "../tmp", "20261016.01"); !errors.Is(err, ErrInvalidCurrent) {
		t.Fatalf("relative root accepted for write: %v", err)
	}
}

func TestCurrentReadOnlyDoesNotCreateFiles(t *testing.T) {
	root := t.TempDir()
	if _, err := readCurrent(context.Background(), root); !errors.Is(err, ErrWaitingForRules) {
		t.Fatal(err)
	}
	items, err := os.ReadDir(root)
	if err != nil || len(items) != 0 {
		t.Fatalf("read created files: %v, %v", items, err)
	}
}

func TestRetryBoundedEvenWhenContextNeverCancelled(t *testing.T) {
	started := time.Now()
	err := renameWithRetry(context.Background(), "", "", func(_, _ string) error {
		return errors.New("retryable")
	}, func(error) bool { return true })
	if err == nil || time.Since(started) > 2*time.Second {
		t.Fatalf("unbounded retries: %v", err)
	}
}
