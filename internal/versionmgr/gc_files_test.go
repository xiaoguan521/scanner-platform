package versionmgr

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const gcOld = "20261015.01"

func gcFixture(t *testing.T) (GCFiles, *GCSnapshot, *int) {
	t.Helper()
	root := t.TempDir()
	for _, path := range []string{"releases", ".trash", filepath.Join("releases", gcOld)} {
		if err := os.Mkdir(filepath.Join(root, path), 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "releases", gcOld, "payload"), []byte("rules"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := WriteLocalCurrent(context.Background(), root, "20261016.02"); err != nil {
		t.Fatal(err)
	}
	snapshot := &GCSnapshot{BackupVersion: "20261016.01", RetiredAt: time.Now().UTC().Add(-3 * time.Hour)}
	calls := new(int)
	g := GCFiles{Root: root, NodeID: "worker-demo", Policy: GCPolicy{Grace: DefaultGCGrace}}
	g.Snapshot = func(_ context.Context, version string) (GCSnapshot, error) {
		if version != gcOld {
			t.Errorf("unexpected snapshot version %q", version)
		}
		return *snapshot, nil
	}
	g.Policy.Running = runningCounter(func(_ context.Context, node, version string) (int, error) {
		*calls++
		if node != "worker-demo" || version != gcOld {
			t.Errorf("unexpected Server query %q %q", node, version)
		}
		return 0, nil
	})
	return g, snapshot, calls
}

func gcExists(t *testing.T, root, parent string, want bool) {
	t.Helper()
	_, err := os.Lstat(filepath.Join(root, parent, gcOld))
	if want && err != nil || !want && !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("%s existence want %v: %v", parent, want, err)
	}
}

func TestGCFilesTwoStagesAndRestart(t *testing.T) {
	g, _, calls := gcFixture(t)
	if err := g.Quarantine(context.Background(), gcOld); err != nil {
		t.Fatal(err)
	}
	gcExists(t, g.Root, "releases", false)
	gcExists(t, g.Root, ".trash", true)
	if *calls != 1 {
		t.Fatalf("quarantine Server calls = %d", *calls)
	}
	// No process-local quarantine state is needed for restart recovery.
	restarted := GCFiles{Root: g.Root, NodeID: g.NodeID, Policy: g.Policy, Snapshot: g.Snapshot}
	if err := restarted.Delete(context.Background(), gcOld); err != nil {
		t.Fatal(err)
	}
	gcExists(t, g.Root, ".trash", false)
	if *calls != 2 {
		t.Fatalf("two stages Server calls = %d", *calls)
	}
}

func TestGCFilesServerFailureAndNewRunningTask(t *testing.T) {
	for _, phase := range []GCPhase{Quarantine, Delete} {
		for _, offline := range []bool{false, true} {
			t.Run(string(phase)+map[bool]string{true: "/offline", false: "/running"}[offline], func(t *testing.T) {
				g, _, _ := gcFixture(t)
				if phase == Delete {
					if err := g.Quarantine(context.Background(), gcOld); err != nil {
						t.Fatal(err)
					}
				}
				g.Policy.Running = runningCounter(func(context.Context, string, string) (int, error) {
					if offline {
						return 0, errors.New("Server unavailable")
					}
					return 1, nil
				})
				var err error
				parent := "releases"
				if phase == Delete {
					parent = ".trash"
					err = g.Delete(context.Background(), gcOld)
				} else {
					err = g.Quarantine(context.Background(), gcOld)
				}
				want := ErrGCInUse
				if offline {
					want = ErrGCUnverified
				}
				if !errors.Is(err, want) {
					t.Fatalf("want %v: %v", want, err)
				}
				gcExists(t, g.Root, parent, true)
			})
		}
	}
}

func TestGCFilesRefreshProtectionBetweenStages(t *testing.T) {
	for _, change := range []string{"current", "backup", "retired", "missing retired", "missing backup", "snapshot error"} {
		t.Run(change, func(t *testing.T) {
			g, snapshot, calls := gcFixture(t)
			if err := g.Quarantine(context.Background(), gcOld); err != nil {
				t.Fatal(err)
			}
			switch change {
			case "current":
				if err := WriteLocalCurrent(context.Background(), g.Root, gcOld); err != nil {
					t.Fatal(err)
				}
			case "backup":
				snapshot.BackupVersion = gcOld
			case "retired":
				snapshot.RetiredAt = time.Now().Add(-time.Minute)
			case "missing retired":
				snapshot.RetiredAt = time.Time{}
			case "missing backup":
				snapshot.BackupVersion = ""
			case "snapshot error":
				g.Snapshot = func(context.Context, string) (GCSnapshot, error) { return GCSnapshot{}, errors.New("unavailable") }
			}
			if err := g.Delete(context.Background(), gcOld); err == nil {
				t.Fatal("protected directory deleted")
			}
			gcExists(t, g.Root, ".trash", true)
			if *calls != 1 {
				t.Fatal("invalid snapshot reached Server")
			}
		})
	}
}

func TestGCFilesRetirementCannotUseMtime(t *testing.T) {
	for _, retired := range []time.Time{{}, time.Now().Add(-time.Hour), time.Now().Add(time.Hour)} {
		g, snapshot, calls := gcFixture(t)
		snapshot.RetiredAt = retired
		old := time.Now().Add(-24 * time.Hour)
		if err := os.Chtimes(filepath.Join(g.Root, "releases", gcOld), old, old); err != nil {
			t.Fatal(err)
		}
		if err := g.Quarantine(context.Background(), gcOld); err == nil {
			t.Fatal("unverified retirement accepted")
		}
		gcExists(t, g.Root, "releases", true)
		if *calls != 0 {
			t.Fatal("invalid retirement reached Server")
		}
	}
}

func TestGCFilesRechecksChangesDuringServerQuery(t *testing.T) {
	for _, phase := range []GCPhase{Quarantine, Delete} {
		for _, change := range []string{"current", "backup", "retired", "root", "releases", "trash", "candidate", "record", "destination", "cancel"} {
			t.Run(string(phase)+"/"+change, func(t *testing.T) {
				g, snapshot, _ := gcFixture(t)
				parent := "releases"
				if phase == Delete {
					if err := g.Quarantine(context.Background(), gcOld); err != nil {
						t.Fatal(err)
					}
					parent = ".trash"
				}
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				g.Policy.Running = runningCounter(func(context.Context, string, string) (int, error) {
					var err error
					switch change {
					case "current":
						err = os.WriteFile(filepath.Join(g.Root, "CURRENT"), []byte(gcOld+"\n"), 0600)
					case "backup":
						snapshot.BackupVersion = gcOld
					case "retired":
						snapshot.RetiredAt = snapshot.RetiredAt.Add(time.Second)
					case "root", "releases", "trash", "candidate":
						path := g.Root
						switch change {
						case "releases":
							path = filepath.Join(path, "releases")
						case "trash":
							path = filepath.Join(path, ".trash")
						case "candidate":
							path = filepath.Join(path, parent, gcOld)
						}
						// Keep the original in the fixture tree, including root replacement.
						moved := path + ".moved"
						if change == "root" {
							moved = filepath.Join(t.TempDir(), "original")
						}
						err = os.Rename(path, moved)
						if err == nil {
							err = os.Mkdir(path, 0700)
						}
					case "record":
						err = os.WriteFile(filepath.Join(g.Root, parent, gcOld, gcRecordName), []byte("{}"), 0600)
					case "destination":
						if phase == Delete {
							err = os.WriteFile(filepath.Join(g.Root, ".trash", gcOld, gcRecordName), []byte("{}"), 0600)
						} else {
							err = os.Mkdir(filepath.Join(g.Root, ".trash", gcOld), 0700)
						}
					case "cancel":
						cancel()
					}
					if err != nil {
						t.Fatal(err)
					}
					return 0, nil
				})
				var err error
				if phase == Delete {
					err = g.Delete(ctx, gcOld)
				} else {
					err = g.Quarantine(ctx, gcOld)
				}
				if err == nil {
					t.Fatal("change during Server query accepted")
				}
			})
		}
	}
}

func TestGCFilesRejectPathsSymlinksAndDestinations(t *testing.T) {
	for _, input := range []string{"../20261015.01", "20261015.01/child", `20261015.01\child`, "", ".", "20261015.01\n"} {
		g, _, calls := gcFixture(t)
		if err := g.Quarantine(context.Background(), input); err == nil {
			t.Fatalf("accepted path %q", input)
		}
		if *calls != 0 {
			t.Fatal("invalid input queried Server")
		}
	}
	for _, entry := range []string{"releases", ".trash", filepath.Join("releases", gcOld), "CURRENT"} {
		t.Run("symlink/"+entry, func(t *testing.T) {
			g, _, _ := gcFixture(t)
			path := filepath.Join(g.Root, entry)
			if err := os.Rename(path, path+".real"); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(path+".real", path); err != nil {
				t.Skipf("symlinks unavailable: %v", err)
			}
			if err := g.Quarantine(context.Background(), gcOld); err == nil {
				t.Fatal("accepted symlink")
			}
		})
	}
	for _, entry := range []string{filepath.Join(".trash", gcOld), filepath.Join("releases", gcOld, gcRecordName)} {
		t.Run("collision/"+entry, func(t *testing.T) {
			g, _, _ := gcFixture(t)
			path := filepath.Join(g.Root, entry)
			if err := os.WriteFile(path, []byte("keep"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := g.Quarantine(context.Background(), gcOld); err == nil {
				t.Fatal("overwrote collision")
			}
			data, err := os.ReadFile(path)
			if err != nil || string(data) != "keep" {
				t.Fatalf("collision changed: %q, %v", data, err)
			}
			gcExists(t, g.Root, "releases", true)
		})
	}
}

func TestGCFilesRejectDamagedQuarantineRecord(t *testing.T) {
	for _, damage := range []string{"missing", "json", "unknown field", "trailing", "oversized", "node", "version", "retired", "future", "zero", "symlink"} {
		t.Run(damage, func(t *testing.T) {
			g, _, calls := gcFixture(t)
			if err := g.Quarantine(context.Background(), gcOld); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(g.Root, ".trash", gcOld, gcRecordName)
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var record gcRecord
			if err := json.Unmarshal(data, &record); err != nil {
				t.Fatal(err)
			}
			switch damage {
			case "missing":
				err = os.Remove(path)
			case "json":
				data = []byte("broken")
			case "unknown field":
				data = []byte(strings.Replace(string(data), "{", `{"unexpected":true,`, 1))
			case "trailing":
				data = append(data, []byte("{}")...)
			case "oversized":
				data = []byte(strings.Repeat(" ", 2049))
			case "symlink":
				err = os.Rename(path, path+".real")
				if err == nil {
					err = os.Symlink(path+".real", path)
					if err != nil {
						t.Skipf("symlinks unavailable: %v", err)
					}
				}
			default:
				switch damage {
				case "node":
					record.NodeID = "other-node"
				case "version":
					record.Version = "20261015.02"
				case "retired":
					record.RetiredAt = record.RetiredAt.Add(time.Second)
				case "future":
					record.QuarantinedAt = time.Now().Add(time.Hour)
				case "zero":
					record.QuarantinedAt = time.Time{}
				}
				data, err = json.Marshal(record)
			}
			if err != nil {
				t.Fatal(err)
			}
			if damage != "missing" && damage != "symlink" {
				if err := os.WriteFile(path, data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err := g.Delete(context.Background(), gcOld); err == nil {
				t.Fatal("damaged quarantine record accepted")
			}
			gcExists(t, g.Root, ".trash", true)
			if *calls != 1 {
				t.Fatal("invalid record reached Server")
			}
		})
	}
}

type gcCancelAfterRename struct {
	context.Context
	cancel context.CancelFunc
	path   string
}

func (c gcCancelAfterRename) Err() error {
	if _, err := os.Stat(c.path); err == nil {
		c.cancel()
	}
	return c.Context.Err()
}

func TestGCFilesRecordFailureLeavesIsolatedDirectory(t *testing.T) {
	g, _, _ := gcFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	watch := gcCancelAfterRename{Context: ctx, cancel: cancel, path: filepath.Join(g.Root, ".trash", gcOld)}
	if err := g.Quarantine(watch, gcOld); !errors.Is(err, context.Canceled) {
		t.Fatalf("want record publication canceled: %v", err)
	}
	gcExists(t, g.Root, "releases", false)
	gcExists(t, g.Root, ".trash", true)
	if err := g.Delete(context.Background(), gcOld); err == nil {
		t.Fatal("isolated directory without durable record deleted")
	}
}

func TestGCFilesPreCanceledDoesNotMutate(t *testing.T) {
	g, _, calls := gcFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := g.Quarantine(ctx, gcOld); !errors.Is(err, context.Canceled) {
		t.Fatalf("want canceled: %v", err)
	}
	gcExists(t, g.Root, "releases", true)
	gcExists(t, g.Root, ".trash", false)
	if *calls != 0 {
		t.Fatal("canceled GC queried Server")
	}
	if err := g.Quarantine(context.Background(), gcOld); err != nil {
		t.Fatal(err)
	}
	if err := g.Delete(ctx, gcOld); !errors.Is(err, context.Canceled) {
		t.Fatalf("want canceled delete: %v", err)
	}
	gcExists(t, g.Root, ".trash", true)
}

func TestGCFilesRejectInvalidConfigurationAndMissingCurrent(t *testing.T) {
	for _, change := range []string{"node empty", "node blank", "node long", "node control", "node utf8", "snapshot", "relative root", "current missing"} {
		t.Run(change, func(t *testing.T) {
			g, _, calls := gcFixture(t)
			switch change {
			case "node empty":
				g.NodeID = ""
			case "node blank":
				g.NodeID = "   "
			case "node long":
				g.NodeID = strings.Repeat("n", 129)
			case "node control":
				g.NodeID = "node\n"
			case "node utf8":
				g.NodeID = string([]byte{0xff})
			case "snapshot":
				g.Snapshot = nil
			case "relative root":
				g.Root = "relative"
			case "current missing":
				if err := os.Remove(filepath.Join(g.Root, "CURRENT")); err != nil {
					t.Fatal(err)
				}
			}
			if err := g.Quarantine(context.Background(), gcOld); err == nil {
				t.Fatal("invalid configuration accepted")
			}
			if *calls != 0 {
				t.Fatal("invalid configuration queried Server")
			}
		})
	}
}

func TestGCFilesDeleteDoesNotFollowPayloadSymlink(t *testing.T) {
	g, _, _ := gcFixture(t)
	outside := t.TempDir()
	path := filepath.Join(outside, "keep")
	if err := os.WriteFile(path, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(g.Root, "releases", gcOld, "outside")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := g.Quarantine(context.Background(), gcOld); err != nil {
		t.Fatal(err)
	}
	if err := g.Delete(context.Background(), gcOld); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "keep" {
		t.Fatalf("payload symlink target changed: %q %v", data, err)
	}
}

func TestGCFilesSerializesCurrentWrite(t *testing.T) {
	g, _, _ := gcFixture(t)
	entered, release := make(chan struct{}), make(chan struct{})
	g.Policy.Running = runningCounter(func(context.Context, string, string) (int, error) {
		close(entered)
		<-release
		return 0, nil
	})
	gcDone := make(chan error, 1)
	go func() { gcDone <- g.Quarantine(context.Background(), gcOld) }()
	<-entered
	writeDone := make(chan error, 1)
	var attempted atomic.Bool
	go func() {
		attempted.Store(true)
		writeDone <- WriteLocalCurrent(context.Background(), g.Root, "20261016.03")
	}()
	for !attempted.Load() {
		time.Sleep(time.Millisecond)
	}
	select {
	case err := <-writeDone:
		close(release)
		t.Fatalf("CURRENT write bypassed GC mutex: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	if err := <-gcDone; err != nil {
		t.Fatal(err)
	}
	if err := <-writeDone; err != nil {
		t.Fatal(err)
	}
	version, err := ReadLocalCurrent(context.Background(), g.Root)
	if err != nil || version != "20261016.03" {
		t.Fatalf("CURRENT after serialized write: %q %v", version, err)
	}
}
