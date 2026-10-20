package versionmgr

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const gcRecordName = ".gc-quarantine.json"

// GCSnapshot comes from trusted Updater retirement/activation state, never from
// user input, directory mtimes, or sorting version names. Missing state denies GC.
type GCSnapshot struct {
	BackupVersion string
	RetiredAt     time.Time
}

// GCFiles performs one explicitly requested GC stage. Root and NodeID are fixed
// deployment configuration. Snapshot must return fresh, coherent metadata.
//
// A single Updater must exclusively own Root. All activation decisions and
// CURRENT writes must coordinate with GC; currentWriteMu only serializes this
// process's GC stages and CURRENT writes. Server must never issue new leases for
// a retired version. This is not a transaction spanning Server and filesystem.
type GCFiles struct {
	Root     string
	NodeID   string
	Policy   GCPolicy
	Snapshot func(context.Context, string) (GCSnapshot, error)
}

type gcRecord struct {
	Version       string    `json:"version"`
	NodeID        string    `json:"node_id"`
	RetiredAt     time.Time `json:"retired_at"`
	QuarantinedAt time.Time `json:"quarantined_at"`
}

// Quarantine moves releases/version into .trash/version and durably records the
// move. An error after rename leaves the directory isolated; a missing record
// deliberately prevents automatic deletion, including after restart.
func (g GCFiles) Quarantine(ctx context.Context, version string) error {
	return g.stage(ctx, version, Quarantine)
}

// Delete independently refreshes all authorization and requires a valid durable
// quarantine record. A new instance can safely resume this stage after restart.
func (g GCFiles) Delete(ctx context.Context, version string) error {
	return g.stage(ctx, version, Delete)
}

func gcError(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrGCUnverified, fmt.Sprintf(format, args...))
}

func (g GCFiles) stage(ctx context.Context, version string, phase GCPhase) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("%w: %w", ErrGCUnverified, err)
	}
	if !validBundleVersion(version) || !validGCNodeID(g.NodeID) || g.Snapshot == nil {
		return gcError("version, configured node and trusted metadata provider required")
	}
	currentWriteMu.Lock()
	defer currentWriteMu.Unlock()
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("%w: %w", ErrGCUnverified, err)
	}
	canonical, err := currentRoot(g.Root)
	if err != nil {
		return fmt.Errorf("GC root: %w", err)
	}
	rootInfo, err := os.Lstat(canonical)
	if err != nil {
		return fmt.Errorf("inspect GC root: %w", err)
	}
	root, err := os.OpenRoot(canonical)
	if err != nil {
		return fmt.Errorf("anchor GC root: %w", err)
	}
	defer root.Close()
	releases, releasesInfo, err := gcOpenDir(root, "releases")
	if err != nil {
		return err
	}
	defer releases.Close()
	trash, trashInfo, err := gcOpenDir(root, ".trash")
	if err != nil {
		return err
	}
	defer trash.Close()
	parent := releases
	if phase == Delete {
		parent = trash
	}
	candidate, candidateInfo, err := gcOpenDir(parent, version)
	if err != nil {
		return err
	}
	defer candidate.Close()
	current, pointerInfo, err := gcReadCurrent(root)
	if err != nil {
		return err
	}
	snapshot, err := g.Snapshot(ctx, version)
	if err != nil {
		return fmt.Errorf("%w: retirement snapshot: %w", ErrGCUnverified, err)
	}
	now := time.Now()
	record := gcRecord{Version: version, NodeID: g.NodeID, RetiredAt: snapshot.RetiredAt, QuarantinedAt: now}
	var recordInfo os.FileInfo
	if phase == Delete {
		record, recordInfo, err = gcReadRecord(candidate)
		if err != nil {
			return err
		}
		if record.Version != version || record.NodeID != g.NodeID ||
			!record.RetiredAt.Equal(snapshot.RetiredAt) || record.QuarantinedAt.IsZero() ||
			record.QuarantinedAt.After(now) || record.RetiredAt.After(record.QuarantinedAt) {
			return gcError("invalid quarantine record metadata")
		}
	} else if err := gcAbsent(candidate, gcRecordName); err != nil {
		return err
	}
	request := GCRequest{NodeID: g.NodeID, Version: version, CurrentVersion: current,
		BackupVersion: snapshot.BackupVersion, RetiredAt: snapshot.RetiredAt,
		QuarantinedAt: record.QuarantinedAt, Phase: phase}
	// Capture directory identity before querying Server as well as afterwards.
	verify := func() error {
		info, err := os.Lstat(canonical)
		if err != nil || !info.IsDir() || !os.SameFile(rootInfo, info) {
			return gcError("bundle root changed")
		}
		for _, entry := range []struct {
			root *os.Root
			name string
			info os.FileInfo
		}{{root, ".", rootInfo}, {root, "releases", releasesInfo}, {root, ".trash", trashInfo}, {parent, version, candidateInfo}} {
			info, err := entry.root.Lstat(entry.name)
			if err != nil || !info.IsDir() || !os.SameFile(entry.info, info) {
				return gcError("directory changed: %s", entry.name)
			}
		}
		value, info, err := gcReadCurrent(root)
		if err != nil {
			return err
		}
		if value != current || !os.SameFile(pointerInfo, info) {
			return gcError("CURRENT changed during GC")
		}
		if phase == Quarantine {
			if err := gcAbsent(trash, version); err != nil {
				return err
			}
			return gcAbsent(candidate, gcRecordName)
		}
		latest, info, err := gcReadRecord(candidate)
		if err != nil {
			return err
		}
		if latest != record || !os.SameFile(recordInfo, info) {
			return gcError("quarantine record changed")
		}
		return nil
	}
	if err := verify(); err != nil {
		return err
	}
	if err := g.Policy.Check(ctx, request, now); err != nil {
		return err
	}
	latest, err := g.Snapshot(ctx, version)
	if err != nil {
		return fmt.Errorf("%w: refresh retirement snapshot: %w", ErrGCUnverified, err)
	}
	if latest.BackupVersion != snapshot.BackupVersion || !latest.RetiredAt.Equal(snapshot.RetiredAt) {
		return gcError("retirement snapshot changed during GC")
	}
	if err := verify(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("%w: %w", ErrGCUnverified, err)
	}
	if phase == Delete {
		if err := trash.RemoveAll(version); err != nil {
			return fmt.Errorf("remove quarantined version: %w", err)
		}
		return gcSyncDir(trash)
	}
	if err := root.Rename(filepath.Join("releases", version), filepath.Join(".trash", version)); err != nil {
		return fmt.Errorf("quarantine version: %w", err)
	}
	record.QuarantinedAt = time.Now()
	if err := gcSyncDir(releases); err != nil {
		return fmt.Errorf("version isolated but releases durability unconfirmed: %w", err)
	}
	if err := gcSyncDir(trash); err != nil {
		return fmt.Errorf("version isolated but trash durability unconfirmed: %w", err)
	}
	if err := gcWriteRecord(ctx, candidate, record); err != nil {
		return fmt.Errorf("version isolated but quarantine record unavailable: %w", err)
	}
	return nil
}

func validGCNodeID(node string) bool {
	if strings.TrimSpace(node) == "" || len(node) > 128 || !utf8.ValidString(node) {
		return false
	}
	for _, r := range node {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func gcOpenDir(parent *os.Root, name string) (*os.Root, os.FileInfo, error) {
	info, err := parent.Lstat(name)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: inspect directory %s: %w", ErrGCUnverified, name, err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, nil, gcError("real directory required: %s", name)
	}
	root, err := parent.OpenRoot(name)
	if err != nil {
		return nil, nil, fmt.Errorf("anchor directory %s: %w", name, err)
	}
	opened, err := root.Stat(".")
	if err != nil || !os.SameFile(info, opened) {
		_ = root.Close()
		return nil, nil, gcError("directory changed while opening: %s", name)
	}
	return root, info, nil
}

func gcAbsent(root *os.Root, name string) error {
	_, err := root.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("%w: inspect reserved destination %s: %w", ErrGCUnverified, name, err)
	}
	return gcError("reserved destination already exists: %s", name)
}

func gcReadRegular(root *os.Root, name string, limit int64) ([]byte, os.FileInfo, error) {
	info, err := root.Lstat(name)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: inspect %s: %w", ErrGCUnverified, name, err)
	}
	if !info.Mode().IsRegular() {
		return nil, nil, gcError("regular file required: %s", name)
	}
	f, err := root.Open(name)
	if err != nil {
		return nil, nil, fmt.Errorf("open GC file %s: %w", name, err)
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		return nil, nil, gcError("file changed while opening: %s", name)
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, nil, fmt.Errorf("read GC file %s: %w", name, err)
	}
	if int64(len(data)) > limit {
		return nil, nil, gcError("oversized file: %s", name)
	}
	return data, info, nil
}

func gcReadCurrent(root *os.Root) (string, os.FileInfo, error) {
	data, info, err := gcReadRegular(root, "CURRENT", 18)
	if err != nil {
		return "", nil, err
	}
	value := string(data)
	if !strings.HasSuffix(value, "\n") || !validBundleVersion(strings.TrimSuffix(value, "\n")) {
		return "", nil, gcError("invalid CURRENT")
	}
	return strings.TrimSuffix(value, "\n"), info, nil
}

func gcReadRecord(root *os.Root) (gcRecord, os.FileInfo, error) {
	data, info, err := gcReadRegular(root, gcRecordName, 2048)
	if err != nil {
		return gcRecord{}, nil, err
	}
	var record gcRecord
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil {
		return record, nil, fmt.Errorf("%w: decode quarantine record: %w", ErrGCUnverified, err)
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return record, nil, gcError("trailing quarantine record data")
	}
	return record, info, nil
}

func gcWriteRecord(ctx context.Context, root *os.Root, record gcRecord) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	name := ".gc-record-" + rand.Text()
	f, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("create quarantine record: %w", err)
	}
	defer func() { _ = root.Remove(name) }()
	if err := json.NewEncoder(f).Encode(record); err != nil {
		_ = f.Close()
		return fmt.Errorf("write quarantine record: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("sync quarantine record: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close quarantine record: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := gcAbsent(root, gcRecordName); err != nil {
		return err
	}
	if err := root.Rename(name, gcRecordName); err != nil {
		return fmt.Errorf("publish quarantine record: %w", err)
	}
	return gcSyncDir(root)
}
