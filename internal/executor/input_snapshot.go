package executor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const snapshotName = ".scanner-input.json"
const maxSnapshotFile int64 = 16 << 30
const maxSnapshotTotal int64 = 32 << 30

var snapshotAlias = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$`)

// inputSnapshot is produced by the operator-run Linux collector. Its hashes
// detect incomplete transfers and changed inputs, not the authenticity of a host.
type inputSnapshot struct {
	SchemaVersion int               `json:"schemaVersion"`
	Source        string            `json:"source"`
	Kind          string            `json:"kind"`
	CollectedAt   string            `json:"collectedAt"`
	Files         map[string]string `json:"files"`
}

func verifyInputSnapshot(ctx context.Context, input, kind string) (string, error) {
	root := input
	manifest := filepath.Join(input, snapshotName)
	if kind == "image-archive" {
		root = filepath.Dir(input)
		manifest = input + snapshotName
	}
	info, err := os.Lstat(manifest)
	if os.IsNotExist(err) {
		return "", nil // Manually prepared inputs remain supported.
	}
	if err != nil || !info.Mode().IsRegular() || info.Size() > 2<<20 {
		return "", fmt.Errorf("invalid input snapshot metadata")
	}
	file, err := os.Open(manifest)
	if err != nil {
		return "", fmt.Errorf("open input snapshot: %w", err)
	}
	data, err := io.ReadAll(io.LimitReader(file, (2<<20)+1))
	file.Close()
	if err != nil {
		return "", fmt.Errorf("read input snapshot: %w", err)
	}
	if len(data) > 2<<20 {
		return "", fmt.Errorf("oversized input snapshot metadata")
	}
	snapshot, err := decodeInputSnapshot(data, kind)
	if err != nil {
		return "", err
	}
	if kind == "image-archive" && (len(snapshot.Files) != 1 || snapshot.Files[filepath.Base(input)] == "") {
		return "", fmt.Errorf("image snapshot must describe only its archive")
	}
	var total int64
	seen := 0
	check := func(path string) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		name := filepath.ToSlash(relative)
		expected, ok := snapshot.Files[name]
		info, err := os.Lstat(path)
		if err != nil || !ok || !info.Mode().IsRegular() || info.Size() > maxSnapshotFile {
			return fmt.Errorf("input snapshot contains missing, unexpected or invalid files")
		}
		total += info.Size()
		if total > maxSnapshotTotal {
			return fmt.Errorf("input snapshot exceeds 32 GiB")
		}
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		defer file.Close()
		hash := sha256.New()
		buffer := make([]byte, 128<<10)
		var copied int64
		for {
			if err := ctx.Err(); err != nil {
				return err
			}
			n, readErr := file.Read(buffer)
			copied += int64(n)
			if copied > maxSnapshotFile || copied > info.Size() {
				return fmt.Errorf("input snapshot file grew during verification")
			}
			hash.Write(buffer[:n])
			if readErr == io.EOF {
				break
			}
			if readErr != nil {
				return readErr
			}
		}
		if copied != info.Size() || hex.EncodeToString(hash.Sum(nil)) != expected {
			return fmt.Errorf("input snapshot hash mismatch; transfer or collect the full input again")
		}
		seen++
		return nil
	}
	if kind == "image-archive" {
		err = check(input)
	} else {
		err = filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if err := ctx.Err(); err != nil {
				return err
			}
			if entry.IsDir() || path == manifest {
				return nil
			}
			return check(path)
		})
	}
	if err != nil {
		return "", fmt.Errorf("verify input snapshot: %w", err)
	}
	if seen != len(snapshot.Files) {
		return "", fmt.Errorf("input snapshot is incomplete")
	}
	digest := sha256.Sum256(data)
	return fmt.Sprintf("离线快照：%s；采集时间：%s；清单 SHA-256：%x。结果仅覆盖本次采集文件。", snapshot.Source, snapshot.CollectedAt, digest), nil
}

func decodeInputSnapshot(data []byte, kind string) (inputSnapshot, error) {
	var snapshot inputSnapshot
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&snapshot); err != nil {
		return snapshot, fmt.Errorf("invalid input snapshot JSON")
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF || snapshot.SchemaVersion != 1 || snapshot.Kind != kind || !snapshotAlias.MatchString(snapshot.Source) || len(snapshot.Files) == 0 || len(snapshot.Files) > 10000 {
		return snapshot, fmt.Errorf("invalid input snapshot schema, kind or file count")
	}
	if _, err := time.Parse(time.RFC3339, snapshot.CollectedAt); err != nil {
		return snapshot, fmt.Errorf("invalid snapshot collection time")
	}
	for name, digest := range snapshot.Files {
		if !filepath.IsLocal(name) || strings.ContainsAny(name, "\\:\x00") || filepath.ToSlash(filepath.Clean(name)) != name || name == snapshotName || len(digest) != 64 {
			return snapshot, fmt.Errorf("invalid input snapshot path or SHA-256")
		}
		if _, err := hex.DecodeString(digest); err != nil || digest != strings.ToLower(digest) {
			return snapshot, fmt.Errorf("invalid input snapshot SHA-256")
		}
	}
	return snapshot, nil
}
