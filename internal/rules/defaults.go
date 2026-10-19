package rules

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// BaselineTemplates are original read-only checks, not an exploit template pack.
func BaselineTemplates() map[string][]byte {
	definitions := []struct{ id, name, header, severity string }{
		{"baseline-nosniff", "响应缺少 X-Content-Type-Options", "x-content-type-options:", "low"},
		{"baseline-csp", "响应缺少 Content-Security-Policy", "content-security-policy:", "info"},
		{"baseline-frame-options", "响应缺少 X-Frame-Options", "x-frame-options:", "info"},
		{"baseline-server-header", "响应公开 Server 软件标识", "server:", "info"},
	}
	files := map[string][]byte{}
	for _, d := range definitions {
		document := map[string]any{"id": d.id, "info": map[string]any{"name": d.name, "author": "scanner-platform", "severity": d.severity, "description": "只读 HTTP 基线检查；缺少响应头需结合服务用途判断，不代表已确认可利用漏洞。", "tags": "baseline,passive"}, "http": []any{map[string]any{"method": "GET", "path": []string{"{{BaseURL}}"}, "matchers": []any{map[string]any{"type": "word", "part": "header", "words": []string{d.header}, "case-insensitive": true, "negative": d.id != "baseline-server-header"}}}}}
		files["nuclei/templates/"+d.id+".json"], _ = json.MarshalIndent(document, "", "  ")
	}
	return files
}

// PrepareDefault installs a bundle built by Updater from the original baseline
// templates and the database downloaded using the pinned Trivy binary.
func (m *Manager) PrepareDefault(ctx context.Context, version, trivyCache string, includeJava bool) (Bundle, error) {
	if !ValidateVersion(version) {
		return Bundle{}, fmt.Errorf("invalid prepared rule version")
	}
	if err := m.initialize(); err != nil {
		return Bundle{}, err
	}
	manifest := Manifest{Version: version, Engines: []string{"nuclei"}, Files: map[string]string{}}
	files := BaselineTemplates()
	sources := map[string]string{}
	if trivyCache != "" {
		info, err := os.Lstat(trivyCache)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return Bundle{}, fmt.Errorf("database cache root must be a concrete directory")
		}
		manifest.Engines = append(manifest.Engines, "trivy")
		names := []string{"db/trivy.db", "db/metadata.json"}
		if includeJava {
			names = append(names, "java-db/trivy-java.db", "java-db/metadata.json")
		}
		for _, name := range names {
			source := filepath.Join(trivyCache, filepath.FromSlash(name))
			// The cache is an explicit local input, not a link into rules/assets.
			for p := filepath.FromSlash(name); p != "."; p = filepath.Dir(p) {
				info, err := os.Lstat(filepath.Join(trivyCache, p))
				if err != nil || info.Mode()&os.ModeSymlink != 0 {
					return Bundle{}, fmt.Errorf("database cache is missing or contains a symlink")
				}
			}
			sources["trivy/"+name] = source
		}
	} else if includeJava {
		return Bundle{}, fmt.Errorf("Java preparation requires a Trivy DB cache")
	}
	// Large Java indexes cannot fit in the web ZIP limit. Copy and hash them
	// directly into a private staging directory, never into a byte slice or DB.
	stage, err := os.MkdirTemp(m.Root, ".prepare-")
	if err != nil {
		return Bundle{}, err
	}
	defer os.RemoveAll(stage)
	var total int64
	for name, data := range files {
		if err := ctx.Err(); err != nil {
			return Bundle{}, err
		}
		destination := filepath.Join(stage, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(destination), 0700); err != nil {
			return Bundle{}, err
		}
		output, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return Bundle{}, err
		}
		_, writeErr := output.Write(data)
		syncErr := output.Sync()
		closeErr := output.Close()
		if writeErr != nil {
			return Bundle{}, writeErr
		}
		if syncErr != nil {
			return Bundle{}, syncErr
		}
		if closeErr != nil {
			return Bundle{}, closeErr
		}
		manifest.Files[name] = hashBytes(data)
		total += int64(len(data))
	}
	for name, source := range sources {
		if err := ctx.Err(); err != nil {
			return Bundle{}, err
		}
		info, err := os.Lstat(source)
		if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > MaxRuleFile || info.Size()+total > MaxExpanded {
			return Bundle{}, fmt.Errorf("database cache file is invalid or exceeds size limits")
		}
		destination := filepath.Join(stage, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(destination), 0700); err != nil {
			return Bundle{}, err
		}
		input, err := os.Open(source)
		if err != nil {
			return Bundle{}, err
		}
		output, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			input.Close()
			return Bundle{}, err
		}
		digest := sha256.New()
		count, copyErr := io.Copy(io.MultiWriter(output, digest), io.LimitReader(preparedReader{ctx, input}, MaxRuleFile+1))
		input.Close()
		syncErr := output.Sync()
		closeErr := output.Close()
		if copyErr != nil {
			return Bundle{}, copyErr
		}
		if syncErr != nil {
			return Bundle{}, syncErr
		}
		if closeErr != nil {
			return Bundle{}, closeErr
		}
		after, err := os.Lstat(source)
		if err != nil || !os.SameFile(info, after) || after.ModTime() != info.ModTime() || count != info.Size() {
			return Bundle{}, fmt.Errorf("database cache changed during preparation")
		}
		total += count
		manifest.Files[name] = hex.EncodeToString(digest.Sum(nil))
	}
	data, _ := json.Marshal(manifest)
	if _, err := decodeManifest(data); err != nil {
		return Bundle{}, err
	}
	return m.publishStage(ctx, stage, manifest, data)
}

type preparedReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r preparedReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(p)
}
