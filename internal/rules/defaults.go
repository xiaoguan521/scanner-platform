package rules

import (
	"archive/zip"
	"bytes"
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
func (m *Manager) PrepareDefault(ctx context.Context, version, trivyCache string) (Bundle, error) {
	manifest := Manifest{Version: version, Engines: []string{"nuclei"}, Files: map[string]string{}}
	files := BaselineTemplates()
	sources := map[string]string{}
	if trivyCache != "" {
		manifest.Engines = append(manifest.Engines, "trivy")
		for _, name := range []string{"db/trivy.db", "db/metadata.json"} {
			source := filepath.Join(trivyCache, filepath.FromSlash(name))
			input, err := os.Open(source)
			if err != nil {
				return Bundle{}, err
			}
			digest := sha256.New()
			_, err = io.Copy(digest, input)
			input.Close()
			if err != nil {
				return Bundle{}, err
			}
			path := "trivy/" + name
			manifest.Files[path] = hex.EncodeToString(digest.Sum(nil))
			sources[path] = source
		}
	}
	for name, data := range files {
		manifest.Files[name] = hashBytes(data)
	}
	var buffer bytes.Buffer
	archive := zip.NewWriter(&buffer)
	for name, data := range files {
		output, err := archive.Create(name)
		if err != nil {
			return Bundle{}, err
		}
		if _, err = output.Write(data); err != nil {
			return Bundle{}, err
		}
	}
	for name, path := range sources {
		if err := ctx.Err(); err != nil {
			return Bundle{}, err
		}
		output, err := archive.Create(name)
		if err != nil {
			return Bundle{}, err
		}
		input, err := os.Open(path)
		if err != nil {
			return Bundle{}, err
		}
		_, err = io.Copy(output, input)
		input.Close()
		if err != nil {
			return Bundle{}, err
		}
	}
	data, _ := json.Marshal(manifest)
	output, err := archive.Create("manifest.json")
	if err != nil {
		return Bundle{}, err
	}
	if _, err = output.Write(data); err != nil {
		return Bundle{}, err
	}
	if err := archive.Close(); err != nil {
		return Bundle{}, err
	}
	if buffer.Len() > MaxArchive {
		return Bundle{}, fmt.Errorf("default rules exceed ZIP import limit")
	}
	return m.Import(ctx, buffer.Bytes())
}
