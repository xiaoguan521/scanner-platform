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
	"strings"
)

type preparedRelease struct {
	root   string
	digest string
	owner  *Manager
}

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

// addCuratedTemplates merges externally curated, read-only JSON Nuclei
// templates (produced by scripts/curate_nuclei_templates.py in CI) into the
// bundle. It applies structural safety checks here; the Worker re-validates
// every template against the full read-only profile before executing it.
func addCuratedTemplates(files map[string][]byte, dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("read curated templates: %w", err)
	}
	added := 0
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		full := filepath.Join(dir, entry.Name())
		info, err := os.Lstat(full)
		if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 64<<10 {
			return fmt.Errorf("curated template %q is missing, a symlink, empty, or too large", entry.Name())
		}
		data, err := os.ReadFile(full)
		if err != nil {
			return err
		}
		var doc struct {
			ID   string `json:"id"`
			HTTP []any  `json:"http"`
		}
		if err := json.Unmarshal(data, &doc); err != nil {
			return fmt.Errorf("curated template %q is not valid JSON: %w", entry.Name(), err)
		}
		if !customRuleID.MatchString(doc.ID) || len(doc.HTTP) != 1 {
			return fmt.Errorf("curated template %q is not the supported baseline shape", entry.Name())
		}
		name := "nuclei/templates/" + doc.ID + ".json"
		if _, exists := files[name]; exists {
			return fmt.Errorf("curated template id %q duplicates an existing template", doc.ID)
		}
		files[name] = data
		added++
		if added > 5000 {
			return fmt.Errorf("curated template set exceeds 5000 templates")
		}
	}
	return nil
}

// PrepareDefault installs a bundle built by Updater from the original baseline
// templates and the database downloaded using the pinned Trivy binary.
func (m *Manager) PrepareDefault(ctx context.Context, version, trivyCache string, includeJava bool, templatesDir ...string) (Bundle, error) {
	m.preparedMu.Lock()
	defer m.preparedMu.Unlock()
	delete(m.prepared, version)
	if !ValidateVersion(version) {
		return Bundle{}, fmt.Errorf("invalid prepared rule version")
	}
	if err := m.initialize(); err != nil {
		return Bundle{}, err
	}
	if _, err := os.Lstat(filepath.Join(m.Root, "releases", version)); err == nil {
		return Bundle{}, fmt.Errorf("prepared version already exists")
	} else if !os.IsNotExist(err) {
		return Bundle{}, err
	}
	manifest := Manifest{Version: version, Engines: []string{"nuclei"}, Files: map[string]string{}}
	files := BaselineTemplates()
	if len(templatesDir) > 0 && templatesDir[0] != "" {
		if err := addCuratedTemplates(files, templatesDir[0]); err != nil {
			return Bundle{}, err
		}
	}
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
	manifest.EngineCompatibility = PinnedEngineCompatibility(manifest.Engines, includeJava)
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
	bundle, err := m.publishStage(ctx, stage, manifest, data, nil)
	if err != nil {
		return Bundle{}, err
	}
	root, err := canonicalRuleRoot(m.Root)
	if err != nil {
		return Bundle{}, err
	}
	if m.prepared == nil {
		m.prepared = make(map[string]preparedRelease)
	}
	m.prepared[version] = preparedRelease{root: root, digest: bundle.ManifestSHA256, owner: m}
	return bundle, nil
}

// ActivatePreparedLocal consumes a one-use capability created only by this
// Manager's successful local preparation. It does not trust historical unsigned
// imports, survive restart, or enable ordinary unsigned activation.
func (m *Manager) ActivatePreparedLocal(ctx context.Context, version string) error {
	m.preparedMu.Lock()
	defer m.preparedMu.Unlock()
	prepared, ok := m.prepared[version]
	delete(m.prepared, version)
	if !ok || prepared.owner != m {
		return fmt.Errorf("version was not freshly prepared by this Manager")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	root, err := canonicalRuleRoot(m.Root)
	if err != nil || root != prepared.root {
		return fmt.Errorf("prepared rule root changed")
	}
	bundle, err := m.Inspect(ctx, version)
	if err != nil {
		return err
	}
	if bundle.ManifestSHA256 != prepared.digest {
		return fmt.Errorf("prepared manifest changed")
	}
	if !bundle.EngineValidated {
		return fmt.Errorf("prepared rules do not match the current engine compatibility")
	}
	return m.activateCurrent(ctx, version, false)
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
