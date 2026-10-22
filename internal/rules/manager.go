// Package rules is owned by sec-updater. Server only queues jobs and stores catalog metadata.
package rules

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"scanner-platform/internal/versionmgr"
)

// MaxArchive is the limit for the Server multipart path. That path stores the
// payload in the local job database, so it intentionally remains small.
const MaxArchive = 256 << 20

// MaxSignedArchive is the limit for signed packages handled directly by the
// Updater. These packages are streamed through a private temporary file and
// never pass through the Server job BLOB or JSON API. Keep this separate from
// MaxArchive so raising the offline package limit cannot accidentally make the
// web upload path retain multi-gigabyte payloads in memory.
const MaxSignedArchive = 2 << 30
const MaxRuleFile = 4 << 30
const MaxExpanded = 8 << 30

var versionPattern = regexp.MustCompile(`^[0-9]{8}\.[0-9]{2,8}$`)

type Manifest struct {
	Version             string                         `json:"version"`
	Engines             []string                       `json:"engines"`
	EngineCompatibility map[string]EngineCompatibility `json:"engine_compatibility,omitempty"`
	Files               map[string]string              `json:"files"`
}
type Bundle struct {
	Version           string   `json:"version"`
	Engines           []string `json:"engines"`
	Channel           string   `json:"channel"`
	ManifestSHA256    string   `json:"manifestSha256"`
	PublishedAt       string   `json:"publishedAt"`
	IsCurrent         bool     `json:"isCurrent"`
	IsBackup          bool     `json:"isBackup"`
	InUseByTasks      int      `json:"inUseByTasks"`
	IntegrityVerified bool     `json:"integrityVerified"`
	SignatureVerified bool     `json:"signatureVerified"`
	EngineValidated   bool     `json:"engineValidated"`
}
type Job struct {
	ID             string `json:"id"`
	Kind           string `json:"kind"`
	Status         string `json:"status"`
	URL            string `json:"url,omitempty"`
	ExpectedSHA256 string `json:"expectedSha256,omitempty"`
	Version        string `json:"version,omitempty"`
	Rollback       bool   `json:"rollback"`
	Message        string `json:"message"`
	CreatedAt      string `json:"createdAt"`
	CompletedAt    string `json:"completedAt"`
	Bundle         []byte `json:"bundle,omitempty"`
	NodeID         string `json:"nodeId,omitempty"`
}
type Report struct {
	JobID   string   `json:"jobId"`
	NodeID  string   `json:"nodeId"`
	Status  string   `json:"status"`
	Message string   `json:"message"`
	Version string   `json:"version"`
	Bundles []Bundle `json:"bundles"`
}
type Manager struct {
	Root        string
	Client      *http.Client
	trustedKeys []ed25519.PublicKey
	trustedRoot string
	preparedMu  sync.Mutex
	prepared    map[string]preparedRelease
}

func ValidateVersion(version string) bool { return versionPattern.MatchString(version) }
func ValidateSource(raw, expected string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || len(raw) > 2048 {
		return fmt.Errorf("规则更新地址须为无凭据的 HTTPS ZIP 地址")
	}
	decoded, err := hex.DecodeString(expected)
	if err != nil || len(decoded) != 32 {
		return fmt.Errorf("请提供规则包的 SHA-256")
	}
	return nil
}
func validFile(name string, engines map[string]bool) bool {
	if name == "" || len(name) > 240 || strings.ContainsAny(name, "\\:\x00") || path.Clean(name) != name || !filepath.IsLocal(filepath.FromSlash(name)) {
		return false
	}
	parts := strings.Split(name, "/")
	if len(parts) < 2 || !engines[parts[0]] {
		return false
	}
	for _, part := range parts {
		if part == "" || part == "." || part == ".." || strings.HasSuffix(part, ".") || strings.HasSuffix(part, " ") {
			return false
		}
	}
	return true
}
func decodeManifest(data []byte) (Manifest, error) {
	var m Manifest
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(&m) != nil || d.Decode(new(any)) != io.EOF || !ValidateVersion(m.Version) || len(m.Files) == 0 || len(m.Files) > 50000 || len(m.Engines) == 0 || len(m.Engines) > 2 {
		return m, fmt.Errorf("manifest.json 格式或版本无效")
	}
	engines := map[string]bool{}
	for _, engine := range m.Engines {
		if (engine != "nuclei" && engine != "trivy") || engines[engine] {
			return m, fmt.Errorf("规则引擎无效")
		}
		engines[engine] = true
	}
	for name, hash := range m.Files {
		raw, err := hex.DecodeString(hash)
		if !validFile(name, engines) || err != nil || len(raw) != 32 {
			return m, fmt.Errorf("manifest 文件路径或哈希无效")
		}
	}
	return m, nil
}
func hashBytes(data []byte) string { h := sha256.Sum256(data); return hex.EncodeToString(h[:]) }
func (m *Manager) initialize() error {
	root, err := filepath.Abs(m.Root)
	if err != nil {
		return err
	}
	m.Root = root
	if err := os.MkdirAll(filepath.Join(root, "releases"), 0700); err != nil {
		return err
	}
	for _, p := range []string{root, filepath.Join(root, "releases")} {
		info, err := os.Lstat(p)
		if err != nil {
			return err
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("规则目录不能是符号链接")
		}
	}
	return nil
}
func readLimited(r io.Reader, max int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > max {
		return nil, fmt.Errorf("规则文件过大")
	}
	return data, nil
}

func (m *Manager) Import(ctx context.Context, data []byte) (Bundle, error) {
	if err := ctx.Err(); err != nil {
		return Bundle{}, err
	}
	if err := m.requireTrust(); err != nil {
		return Bundle{}, err
	}
	if len(data) == 0 || len(data) > MaxArchive {
		return Bundle{}, fmt.Errorf("ZIP 大小须在 1 字节至 256 MiB 之间")
	}
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return Bundle{}, fmt.Errorf("无效的 ZIP 规则包")
	}
	return m.importArchive(ctx, zr)
}

// ImportFile imports a signed ZIP directly from a local regular file. It is
// the offline path for the large vulnerability-data artifact; the file is
// never read into a []byte or placed in the Server's SQLite job table.
func (m *Manager) ImportFile(ctx context.Context, archivePath string) (Bundle, error) {
	if err := ctx.Err(); err != nil {
		return Bundle{}, err
	}
	if err := m.requireTrust(); err != nil {
		return Bundle{}, err
	}
	info, err := os.Lstat(archivePath)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return Bundle{}, fmt.Errorf("签名 ZIP 必须是普通非符号链接文件")
	}
	if info.Size() <= 0 || info.Size() > MaxSignedArchive {
		return Bundle{}, fmt.Errorf("签名 ZIP 大小须在 1 字节至 2 GiB 之间")
	}
	input, err := os.Open(archivePath)
	if err != nil {
		return Bundle{}, err
	}
	defer input.Close()
	opened, err := input.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) || opened.Size() != info.Size() {
		return Bundle{}, fmt.Errorf("签名 ZIP 在打开时发生变化")
	}
	zr, err := zip.NewReader(input, info.Size())
	if err != nil {
		return Bundle{}, fmt.Errorf("无效的 ZIP 规则包")
	}
	return m.importArchive(ctx, zr)
}

func (m *Manager) importArchive(ctx context.Context, zr *zip.Reader) (Bundle, error) {
	prefix := ""
	if !hasArchiveEntry(zr, manifestName) {
		var err error
		prefix, err = findArtifactReleasePrefix(zr)
		if err != nil {
			return Bundle{}, err
		}
	}
	return m.importArchivePrefix(ctx, zr, prefix)
}

func hasArchiveEntry(zr *zip.Reader, name string) bool {
	for _, f := range zr.File {
		if f.Name == name && !f.FileInfo().IsDir() {
			return true
		}
	}
	return false
}

// findArtifactReleasePrefix recognizes the directory-tree ZIP emitted by the
// offline GitHub Actions workflow. Only one version directory may be present;
// the outer CURRENT, README and SHA256SUMS files are not rule payloads.
func findArtifactReleasePrefix(zr *zip.Reader) (string, error) {
	const root = "vuln-data/releases/"
	prefixes := map[string]bool{}
	for _, f := range zr.File {
		if f.FileInfo().IsDir() || !strings.HasPrefix(f.Name, root) || !strings.HasSuffix(f.Name, "/"+manifestName) {
			continue
		}
		version := strings.TrimSuffix(strings.TrimPrefix(f.Name, root), "/"+manifestName)
		if ValidateVersion(version) {
			prefixes[root+version+"/"] = true
		}
	}
	if len(prefixes) != 1 {
		return "", fmt.Errorf("ZIP 顶层缺少 manifest.json，且未找到唯一的已签名规则版本目录")
	}
	for prefix := range prefixes {
		return prefix, nil
	}
	return "", fmt.Errorf("ZIP 规则版本目录无效")
}

func (m *Manager) importArchivePrefix(ctx context.Context, zr *zip.Reader, prefix string) (Bundle, error) {
	if err := ctx.Err(); err != nil {
		return Bundle{}, err
	}
	if err := m.initialize(); err != nil {
		return Bundle{}, err
	}
	if len(zr.File) > 100001 {
		return Bundle{}, fmt.Errorf("ZIP 文件数量过多")
	}
	entries := map[string]*zip.File{}
	var manifestData, signatureData []byte
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		name := f.Name
		if prefix != "" {
			if !strings.HasPrefix(name, prefix) {
				continue
			}
			name = strings.TrimPrefix(name, prefix)
			if name == "" {
				continue
			}
		}
		if !f.Mode().IsRegular() || entries[name] != nil {
			return Bundle{}, fmt.Errorf("规则包含链接或重复文件")
		}
		entries[name] = f
		if name == manifestName || name == signatureName {
			r, err := f.Open()
			if err != nil {
				return Bundle{}, err
			}
			limit := int64(8 << 20)
			if name == signatureName {
				limit = ed25519.SignatureSize
			}
			value, readErr := readLimited(r, limit)
			r.Close()
			if readErr != nil {
				return Bundle{}, readErr
			}
			if name == manifestName {
				manifestData = value
			} else {
				signatureData = value
			}
		}
	}
	if err := m.verifySignature(manifestData, signatureData); err != nil {
		return Bundle{}, err
	}
	manifest, err := decodeManifest(manifestData)
	if err != nil {
		return Bundle{}, err
	}
	if prefix != "" {
		pathVersion := strings.TrimSuffix(strings.TrimPrefix(prefix, "vuln-data/releases/"), "/")
		if manifest.Version != pathVersion {
			return Bundle{}, fmt.Errorf("规则版本目录与 manifest 不一致")
		}
	}
	if len(entries) != len(manifest.Files)+2 {
		return Bundle{}, fmt.Errorf("ZIP 文件与 manifest 不一致")
	}
	stage, err := os.MkdirTemp(m.Root, ".import-")
	if err != nil {
		return Bundle{}, err
	}
	defer os.RemoveAll(stage)
	var total uint64
	names := make([]string, 0, len(manifest.Files))
	for name := range manifest.Files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if err := ctx.Err(); err != nil {
			return Bundle{}, err
		}
		f := entries[name]
		if f == nil || f.UncompressedSize64 > MaxRuleFile {
			return Bundle{}, fmt.Errorf("规则文件缺失或过大")
		}
		if total >= MaxExpanded {
			return Bundle{}, fmt.Errorf("规则包解压大小超限")
		}
		remaining := uint64(MaxExpanded) - total
		copyLimit := uint64(MaxRuleFile) + 1
		if remaining < copyLimit-1 {
			copyLimit = remaining + 1
		}
		r, err := f.Open()
		if err != nil {
			return Bundle{}, err
		}
		dest := filepath.Join(stage, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(dest), 0700); err != nil {
			r.Close()
			return Bundle{}, err
		}
		output, err := os.OpenFile(dest, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			r.Close()
			return Bundle{}, err
		}
		digest := sha256.New()
		count, copyErr := io.Copy(io.MultiWriter(output, digest), io.LimitReader(preparedReader{ctx, r}, int64(copyLimit)))
		r.Close()
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
		if count < 0 || uint64(count) > uint64(MaxRuleFile) || uint64(count) > remaining {
			return Bundle{}, fmt.Errorf("规则包解压大小超限")
		}
		total += uint64(count)
		if !strings.EqualFold(hex.EncodeToString(digest.Sum(nil)), manifest.Files[name]) {
			return Bundle{}, fmt.Errorf("规则文件 SHA-256 校验失败或大小超限")
		}

	}
	return m.publishStage(ctx, stage, manifest, manifestData, signatureData)
}

// publishStage is shared by ZIP import and Updater's streaming local DB
// preparation. Neither path changes CURRENT until a separate activation.
func (m *Manager) publishStage(ctx context.Context, stage string, manifest Manifest, manifestData, signatureData []byte) (Bundle, error) {
	if err := ctx.Err(); err != nil {
		return Bundle{}, err
	}
	output, err := os.OpenFile(filepath.Join(stage, "manifest.json"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return Bundle{}, err
	}
	_, writeErr := output.Write(manifestData)
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
	if signatureData != nil {
		output, err := os.OpenFile(filepath.Join(stage, signatureName), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return Bundle{}, err
		}
		_, writeErr := output.Write(signatureData)
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
	}
	destination := filepath.Join(m.Root, "releases", manifest.Version)
	if _, err := os.Lstat(destination); err == nil {
		oldSignature, sigErr := readRuleMetadata(destination, signatureName, ed25519.SignatureSize)
		if sigErr != nil && !(errors.Is(sigErr, os.ErrNotExist) && signatureData == nil) {
			return Bundle{}, fmt.Errorf("版本已存在，签名不可覆盖或补写")
		}
		if !bytes.Equal(oldSignature, signatureData) {
			return Bundle{}, fmt.Errorf("版本已存在，签名不可覆盖")
		}
		old, err := m.inspect(ctx, manifest.Version)
		if err != nil {
			return Bundle{}, err
		}
		if old.ManifestSHA256 != hashBytes(manifestData) {
			return Bundle{}, fmt.Errorf("版本已存在，内容不可覆盖")
		}
		return old, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return Bundle{}, err
	}
	if err := os.Rename(stage, destination); err != nil {
		return Bundle{}, err
	}
	return m.inspect(ctx, manifest.Version)
}

func (m *Manager) inspect(ctx context.Context, version string) (Bundle, error) {
	return m.inspectBundle(ctx, version, false)
}

func (m *Manager) inspectBundle(ctx context.Context, version string, requireSignature bool) (Bundle, error) {
	if err := ctx.Err(); err != nil {
		return Bundle{}, err
	}
	if !ValidateVersion(version) {
		return Bundle{}, fmt.Errorf("版本无效")
	}
	dir := filepath.Join(m.Root, "releases", version)
	info, err := os.Lstat(dir)
	if err != nil {
		return Bundle{}, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return Bundle{}, fmt.Errorf("规则版本目录无效")
	}
	data, err := readRuleMetadata(dir, manifestName, 8<<20)
	if err != nil {
		return Bundle{}, err
	}
	signatureVerified := false
	if requireSignature || len(m.trustedKeys) != 0 {
		signature, sigErr := readRuleMetadata(dir, signatureName, ed25519.SignatureSize)
		if sigErr == nil {
			if err := m.verifySignature(data, signature); err != nil {
				return Bundle{}, err
			}
			signatureVerified = true
		} else if requireSignature || !errors.Is(sigErr, os.ErrNotExist) {
			return Bundle{}, fmt.Errorf("规则 manifest 签名读取失败: %w", sigErr)
		}
	}
	manifest, err := decodeManifest(data)
	if err != nil || manifest.Version != version {
		return Bundle{}, fmt.Errorf("规则 manifest 无效")
	}
	for name, expected := range manifest.Files {
		if err := ctx.Err(); err != nil {
			return Bundle{}, err
		}
		dest := filepath.Join(dir, filepath.FromSlash(name))
		rel := filepath.FromSlash(name)
		for p := rel; p != "."; p = filepath.Dir(p) {
			info, err := os.Lstat(filepath.Join(dir, p))
			if err != nil || info.Mode()&os.ModeSymlink != 0 {
				return Bundle{}, fmt.Errorf("规则路径缺失或包含链接")
			}
		}
		info, err := os.Stat(dest)
		if err != nil || !info.Mode().IsRegular() || info.Size() > MaxRuleFile {
			return Bundle{}, fmt.Errorf("规则文件无效")
		}
		input, err := os.Open(dest)
		if err != nil {
			return Bundle{}, err
		}
		digest := sha256.New()
		_, copyErr := io.Copy(digest, io.LimitReader(input, MaxRuleFile+1))
		input.Close()
		if copyErr != nil || !strings.EqualFold(hex.EncodeToString(digest.Sum(nil)), expected) {
			return Bundle{}, fmt.Errorf("已存规则文件 SHA-256 校验失败")
		}

	}
	engineValidated, err := validateEngineCompatibility(manifest, dir)
	if err != nil {
		return Bundle{}, err
	}
	return Bundle{Version: version, Engines: manifest.Engines, Channel: "local", ManifestSHA256: hashBytes(data), PublishedAt: info.ModTime().UTC().Format(time.RFC3339Nano), IntegrityVerified: true, SignatureVerified: signatureVerified, EngineValidated: engineValidated}, nil
}

// Inspect verifies an already installed version without creating any directory.
// This is the read-only entrypoint used by Worker.
func (m *Manager) Inspect(ctx context.Context, version string) (Bundle, error) {
	return m.inspect(ctx, version)
}
func older(a, b string) bool {
	ap := strings.Split(a, ".")
	bp := strings.Split(b, ".")
	if ap[0] != bp[0] {
		return ap[0] < bp[0]
	}
	ai, _ := strconv.Atoi(ap[1])
	bi, _ := strconv.Atoi(bp[1])
	return ai < bi
}
func (m *Manager) Activate(ctx context.Context, version string, rollback bool) error {
	if err := m.requireTrust(); err != nil {
		return err
	}
	if err := m.initialize(); err != nil {
		return err
	}
	bundle, err := m.inspectBundle(ctx, version, true)
	if err != nil {
		return err
	}
	if !bundle.SignatureVerified {
		return fmt.Errorf("普通激活要求有效的 manifest Ed25519 签名")
	}
	if !bundle.EngineValidated {
		return fmt.Errorf("普通激活要求规则包声明并通过当前引擎兼容性校验")
	}
	return m.activateCurrent(ctx, version, rollback)
}

func (m *Manager) activateCurrent(ctx context.Context, version string, rollback bool) error {
	current, err := versionmgr.ReadLocalCurrent(ctx, m.Root)
	if err != nil && !errors.Is(err, versionmgr.ErrWaitingForRules) {
		return err
	}
	if current != "" && older(version, current) && !rollback {
		return fmt.Errorf("较旧版本必须通过显式回滚操作激活")
	}
	return versionmgr.WriteLocalCurrent(ctx, m.Root, version)
}
func (m *Manager) List(ctx context.Context) ([]Bundle, error) {
	if err := m.initialize(); err != nil {
		return nil, err
	}
	current, err := versionmgr.ReadLocalCurrent(ctx, m.Root)
	if err != nil && !errors.Is(err, versionmgr.ErrWaitingForRules) {
		return nil, err
	}
	entries, err := os.ReadDir(filepath.Join(m.Root, "releases"))
	if err != nil {
		return nil, err
	}
	out := []Bundle{}
	for _, entry := range entries {
		if !ValidateVersion(entry.Name()) {
			continue
		}
		bundle, err := m.inspect(ctx, entry.Name())
		if err != nil {
			return nil, err
		}
		bundle.IsCurrent = bundle.Version == current
		out = append(out, bundle)
	}
	sort.Slice(out, func(i, j int) bool { return older(out[j].Version, out[i].Version) })
	for i := range out {
		if !out[i].IsCurrent {
			out[i].IsBackup = true
			break
		}
	}
	return out, nil
}
func (m *Manager) Fetch(ctx context.Context, raw, expected string) (Bundle, error) {
	if err := m.requireTrust(); err != nil {
		return Bundle{}, err
	}
	if err := ValidateSource(raw, expected); err != nil {
		return Bundle{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return Bundle{}, err
	}
	client := m.Client
	if client == nil {
		client = &http.Client{Timeout: time.Hour, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	copyClient := *client
	copyClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	client = &copyClient
	response, err := client.Do(req)
	if err != nil {
		return Bundle{}, fmt.Errorf("规则包下载失败")
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return Bundle{}, fmt.Errorf("规则源返回 HTTP %d", response.StatusCode)
	}
	if response.ContentLength > MaxSignedArchive {
		return Bundle{}, fmt.Errorf("下载 ZIP 超过 2 GiB 限制")
	}
	if err := m.initialize(); err != nil {
		return Bundle{}, err
	}
	temporary, err := os.CreateTemp(m.Root, ".fetch-*.zip")
	if err != nil {
		return Bundle{}, err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	digest := sha256.New()
	count, copyErr := io.Copy(io.MultiWriter(temporary, digest), io.LimitReader(preparedReader{ctx, response.Body}, MaxSignedArchive+1))
	syncErr := temporary.Sync()
	closeErr := temporary.Close()
	if copyErr != nil {
		return Bundle{}, copyErr
	}
	if syncErr != nil {
		return Bundle{}, syncErr
	}
	if closeErr != nil {
		return Bundle{}, closeErr
	}
	if count <= 0 || count > MaxSignedArchive {
		return Bundle{}, fmt.Errorf("下载 ZIP 大小须在 1 字节至 2 GiB 之间")
	}
	if !strings.EqualFold(hex.EncodeToString(digest.Sum(nil)), expected) {
		return Bundle{}, fmt.Errorf("下载包 SHA-256 校验失败")
	}
	return m.ImportFile(ctx, temporaryPath)
}
