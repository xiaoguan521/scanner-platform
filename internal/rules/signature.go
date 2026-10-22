package rules

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const manifestName = "manifest.json"
const signatureName = "manifest.json.sig"
const maxTrustedKeys = 3

// NewVerifiedManager loads one deployment trust anchor from outside the rule
// tree. It remains the compatibility entrypoint for callers that have not yet
// adopted the repeatable key flag.
func NewVerifiedManager(root, keyPath string) (*Manager, error) {
	return NewVerifiedManagerWithKeys(root, []string{keyPath})
}

// NewVerifiedManagerWithKeys loads a bounded set of deployment trust anchors
// from outside the rule tree. Keeping both the retiring and replacement key
// during an explicit transition lets already published bundles continue to
// verify without allowing a bundle to introduce or replace trust. Keys are
// copied into private immutable process state; the files are never watched or
// re-read during verification.
func NewVerifiedManagerWithKeys(root string, keyPaths []string) (*Manager, error) {
	root, err := canonicalRuleRoot(root)
	if err != nil {
		return nil, fmt.Errorf("resolve rule root: %w", err)
	}
	if len(keyPaths) == 0 || len(keyPaths) > maxTrustedKeys {
		return nil, fmt.Errorf("trusted public key count must be between 1 and %d", maxTrustedKeys)
	}
	keys := make([]ed25519.PublicKey, 0, len(keyPaths))
	for _, keyPath := range keyPaths {
		key, err := loadTrustedPublicKey(root, keyPath)
		if err != nil {
			return nil, err
		}
		for _, existing := range keys {
			if bytes.Equal(existing, key) {
				return nil, fmt.Errorf("trusted public keys must be unique")
			}
		}
		keys = append(keys, key)
	}
	return &Manager{Root: root, trustedKeys: keys, trustedRoot: root}, nil
}

func loadTrustedPublicKey(root, keyPath string) (ed25519.PublicKey, error) {
	keyPath, err := filepath.Abs(keyPath)
	if err != nil {
		return nil, fmt.Errorf("resolve trusted public key path: %w", err)
	}
	info, err := os.Lstat(keyPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > 4096 {
		return nil, fmt.Errorf("trusted public key must be a regular non-symlink file of at most 4 KiB")
	}
	canonicalKey, err := filepath.EvalSymlinks(keyPath)
	if err != nil {
		return nil, fmt.Errorf("resolve trusted public key file: %w", err)
	}
	rel, err := filepath.Rel(root, canonicalKey)
	if err != nil || rel == "." || filepath.IsLocal(rel) {
		return nil, fmt.Errorf("trusted public key must be outside the rule root")
	}
	// A lexical relative-path check alone misses case aliases on filesystems
	// where EvalSymlinks preserves spelling. Compare actual ancestor identity.
	rootInfo, rootErr := os.Stat(root)
	if rootErr != nil && !errors.Is(rootErr, os.ErrNotExist) {
		return nil, fmt.Errorf("inspect rule root for public key separation: %w", rootErr)
	}
	if rootErr == nil {
		for parent := filepath.Dir(canonicalKey); ; parent = filepath.Dir(parent) {
			parentInfo, err := os.Stat(parent)
			if err != nil {
				return nil, fmt.Errorf("inspect trusted public key parent: %w", err)
			}
			if os.SameFile(rootInfo, parentInfo) {
				return nil, fmt.Errorf("trusted public key must be outside the rule root")
			}
			if filepath.Dir(parent) == parent {
				break
			}
		}
	}
	f, err := os.Open(keyPath)
	if err != nil {
		return nil, fmt.Errorf("open trusted public key file: %w", err)
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		return nil, fmt.Errorf("trusted public key file changed while opening")
	}
	data, err := readLimited(f, 4096)
	if err != nil {
		return nil, fmt.Errorf("read trusted public key file: %w", err)
	}
	data = bytes.TrimSpace(data)
	block, rest := pem.Decode(data)
	if !bytes.HasPrefix(data, []byte("-----BEGIN PUBLIC KEY-----")) || block == nil ||
		block.Type != "PUBLIC KEY" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 ||
		bytes.Count(data, []byte("-----BEGIN ")) != 1 || bytes.Count(data, []byte("-----END ")) != 1 {
		return nil, fmt.Errorf("trusted public key must contain exactly one PUBLIC KEY PEM block")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("trusted public key is not a valid PKIX public key")
	}
	key, ok := parsed.(ed25519.PublicKey)
	if !ok || len(key) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("trusted public key must be Ed25519")
	}
	return append(ed25519.PublicKey(nil), key...), nil
}

// canonicalRuleRoot handles a not-yet-created destination without creating it.
// Existing final roots must be real directories, as initialize also requires.
func canonicalRuleRoot(root string) (string, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	info, err := os.Lstat(abs)
	if err == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("rule root must be a real directory")
		}
		return filepath.EvalSymlinks(abs)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	parent, err := canonicalRuleRoot(filepath.Dir(abs))
	if err != nil {
		return "", err
	}
	return filepath.Join(parent, filepath.Base(abs)), nil
}

func (m *Manager) requireTrust() error {
	if len(m.trustedKeys) == 0 {
		return fmt.Errorf("规则导入和普通激活需要配置至少一把受信任的 Ed25519 公钥")
	}
	root, err := canonicalRuleRoot(m.Root)
	if err != nil || root != m.trustedRoot {
		return fmt.Errorf("规则根目录与已加载公钥的配置不一致")
	}
	return nil
}

func (m *Manager) verifySignature(manifest, signature []byte) error {
	if err := m.requireTrust(); err != nil {
		return err
	}
	if len(signature) != ed25519.SignatureSize {
		return fmt.Errorf("规则 manifest Ed25519 签名无效或缺失")
	}
	for _, key := range m.trustedKeys {
		if ed25519.Verify(key, manifest, signature) {
			return nil
		}
	}
	return fmt.Errorf("规则 manifest Ed25519 签名无效或缺失")
}

// readRuleMetadata rejects symlinks and bounds reads of manifest/signature files.
func readRuleMetadata(dir, name string, limit int64) ([]byte, error) {
	path := filepath.Join(dir, name)
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("规则元数据必须是普通文件")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		return nil, fmt.Errorf("规则元数据在打开时发生变化")
	}
	return readLimited(f, limit)
}
