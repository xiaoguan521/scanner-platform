// Package sshcollect runs a fixed, one-shot package snapshot collector over the
// local OpenSSH client. SSH profiles and host keys never pass through Server.
package sshcollect

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"archive/tar"
	"net/netip"
	"scanner-platform/internal/taskflow"
)

const (
	maxConfigBytes  = 1 << 20
	maxArchiveBytes = int64(2 << 30)
	maxArchiveFiles = 10000
)

var (
	userPattern       = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]{0,31}$`)
	aliasPattern      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`)
	ErrHostKey        = errors.New("SSH host key is not pinned")
	ErrAuthentication = errors.New("SSH public-key authentication failed")
	ErrSSH            = errors.New("SSH collection failed")
)

// Profile identifies a single numeric IP. Private key contents, passwords and
// agent data are never serialized in the config or sent to Server.
type Profile struct {
	IP             string        `json:"ip"`
	SSHPort        int           `json:"sshPort"`
	User           string        `json:"user"`
	Auth           string        `json:"auth"` // "agent" or "private-key"
	PrivateKeyFile string        `json:"privateKeyFile,omitempty"`
	Apps           []Application `json:"apps,omitempty"`
}

type fileConfig struct {
	KnownHostsFile string    `json:"knownHostsFile"`
	Targets        []Profile `json:"targets"`
}

type Collector struct {
	knownHosts      string
	baseDir         string
	profiles        map[string]Profile
	runApplications func(context.Context, []string, io.Writer, io.Writer) error
}

//go:embed collector.py
var collectorSource []byte

// Load validates a Worker-local SSH configuration. Relative paths are resolved
// from the config file directory; passwords and unknown fields are rejected.
func Load(configPath string) (*Collector, error) {
	absolute, err := filepath.Abs(configPath)
	if err != nil {
		return nil, errors.New("invalid SSH config path")
	}
	if !regularNonSymlink(absolute, maxConfigBytes, false) {
		return nil, errors.New("SSH config must be a regular local file")
	}
	data, err := os.ReadFile(absolute)
	if err != nil || len(data) > maxConfigBytes {
		return nil, errors.New("cannot read SSH config")
	}
	var cfg fileConfig
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		return nil, errors.New("invalid SSH config JSON")
	}
	if decoder.Decode(new(any)) != io.EOF || len(cfg.Targets) > 1000 {
		return nil, errors.New("invalid SSH config shape")
	}
	base := filepath.Dir(absolute)
	knownHosts, err := localPath(base, cfg.KnownHostsFile)
	if err != nil || !regularNonSymlink(knownHosts, 8<<20, false) {
		return nil, errors.New("SSH known-hosts file must be a regular local file")
	}
	collector := &Collector{knownHosts: knownHosts, baseDir: base, profiles: make(map[string]Profile, len(cfg.Targets))}
	for _, profile := range cfg.Targets {
		ip, err := netip.ParseAddr(profile.IP)
		if err != nil || ip.Zone() != "" || ip.IsUnspecified() || ip.IsMulticast() || ip.String() != profile.IP || profile.SSHPort < 1 || profile.SSHPort > 65535 || !userPattern.MatchString(profile.User) {
			return nil, errors.New("SSH profile must use a canonical numeric IP, valid port and account name")
		}
		if _, duplicate := collector.profiles[profile.IP]; duplicate {
			return nil, errors.New("duplicate SSH target profile")
		}
		switch profile.Auth {
		case "agent":
			if profile.PrivateKeyFile != "" {
				return nil, errors.New("SSH agent profile cannot include a private-key path")
			}
		case "private-key":
			if profile.PrivateKeyFile == "" {
				return nil, errors.New("private-key profile requires a local key file")
			}
			key, err := localPath(base, profile.PrivateKeyFile)
			if err != nil || !regularNonSymlink(key, 1<<20, true) {
				return nil, errors.New("SSH private key must be a regular local file with owner-only permissions")
			}
			profile.PrivateKeyFile = key
		default:
			return nil, errors.New("SSH auth must be agent or private-key")
		}
		if err := validateApplications(profile.Apps); err != nil {
			return nil, err
		}
		collector.profiles[profile.IP] = profile
	}
	return collector, nil
}

func localPath(base, value string) (string, error) {
	if value == "" || strings.ContainsRune(value, '\x00') {
		return "", errors.New("empty local path")
	}
	if filepath.IsAbs(value) {
		return filepath.Clean(value), nil
	}
	if !filepath.IsLocal(value) {
		return "", errors.New("path must stay local to config directory")
	}
	return filepath.Join(base, value), nil
}

func regularNonSymlink(filename string, max int64, private bool) bool {
	clean := filepath.Clean(filename)
	resolvedDir, err := filepath.EvalSymlinks(filepath.Dir(clean))
	if err != nil {
		return false
	}
	resolved := filepath.Join(resolvedDir, filepath.Base(clean))
	info, err := os.Lstat(resolved)
	if err != nil || !info.Mode().IsRegular() || info.Size() > max {
		return false
	}
	return !private || runtime.GOOS == "windows" || info.Mode().Perm()&0077 == 0
}

// Configured reports whether a target has a Worker-local SSH profile.
func (c *Collector) Configured(target string) bool {
	return c != nil && c.profiles[target].IP != ""
}

// ProfilePort returns the configured SSH port for a numeric target.
func (c *Collector) ProfilePort(target string) (int, bool) {
	if c == nil {
		return 0, false
	}
	profile, ok := c.profiles[target]
	return profile.SSHPort, ok
}

// CollectRootfs runs only the embedded read-only package collector. The
// configured SSH port must be both selected and found open by the same task.
func (c *Collector) CollectRootfs(ctx context.Context, target string, selectedPorts, openPorts []int, runtimeDir, inputsDir string) (string, func(), string, error) {
	if c == nil {
		return "", func() {}, taskflow.SystemScanNotConfigured, nil
	}
	profile, ok := c.profiles[target]
	if !ok {
		return "", func() {}, taskflow.SystemScanNotConfigured, nil
	}
	if !containsPort(selectedPorts, profile.SSHPort) {
		return "", func() {}, taskflow.SystemScanPortOutOfScope, nil
	}
	if !containsPort(openPorts, profile.SSHPort) {
		return "", func() {}, taskflow.SystemScanPortClosed, nil
	}
	sshPath, err := exec.LookPath("ssh")
	if err != nil {
		return "", func() {}, taskflow.SystemScanClientMissing, ErrSSH
	}
	if err := os.MkdirAll(runtimeDir, 0700); err != nil {
		return "", func() {}, "", ErrSSH
	}
	if err := os.MkdirAll(inputsDir, 0700); err != nil {
		return "", func() {}, "", ErrSSH
	}
	var random [12]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", func() {}, "", ErrSSH
	}
	stamp := hex.EncodeToString(random[:])
	runtimeRoot, err := os.MkdirTemp(runtimeDir, "sshcollect-")
	if err != nil {
		return "", func() {}, "", ErrSSH
	}
	archivePath := filepath.Join(runtimeRoot, "rootfs.tar.gz")
	archive, err := os.OpenFile(archivePath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		os.RemoveAll(runtimeRoot)
		return "", func() {}, "", ErrSSH
	}
	args := []string{
		"-T", "-p", fmt.Sprint(profile.SSHPort),
		"-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
		"-o", "UserKnownHostsFile=" + c.knownHosts,
		"-o", "GlobalKnownHostsFile=" + nullDevice(),
		"-o", "UpdateHostKeys=no", "-o", "PasswordAuthentication=no",
		"-o", "KbdInteractiveAuthentication=no", "-o", "PreferredAuthentications=publickey",
		"-o", "ClearAllForwardings=yes", "-o", "PermitLocalCommand=no",
		"-o", "ConnectTimeout=10", "-o", "ServerAliveInterval=10", "-o", "ServerAliveCountMax=1",
	}
	if profile.Auth == "private-key" {
		args = append(args, "-o", "IdentitiesOnly=yes", "-i", profile.PrivateKeyFile)
	}
	args = append([]string{"-F", nullDevice()}, args...)
	address, _ := netip.ParseAddr(profile.IP)
	destination := profile.User + "@" + profile.IP
	if address.Is6() {
		destination = profile.User + "@" + "[" + profile.IP + "]"
	}
	remoteOutput := "/tmp/secscan-" + stamp
	if !safeRemoteOutput(remoteOutput) {
		archive.Close()
		os.RemoveAll(runtimeRoot)
		return "", func() {}, "", ErrSSH
	}
	addressDigest := sha256.Sum256([]byte(target))
	sourceAlias := "target-" + hex.EncodeToString(addressDigest[:6])
	args = append(args, destination, "python3", "-", "--source", sourceAlias, "--output", remoteOutput, "--rootfs", "/", "--archive-stdout")
	cmd := exec.CommandContext(ctx, sshPath, args...)
	cmd.Stdin = bytes.NewReader(collectorSource)
	cmd.Stdout = &limitedWriter{dst: archive, remaining: maxArchiveBytes}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	cmd.Env = sshEnvironment()
	runErr := cmd.Run()
	closeErr := archive.Close()
	if runErr != nil || closeErr != nil {
		os.RemoveAll(runtimeRoot)
		if ctx.Err() != nil {
			return "", func() {}, "", ctx.Err()
		}
		text := stderr.String()
		if strings.Contains(text, "Host key verification failed") || strings.Contains(text, "REMOTE HOST IDENTIFICATION HAS CHANGED") {
			return "", func() {}, taskflow.SystemScanHostKeyMismatch, ErrHostKey
		}
		if strings.Contains(text, "Permission denied") {
			return "", func() {}, taskflow.SystemScanAuthFailed, ErrAuthentication
		}
		if strings.Contains(text, "python3: not found") || strings.Contains(text, "python3: command not found") {
			return "", func() {}, taskflow.SystemScanPythonMissing, ErrSSH
		}
		return "", func() {}, taskflow.SystemScanCollectionFailed, ErrSSH
	}
	if err := extractSnapshot(archivePath, filepath.Join(inputsDir, "ssh-"+stamp)); err != nil {
		os.RemoveAll(runtimeRoot)
		os.RemoveAll(filepath.Join(inputsDir, "ssh-"+stamp))
		return "", func() {}, taskflow.SystemScanInvalidSnapshot, ErrSSH
	}
	inputPath := filepath.Join(inputsDir, "ssh-"+stamp, "os")
	relative, err := filepath.Rel(inputsDir, inputPath)
	if err != nil || !filepath.IsLocal(relative) {
		os.RemoveAll(runtimeRoot)
		os.RemoveAll(filepath.Join(inputsDir, "ssh-"+stamp))
		return "", func() {}, "", ErrSSH
	}
	cleanup := func() {
		_ = os.RemoveAll(runtimeRoot)
		_ = os.RemoveAll(filepath.Join(inputsDir, "ssh-"+stamp))
	}
	return filepath.ToSlash(relative), cleanup, taskflow.SystemScanCompleted, nil
}

func nullDevice() string {
	if runtime.GOOS == "windows" {
		return "NUL"
	}
	return "/dev/null"
}

func containsPort(ports []int, want int) bool {
	for _, port := range ports {
		if port == want {
			return true
		}
	}
	return false
}

type limitedWriter struct {
	dst       io.Writer
	remaining int64
}

func (w *limitedWriter) Write(p []byte) (int, error) {
	if int64(len(p)) > w.remaining {
		return 0, errors.New("SSH snapshot exceeds size limit")
	}
	n, err := w.dst.Write(p)
	w.remaining -= int64(n)
	return n, err
}

func extractSnapshot(filename, destination string) error {
	if _, err := os.Lstat(destination); err == nil || !os.IsNotExist(err) {
		return errors.New("destination exists")
	}
	if err := os.Mkdir(destination, 0700); err != nil {
		return err
	}
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	gz, err := gzip.NewReader(file)
	if err != nil {
		return err
	}
	defer gz.Close()
	reader := tar.NewReader(gz)
	files, total := 0, int64(0)
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		name := strings.TrimSuffix(header.Name, "/")
		if name == "" || name == "." {
			continue
		}
		if strings.ContainsAny(name, "\\:\x00") || path.IsAbs(name) || path.Clean(name) != name || name != "os" && !strings.HasPrefix(name, "os/") && name != "collection.json" && name != ".gitignore" {
			return errors.New("archive path is outside selected OS snapshot")
		}
		local := filepath.Join(destination, filepath.FromSlash(name))
		relative, err := filepath.Rel(destination, local)
		if err != nil || !filepath.IsLocal(relative) {
			return errors.New("archive path escapes destination")
		}
		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(local, 0700); err != nil {
				return err
			}
		case tar.TypeReg, tar.TypeRegA:
			files++
			if header.Size < 0 || header.Size > maxArchiveBytes-total {
				return errors.New("archive exceeds file or size limit")
			}
			total += header.Size
			if files > maxArchiveFiles {
				return errors.New("archive exceeds file or size limit")
			}
			if err := os.MkdirAll(filepath.Dir(local), 0700); err != nil {
				return err
			}
			out, err := os.OpenFile(local, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
			if err != nil {
				return err
			}
			copied, copyErr := io.CopyN(out, reader, header.Size)
			closeErr := out.Close()
			if copyErr != nil || closeErr != nil || copied != header.Size {
				return errors.New("archive file truncated")
			}
		default:
			return errors.New("archive contains unsupported entry type")
		}
	}
	manifest := filepath.Join(destination, "os", ".scanner-input.json")
	base := filepath.Base(destination)
	if !regularNonSymlink(manifest, 2<<20, false) || !strings.HasPrefix(base, "ssh-") || !aliasPattern.MatchString(strings.TrimPrefix(base, "ssh-")) {
		return errors.New("archive is missing a valid input manifest")
	}
	return nil
}

// Keep a compile-time guard against accidentally changing the fixed remote
// destination into user-controlled shell syntax.
func safeRemoteOutput(value string) bool {
	return strings.HasPrefix(value, "/tmp/secscan-") && aliasPattern.MatchString(strings.TrimPrefix(value, "/tmp/secscan-"))
}

func sshEnvironment() []string {
	keys := []string{"PATH", "SSH_AUTH_SOCK"}
	if runtime.GOOS == "windows" {
		keys = append(keys, "SystemRoot", "WINDIR", "TEMP", "TMP")
	}
	env := make([]string, 0, len(keys))
	for _, key := range keys {
		if value, ok := os.LookupEnv(key); ok && value != "" {
			env = append(env, key+"="+value)
		}
	}
	return env
}
