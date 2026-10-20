package sshcollect

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
)

const maxApplicationFile int64 = 512 << 20
const maxApplicationTotal int64 = 2 << 30

// Application is a Worker-local explicit deployment directory; never sent to Server.
type Application struct {
	Alias       string `json:"alias"`
	Directory   string `json:"directory"`
	IncludeJava bool   `json:"includeJava"`
	IncludeGo   bool   `json:"includeGo"`
}

// AppInput describes one independently analyzed deployment artifact.
type AppInput struct{ Alias, InputPath, ArtifactType string }

func validateApplications(apps []Application) error {
	if len(apps) > 8 {
		return errors.New("SSH profile supports at most 8 applications")
	}
	seen := map[string]bool{}
	for _, app := range apps {
		if !aliasPattern.MatchString(app.Alias) || seen[app.Alias] || (!app.IncludeJava && !app.IncludeGo) || !validApplicationDirectory(app.Directory) {
			return errors.New("invalid SSH application alias, deployment directory or types")
		}
		seen[app.Alias] = true
	}
	return nil
}

func validApplicationDirectory(value string) bool {
	if len(value) > 512 || !path.IsAbs(value) || path.Clean(value) != value || value == "/" {
		return false
	}
	for _, ch := range value {
		if unicode.IsControl(ch) {
			return false
		}
	}
	for _, part := range strings.Split(value, "/") {
		if part == "." || part == ".." {
			return false
		}
	}
	for _, root := range []string{"/proc", "/sys", "/dev", "/run", "/tmp", "/net", "/mnt", "/media"} {
		if value == root || strings.HasPrefix(value, root+"/") {
			return false
		}
	}
	for _, root := range []string{"/opt", "/srv", "/home", "/root", "/etc", "/usr", "/usr/local", "/var", "/var/lib", "/var/www", "/var/opt", "/var/local", "/bin", "/sbin", "/lib", "/lib64", "/boot"} {
		if value == root {
			return false
		}
	}
	return true
}

func (c *Collector) Applications(target string) []Application {
	if c == nil {
		return nil
	}
	return append([]Application(nil), c.profiles[target].Apps...)
}

func applicationSource(target string, app Application) string {
	hostDigest := sha256.Sum256([]byte(target))
	digest := sha256.Sum256([]byte("target-" + hex.EncodeToString(hostDigest[:6]) + "\x00" + app.Alias + "\x00" + app.Directory))
	return "app-" + hex.EncodeToString(digest[:16])
}

func applicationToken(apps []Application) (string, error) {
	if err := validateApplications(apps); err != nil {
		return "", err
	}
	data, err := json.Marshal(apps)
	if err != nil {
		return "", err
	}
	token := "x" + base64.RawURLEncoding.EncodeToString(data)
	if len(token) > 8192 || !regexp.MustCompile(`^x[A-Za-z0-9_-]+$`).MatchString(token) {
		return "", ErrSSH
	}
	return token, nil
}

// CollectApplications performs a second bounded SSH collection only when the
// same configured numeric address and SSH port were selected and found open.
// status is a fixed machine enum; SSH output and remote paths are never public.
func (c *Collector) CollectApplications(ctx context.Context, target string, selectedPorts, openPorts []int, runtimeDir, inputsDir string) ([]AppInput, func(), string, error) {
	noop := func() {}
	apps := c.Applications(target)
	if len(apps) == 0 {
		return nil, noop, "not_configured", nil
	}
	profile := c.profiles[target]
	if !containsPort(selectedPorts, profile.SSHPort) {
		return nil, noop, "port_out_of_scope", nil
	}
	if !containsPort(openPorts, profile.SSHPort) {
		return nil, noop, "collection_failed", ErrSSH
	}
	token, err := applicationToken(apps)
	if err != nil {
		return nil, noop, "collection_failed", ErrSSH
	}
	if err := ctx.Err(); err != nil {
		return nil, noop, "collection_failed", err
	}
	if err := os.MkdirAll(runtimeDir, 0700); err != nil {
		return nil, noop, "collection_failed", ErrSSH
	}
	if err := os.MkdirAll(inputsDir, 0700); err != nil {
		return nil, noop, "collection_failed", ErrSSH
	}
	work, err := os.MkdirTemp(runtimeDir, "sshapps-")
	if err != nil {
		return nil, noop, "collection_failed", ErrSSH
	}
	inputRoot, err := os.MkdirTemp(inputsDir, "sshapps-")
	if err != nil {
		os.RemoveAll(work)
		return nil, noop, "collection_failed", ErrSSH
	}
	cleanup := func() { _ = os.RemoveAll(work); _ = os.RemoveAll(inputRoot) }
	fail := func(err error) ([]AppInput, func(), string, error) {
		cleanup()
		return nil, noop, "collection_failed", err
	}
	archivePath := filepath.Join(work, "apps.tar.gz")
	archive, err := os.OpenFile(archivePath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return fail(ErrSSH)
	}
	args := []string{"-F", nullDevice(), "-T", "-p", strconv.Itoa(profile.SSHPort), "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "UserKnownHostsFile=" + c.knownHosts, "-o", "GlobalKnownHostsFile=" + nullDevice(), "-o", "UpdateHostKeys=no", "-o", "PasswordAuthentication=no", "-o", "KbdInteractiveAuthentication=no", "-o", "PreferredAuthentications=publickey", "-o", "ClearAllForwardings=yes", "-o", "PermitLocalCommand=no", "-o", "ConnectTimeout=10", "-o", "ServerAliveInterval=10", "-o", "ServerAliveCountMax=1"}
	if profile.Auth == "private-key" {
		args = append(args, "-o", "IdentitiesOnly=yes", "-i", profile.PrivateKeyFile)
	}
	address, _ := netip.ParseAddr(target)
	destination := profile.User + "@" + target
	if address.Is6() {
		destination = profile.User + "@[" + target + "]"
	}
	digest := sha256.Sum256([]byte(target))
	source := "target-" + hex.EncodeToString(digest[:6])
	output := "/tmp/secscan-" + filepath.Base(work)
	if !safeRemoteOutput(output) {
		archive.Close()
		return fail(ErrSSH)
	}
	args = append(args, destination, "python3", "-", "--source", source, "--output", output, "--rootfs", "/", "--archive-stdout", "--ssh-apps-b64="+token)
	var stderr bytes.Buffer
	// Bound the remote walk and transfer even if the caller omitted a deadline.
	sshCtx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	writer := &limitedWriter{dst: archive, remaining: maxApplicationTotal + (4 << 20)}
	if c.runApplications != nil {
		err = c.runApplications(sshCtx, args, writer, &limitedWriter{dst: &stderr, remaining: 64 << 10})
	} else {
		ssh, lookErr := exec.LookPath("ssh")
		if lookErr != nil {
			archive.Close()
			return fail(ErrSSH)
		}
		cmd := exec.CommandContext(sshCtx, ssh, args...)
		cmd.Stdin = bytes.NewReader(collectorSource)
		cmd.Stdout = writer
		cmd.Stderr = &limitedWriter{dst: &stderr, remaining: 64 << 10}
		cmd.Env = sshEnvironment()
		err = cmd.Run()
	}
	closeErr := archive.Close()
	if err != nil || closeErr != nil {
		if ctx.Err() != nil {
			return fail(ctx.Err())
		}
		return fail(ErrSSH)
	}
	inputs, err := extractApplicationsContext(sshCtx, archivePath, inputRoot, target, apps)
	if err != nil {
		return fail(ErrSSH)
	}
	for i := range inputs {
		relative, err := filepath.Rel(inputsDir, inputs[i].InputPath)
		if err != nil || !filepath.IsLocal(relative) {
			return fail(ErrSSH)
		}
		inputs[i].InputPath = filepath.ToSlash(relative)
	}
	return inputs, cleanup, "collected", nil
}

var appSequence = regexp.MustCompile(`^[0-9]{4}$`)

func extractApplications(filename, destination, target string, apps []Application) ([]AppInput, error) {
	return extractApplicationsContext(context.Background(), filename, destination, target, apps)
}

func extractApplicationsContext(ctx context.Context, filename, destination, target string, apps []Application) ([]AppInput, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	allowed := map[string]Application{}
	for _, app := range apps {
		allowed[app.Alias] = app
	}
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	gz, err := gzip.NewReader(file)
	if err != nil {
		return nil, err
	}
	defer gz.Close()
	tr := tar.NewReader(&applicationReader{ctx: ctx, reader: gz})
	seen := map[string]bool{}
	groups := map[string]map[int]map[string]string{}
	var total int64
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		name := strings.TrimSuffix(h.Name, "/")
		if name == "" || path.Clean(name) != name || path.IsAbs(name) || strings.ContainsAny(name, "\\:\x00") || seen[name] {
			return nil, errors.New("invalid or duplicate application archive path")
		}
		seen[name] = true
		parts := strings.Split(name, "/")
		valid := false
		if name == "apps" {
			valid = h.Typeflag == tar.TypeDir
		} else if len(parts) >= 2 && len(parts) <= 4 && parts[0] == "apps" {
			app, ok := allowed[parts[1]]
			if ok && len(parts) == 2 {
				valid = h.Typeflag == tar.TypeDir
			}
			if ok && len(parts) >= 3 && appSequence.MatchString(parts[2]) {
				n, _ := strconv.Atoi(parts[2])
				if n < 16 {
					if len(parts) == 3 {
						valid = h.Typeflag == tar.TypeDir
					} else {
						base := parts[3]
						valid = (base == ".scanner-input.json" || base == "artifact.jar" && app.IncludeJava || base == "artifact.war" && app.IncludeJava || base == "artifact.ear" && app.IncludeJava || base == "artifact.par" && app.IncludeJava || base == "artifact.elf" && app.IncludeGo) && (h.Typeflag == tar.TypeReg || h.Typeflag == tar.TypeRegA)
						if valid {
							if groups[app.Alias] == nil {
								groups[app.Alias] = map[int]map[string]string{}
							}
							if groups[app.Alias][n] == nil {
								groups[app.Alias][n] = map[string]string{}
							}
							groups[app.Alias][n][base] = ""
						}
					}
				}
			}
		}
		if !valid || h.Typeflag == tar.TypeDir && h.Size != 0 || h.Typeflag != tar.TypeDir && name != h.Name {
			return nil, errors.New("unexpected application archive entry")
		}
		local := filepath.Join(destination, filepath.FromSlash(name))
		if h.Typeflag == tar.TypeDir {
			if err := os.MkdirAll(local, 0700); err != nil {
				return nil, err
			}
			continue
		}
		limit := maxApplicationFile
		if parts[3] == ".scanner-input.json" {
			limit = 4096
		}
		if h.Size < 0 || h.Size > limit || h.Size > maxApplicationTotal-total || len(seen) > 160 {
			return nil, errors.New("application archive limit exceeded")
		}
		total += h.Size
		if err := os.MkdirAll(filepath.Dir(local), 0700); err != nil {
			return nil, err
		}
		out, err := os.OpenFile(local, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return nil, err
		}
		hash := sha256.New()
		_, copyErr := io.CopyN(io.MultiWriter(out, hash), tr, h.Size)
		closeErr := out.Close()
		if copyErr != nil || closeErr != nil {
			return nil, errors.New("truncated application artifact")
		}
		groups[parts[1]][mustSequence(parts[2])][parts[3]] = hex.EncodeToString(hash.Sum(nil))
	}
	inputs := []AppInput{}
	javaExpansion := &javaBudget{ctx: ctx}
	for _, app := range apps {
		group := groups[app.Alias]
		if len(group) == 0 {
			return nil, errors.New("application has no selected artifacts")
		}
		indexes := []int{}
		for n := range group {
			indexes = append(indexes, n)
		}
		sort.Ints(indexes)
		for expected, n := range indexes {
			files := group[n]
			if n != expected || len(files) != 2 || files[".scanner-input.json"] == "" {
				return nil, errors.New("application requires one artifact and snapshot per sequential input")
			}
			dir := filepath.Join(destination, "apps", app.Alias, fmt.Sprintf("%04d", n))
			var artifact string
			for name := range files {
				if name != ".scanner-input.json" {
					artifact = name
				}
			}
			var snapshot struct {
				SchemaVersion int               `json:"schemaVersion"`
				Source        string            `json:"source"`
				Kind          string            `json:"kind"`
				CollectedAt   string            `json:"collectedAt"`
				Files         map[string]string `json:"files"`
			}
			data, err := os.ReadFile(filepath.Join(dir, ".scanner-input.json"))
			if err != nil {
				return nil, err
			}
			decoder := json.NewDecoder(bytes.NewReader(data))
			decoder.DisallowUnknownFields()
			if decoder.Decode(&snapshot) != nil || decoder.Decode(new(any)) != io.EOF || snapshot.SchemaVersion != 1 || snapshot.Source != applicationSource(target, app) || snapshot.Kind != "artifact" || len(snapshot.Files) != 1 || snapshot.Files[artifact] != files[artifact] {
				return nil, errors.New("invalid application snapshot or hash")
			}
			if _, err := time.Parse(time.RFC3339, snapshot.CollectedAt); err != nil {
				return nil, errors.New("invalid application collection time")
			}
			kind := "jar"
			if artifact != "artifact.elf" {
				if err := validateJavaArchive(filepath.Join(dir, artifact), javaExpansion); err != nil {
					return nil, err
				}
			}
			if artifact == "artifact.elf" {
				kind = "gobinary"
				file, err := os.Open(filepath.Join(dir, artifact))
				if err != nil {
					return nil, err
				}
				var magic [4]byte
				_, readErr := io.ReadFull(file, magic[:])
				file.Close()
				if readErr != nil || string(magic[:]) != "\x7fELF" {
					return nil, errors.New("application is not an ELF binary")
				}
				if _, err := buildinfo.ReadFile(filepath.Join(dir, artifact)); err != nil {
					return nil, errors.New("ELF application is not a supported Go binary")
				}
			}
			inputs = append(inputs, AppInput{Alias: app.Alias, InputPath: dir, ArtifactType: kind})
			if len(inputs) > 32 {
				return nil, errors.New("too many application artifacts")
			}
		}
	}
	return inputs, nil
}
func mustSequence(value string) int { n, _ := strconv.Atoi(value); return n }

// applicationReader checks cancellation between bounded stream reads.
type applicationReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r *applicationReader) Read(data []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(data)
}
