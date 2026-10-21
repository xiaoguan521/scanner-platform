// Package deploy builds and executes an explicit, role-scoped node material
// deployment plan. It never discovers hosts, expands networks or logs secret
// material. The caller must provide a numeric target IP and a pinned SSH
// known-hosts file.
package deploy

import (
	"context"
	"crypto/rand"
	"encoding/hex"
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

	"scanner-platform/internal/provision"
)

const (
	defaultSSHBinary       = "/usr/bin/ssh"
	defaultSCPBinary       = "/usr/bin/scp"
	defaultProvisionBinary = "/opt/sec/bin/sec-node-provision"
)

var (
	remoteUserPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]{0,63}$`)
	serviceNames      = map[provision.PackageRole]map[string]struct{}{
		provision.PackageRoleServer:  {"sec-server": {}, "scanner-platform-server": {}},
		provision.PackageRoleWorker:  {"sec-worker": {}, "scanner-platform-worker": {}},
		provision.PackageRoleUpdater: {"sec-updater": {}, "scanner-platform-updater": {}},
	}
)

// Options defines one explicit deployment target. PackageDir must contain a
// verified role-scoped package; a complete provisioning directory is rejected.
type Options struct {
	PackageDir      string
	TargetIP        netip.Addr
	SSHPort         uint16
	User            string
	IdentityFile    string
	KnownHostsFile  string
	RemoteDir       string
	ServiceName     string
	ProvisionBinary string
	SSHBinary       string
	SCPBinary       string
}

// Step is a command in a deployment plan. Args never contain token or key
// contents; they contain only paths, role metadata and explicit target data.
type Step struct {
	Name   string   `json:"name"`
	Binary string   `json:"binary"`
	Args   []string `json:"args"`
}

// Plan is safe to render for operator review. StageDir is a remote temporary
// path and does not contain credentials.
type Plan struct {
	Target    string                `json:"target"`
	Role      provision.PackageRole `json:"role"`
	NodeID    string                `json:"nodeId,omitempty"`
	RemoteDir string                `json:"remoteDir"`
	StageDir  string                `json:"stageDir"`
	Steps     []Step                `json:"steps"`
	cleanup   Step
}

// Runner executes one local ssh/scp process. Tests can inject a recorder;
// production uses ExecRunner, which discards command output to avoid leaking
// remote paths, credentials or service-manager diagnostics into logs.
type Runner interface {
	Run(context.Context, string, []string) error
}

// ExecRunner invokes an external OpenSSH client without a shell.
type ExecRunner struct{}

func (ExecRunner) Run(ctx context.Context, binary string, args []string) error {
	command := exec.CommandContext(ctx, binary, args...)
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	return command.Run()
}

// BuildPlan validates the local package and creates an explicit deployment
// plan. It performs no network operation.
func BuildPlan(opts Options) (Plan, error) {
	if err := validateOptions(opts); err != nil {
		return Plan{}, err
	}
	verified, err := provision.Verify(provision.VerifyOptions{OutputDir: opts.PackageDir})
	if err != nil {
		return Plan{}, fmt.Errorf("verify node package: %w", err)
	}
	if verified.Role == "" {
		return Plan{}, errors.New("complete material directories cannot be deployed; create a role-scoped package first")
	}
	if opts.RoleMismatch(verified) {
		return Plan{}, errors.New("node package metadata does not match deployment options")
	}
	files, err := packageFiles(opts.PackageDir)
	if err != nil {
		return Plan{}, err
	}
	stage, err := temporaryRemotePath(opts.RemoteDir)
	if err != nil {
		return Plan{}, err
	}
	sshBinary := opts.SSHBinary
	if sshBinary == "" {
		sshBinary = defaultSSHBinary
	}
	scpBinary := opts.SCPBinary
	if scpBinary == "" {
		scpBinary = defaultSCPBinary
	}
	provisionBinary := opts.ProvisionBinary
	if provisionBinary == "" {
		provisionBinary = defaultProvisionBinary
	}
	endpoint := sshEndpoint(opts.User, opts.TargetIP)
	baseSSH := sshArgs(opts, endpoint)
	steps := []Step{
		{
			Name:   "create-staging-directory",
			Binary: sshBinary,
			Args:   append(append([]string(nil), baseSSH...), remoteCommand("install -d -m 700 -- "+shellWord(path.Dir(opts.RemoteDir))+" && mkdir -m 700 -- "+shellWord(stage))),
		},
	}
	scpArgs := scpArgs(opts, endpoint)
	for _, file := range files {
		scpArgs = append(scpArgs, filepath.Join(opts.PackageDir, file))
	}
	// The remote path is restricted to a safe absolute form, so it can be
	// passed as an scp destination without embedding shell quoting characters.
	scpArgs = append(scpArgs, endpoint+":"+stage+"/")
	steps = append(steps, Step{Name: "copy-role-package", Binary: scpBinary, Args: scpArgs})
	steps = append(steps, Step{
		Name:   "verify-remote-package",
		Binary: sshBinary,
		Args:   append(append([]string(nil), baseSSH...), remoteCommand(shellWord(provisionBinary)+" --verify-dir "+shellWord(stage))),
	})
	publish := "test ! -e " + shellWord(opts.RemoteDir) + " && mv -- " + shellWord(stage) + " " + shellWord(opts.RemoteDir)
	steps = append(steps, Step{Name: "publish-package", Binary: sshBinary, Args: append(append([]string(nil), baseSSH...), remoteCommand(publish))})
	steps = append(steps, Step{
		Name:   "restart-service",
		Binary: sshBinary,
		Args:   append(append([]string(nil), baseSSH...), remoteCommand("systemctl restart "+shellWord(opts.ServiceName))),
	})
	cleanup := Step{
		Name:   "cleanup-staging-directory",
		Binary: sshBinary,
		Args:   append(append([]string(nil), baseSSH...), remoteCommand("rm -rf -- "+shellWord(stage))),
	}
	return Plan{Target: endpoint, Role: verified.Role, NodeID: verified.NodeID, RemoteDir: opts.RemoteDir, StageDir: stage, Steps: steps, cleanup: cleanup}, nil
}

// Execute runs a previously built plan. If a pre-publish step fails, the
// temporary remote directory is removed best-effort. A publish or service
// restart failure is returned without deleting the published directory.
func (p Plan) Execute(ctx context.Context, runner Runner) error {
	if runner == nil {
		return errors.New("deployment runner is required")
	}
	for index, step := range p.Steps {
		if err := runner.Run(ctx, step.Binary, step.Args); err != nil {
			if index < 4 && p.cleanup.Binary != "" {
				_ = runner.Run(ctx, p.cleanup.Binary, p.cleanup.Args)
			}
			return fmt.Errorf("deployment step %s failed: %w", step.Name, err)
		}
	}
	return nil
}

func (o Options) RoleMismatch(verified provision.VerifyResult) bool {
	if o.ServiceName == "" {
		return true
	}
	for role, services := range serviceNames {
		if _, ok := services[o.ServiceName]; ok {
			return role != verified.Role
		}
	}
	return true
}

func validateOptions(o Options) error {
	if strings.TrimSpace(o.PackageDir) == "" {
		return errors.New("package directory is required")
	}
	if !o.TargetIP.IsValid() || o.TargetIP.IsUnspecified() || o.TargetIP.IsMulticast() || o.TargetIP.Zone() != "" {
		return errors.New("target must be a specific numeric unicast IP")
	}
	if o.SSHPort == 0 {
		return errors.New("SSH port must be between 1 and 65535")
	}
	if !remoteUserPattern.MatchString(o.User) {
		return errors.New("SSH user is invalid")
	}
	if !filepath.IsAbs(o.IdentityFile) || !filepath.IsAbs(o.KnownHostsFile) {
		return errors.New("SSH identity and known-hosts paths must be absolute")
	}
	if err := validateOwnerOnlyFile(o.IdentityFile, "SSH identity file"); err != nil {
		return err
	}
	if err := validateRegularFile(o.KnownHostsFile, "SSH known-hosts file"); err != nil {
		return err
	}
	if err := validateRemotePath(o.RemoteDir, false); err != nil {
		return fmt.Errorf("remote directory: %w", err)
	}
	if !isAllowedService(o.ServiceName) {
		return errors.New("service name is not an allowed scanner service")
	}
	if o.ProvisionBinary != "" && !isSafeAbsolutePath(o.ProvisionBinary) {
		return errors.New("provision binary must be a safe absolute path")
	}
	return nil
}

func isAllowedService(service string) bool {
	for _, services := range serviceNames {
		if _, ok := services[service]; ok {
			return true
		}
	}
	return false
}

func packageFiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("list node package: %w", err)
	}
	files := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !entry.Type().IsRegular() {
			return nil, fmt.Errorf("node package contains non-regular entry %q", entry.Name())
		}
		files = append(files, entry.Name())
	}
	sort.Strings(files)
	return files, nil
}

func temporaryRemotePath(remoteDir string) (string, error) {
	bytes := make([]byte, 8)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("generate remote staging suffix: %w", err)
	}
	return path.Join(remoteDir, ".incoming-"+hex.EncodeToString(bytes)), nil
}

func sshEndpoint(user string, ip netip.Addr) string {
	host := ip.String()
	if ip.Is6() {
		host = "[" + host + "]"
	}
	return user + "@" + host
}

func sshArgs(o Options, endpoint string) []string {
	return []string{"-q", "-oBatchMode=yes", "-oStrictHostKeyChecking=yes", "-oUserKnownHostsFile=" + o.KnownHostsFile, "-i", o.IdentityFile, "-p", strconv.Itoa(int(o.SSHPort)), endpoint}
}

func scpArgs(o Options, endpoint string) []string {
	return []string{"-q", "-oBatchMode=yes", "-oStrictHostKeyChecking=yes", "-oUserKnownHostsFile=" + o.KnownHostsFile, "-i", o.IdentityFile, "-P", strconv.Itoa(int(o.SSHPort)), "--"}
}

func remoteCommand(command string) string { return command }

func shellWord(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}

func validateRemotePath(value string, allowRoot bool) error {
	if value == "" || !strings.HasPrefix(value, "/") || strings.ContainsAny(value, "\x00\r\n") {
		return errors.New("must be an absolute path")
	}
	clean := path.Clean(value)
	if clean != value || strings.Contains(value, "//") || (!allowRoot && clean == "/") {
		return errors.New("contains an unsafe path")
	}
	return nil
}

func isSafeAbsolutePath(value string) bool {
	return validateRemotePath(value, false) == nil
}

func validateRegularFile(path, description string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("%s: %w", description, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("%s must be a regular non-symlink file", description)
	}
	return nil
}

func validateOwnerOnlyFile(path, description string) error {
	if err := validateRegularFile(path, description); err != nil {
		return err
	}
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("%s: %w", description, err)
	}
	if info.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("%s must be owner-only", description)
	}
	return nil
}
