// Package portable runs Server, Worker and Updater in one process for the
// single-binary offline edition (architecture-v3.2.md section 9).
package portable

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Layout is the fixed directory structure beside the sec-portable binary.
type Layout struct {
	Home, Bin, Rules, Config, Runtime                      string
	Database, Reports, WorkerRuntime, Inputs, EngineData   string
	Logs, LogFile, LockFile, SSHConfig, TrustedRuleKeysDir string
}

// ResolveLayout uses home when given and otherwise the directory that holds
// the running executable, so double-clicking the binary finds its data.
func ResolveLayout(home string) (Layout, error) {
	if home == "" {
		executable, err := os.Executable()
		if err != nil {
			return Layout{}, fmt.Errorf("locate sec-portable: %w", err)
		}
		if resolved, err := filepath.EvalSymlinks(executable); err == nil {
			executable = resolved
		}
		home = filepath.Dir(executable)
	}
	home, err := filepath.Abs(home)
	if err != nil {
		return Layout{}, err
	}
	runtime := filepath.Join(home, "runtime")
	config := filepath.Join(home, "config")
	return Layout{
		Home: home, Bin: filepath.Join(home, "bin"), Rules: filepath.Join(home, "vuln-data"), Config: config, Runtime: runtime,
		Database: filepath.Join(runtime, "platform.db"), Reports: filepath.Join(runtime, "reports"),
		WorkerRuntime: filepath.Join(runtime, "worker"), Inputs: filepath.Join(runtime, "inputs"),
		EngineData: filepath.Join(runtime, "engine-data", "trivy"),
		Logs:       filepath.Join(runtime, "logs"), LogFile: filepath.Join(runtime, "logs", "portable.log"),
		LockFile:  filepath.Join(runtime, "portable.lock"),
		SSHConfig: filepath.Join(config, "ssh-config.json"), TrustedRuleKeysDir: filepath.Join(config, "trusted-rule-keys"),
	}, nil
}

// Prepare creates the private runtime directories (owner-only) and the rule
// directory if it is missing. It never touches bin/ or config/.
func (l Layout) Prepare() error {
	for _, dir := range []string{l.Runtime, l.Reports, l.WorkerRuntime, l.Inputs, l.EngineData, l.Logs} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("create %s: %w", dir, err)
		}
	}
	// MkdirAll keeps an existing directory's mode; tighten runtime/ itself.
	if err := os.Chmod(l.Runtime, 0o700); err != nil {
		return fmt.Errorf("protect runtime directory: %w", err)
	}
	if err := os.MkdirAll(l.Rules, 0o755); err != nil {
		return fmt.Errorf("create rule directory: %w", err)
	}
	return nil
}

// OptionalSSHConfig returns config/ssh-config.json when the operator placed one.
func (l Layout) OptionalSSHConfig() (string, error) {
	info, err := os.Stat(l.SSHConfig)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", errors.New("config/ssh-config.json must be a regular file")
	}
	return l.SSHConfig, nil
}

// TrustedRuleKeys lists config/trusted-rule-keys/*.pem. Without keys the
// Updater keeps the existing unsigned local behaviour; with keys, imported
// bundles must be signed by one of them.
func (l Layout) TrustedRuleKeys() ([]string, error) {
	keys, err := filepath.Glob(filepath.Join(l.TrustedRuleKeysDir, "*.pem"))
	if err != nil {
		return nil, err
	}
	return keys, nil
}
