package workerfence

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
)

// RestrictedExec configures a process that is NOT callable from untrusted
// scan input. The executor must build and review all engine arguments first.
type RestrictedExec struct {
	SetprivPath string
	EnginePath  string
	EngineArgs  []string
	RuntimeDir  string
}

// restrictedCommand assembles an argv vector, never a shell string.
// setpriv is required to clear UID/GID, groups, inherited, ambient and
// bounding capabilities and to prevent privilege gain across execve.
func (p RestrictedExec) restrictedCommand() ([]string, []string, error) {
	if !filepath.IsAbs(p.SetprivPath) || filepath.Clean(p.SetprivPath) != p.SetprivPath {
		return nil, nil, errors.New("setpriv path must be absolute/canonical")
	}
	if !filepath.IsAbs(p.EnginePath) || filepath.Clean(p.EnginePath) != p.EnginePath {
		return nil, nil, errors.New("engine path must be absolute/canonical")
	}
	if !filepath.IsAbs(p.RuntimeDir) || filepath.Clean(p.RuntimeDir) != p.RuntimeDir || p.RuntimeDir == "/" {
		return nil, nil, errors.New("runtime directory must be absolute, private and non-root")
	}
	engine := filepath.Base(p.EnginePath)
	if engine != "nuclei" && engine != "trivy" {
		return nil, nil, fmt.Errorf("engine %q not authorized for worker launch", engine)
	}
	for _, a := range p.EngineArgs {
		if a == "" || strings.ContainsAny(a, "\x00\r\n") {
			return nil, nil, errors.New("engine argv contains empty or invalid argument")
		}
	}
	argv := []string{
		"--reuid=10001", "--regid=10001", "--clear-groups",
		"--inh-caps=-all", "--ambient-caps=-all", "--bounding-set=-all",
		"--no-new-privs", "--", p.EnginePath,
	}
	argv = append(argv, p.EngineArgs...)
	environment := []string{
		"HOME=" + filepath.Join(p.RuntimeDir, "home"),
		"XDG_CACHE_HOME=" + filepath.Join(p.RuntimeDir, "cache"),
		"XDG_CONFIG_HOME=" + filepath.Join(p.RuntimeDir, "config"),
		"TMPDIR=" + filepath.Join(p.RuntimeDir, "tmp"),
		"PATH=/usr/bin:/bin",
	}
	return argv, environment, nil
}
