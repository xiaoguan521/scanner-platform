package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"scanner-platform/internal/portprobe"
	"scanner-platform/internal/rules"
	"scanner-platform/internal/sshcollect"
	"scanner-platform/internal/taskflow"
)

const NucleiVersion = "3.11.1"
const TrivyVersion = "0.76.0"
const ZAPVersion = "2.17.0"

type Runner struct {
	BinDir        string
	RulesDir      string
	RuntimeDir    string
	InputsDir     string
	Rate          int
	Timeout       int
	SSHCollector  *sshcollect.Collector
	versionOnce   sync.Once
	versionErrors map[string]error
}

func (r *Runner) binary(name string) string {
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	return filepath.Join(r.BinDir, name)
}
func (r *Runner) zapJAR() string { return filepath.Join(r.BinDir, "zap", "zap-"+ZAPVersion+".jar") }

func (r *Runner) Status() []taskflow.EngineStatus {
	r.checkVersions()
	out := []taskflow.EngineStatus{}
	for _, item := range []struct{ name, version, path string }{{"nuclei", NucleiVersion, r.binary("nuclei")}, {"trivy", TrivyVersion, r.binary("trivy")}, {"zap", ZAPVersion, r.zapJAR()}} {
		info, err := os.Stat(item.path)
		installed := err == nil && info.Mode().IsRegular()
		status := taskflow.EngineStatus{Name: item.name, Version: item.version, Installed: installed, Message: "程序未安装，请运行 make engines"}
		if installed {
			status.Message = "程序已安装，等待可用规则库"
			if item.name == "zap" {
				_, e := exec.LookPath("java")
				status.Ready = e == nil
				status.Message = "被动检查；需 Java 17+；仅分析指定地址的响应"
			} else if data, err := os.ReadFile(filepath.Join(r.RulesDir, "CURRENT")); err == nil {
				version := strings.TrimSpace(string(data))
				if rules.ValidateVersion(version) {
					path := filepath.Join(r.RulesDir, "releases", version, item.name)
					if info, err := os.Stat(path); err == nil && info.IsDir() {
						status.Ready = true
						status.Message = "程序和本地规则已就绪，执行前校验完整性"
						if item.name == "trivy" {
							status.Ready = hasDBFiles(filepath.Join(path, "db"), "trivy.db")
							status.Message = "主漏洞库文件已就绪；Java 索引未准备，JAR 需运行 make engines-java"
							if hasJavaDB(path) {
								status.Message = "主漏洞库和 Java 索引文件已就绪；执行前校验完整性"
							}
							if !status.Ready {
								status.Message = "主漏洞库文件缺失，请运行 make engines 或重新导入完整规则"
							}
						}
					}
				}
			}
		}
		if installed && r.versionErrors[item.name] != nil {
			status.Ready = false
			status.Message = "程序版本或运行环境检查失败，请运行 make verify-flags"
		}
		out = append(out, status)
	}
	return out
}

func (r *Runner) ruleDirectory(ctx context.Context, version, engine string) (string, error) {
	if version == "" {
		data, err := os.ReadFile(filepath.Join(r.RulesDir, "CURRENT"))
		if err != nil {
			return "", fmt.Errorf("no active rules")
		}
		version = strings.TrimSpace(string(data))
	}
	if !rules.ValidateVersion(version) {
		return "", fmt.Errorf("invalid rule version")
	}
	// Read-only verification: Worker never creates or alters a rules directory.
	manager := rules.Manager{Root: r.RulesDir}
	bundle, err := manager.Inspect(ctx, version)
	if err != nil {
		return "", fmt.Errorf("verify pinned rules: %w", err)
	}
	supported := false
	for _, name := range bundle.Engines {
		supported = supported || name == engine
	}
	if !supported {
		return "", fmt.Errorf("rule bundle does not include %s", engine)
	}
	return filepath.Join(r.RulesDir, "releases", version, engine), nil
}

func (r *Runner) Execute(ctx context.Context, task taskflow.Task) ([]taskflow.Detection, error) {
	if os.Geteuid() == 0 {
		return nil, fmt.Errorf("run scanning Worker as an ordinary user")
	}
	r.checkVersions()
	if len(task.Engines) == 1 && r.versionErrors[task.Engines[0]] != nil {
		return nil, r.versionErrors[task.Engines[0]]
	}
	if task.Synthetic || len(task.Engines) != 1 || len(task.Chunks) != 1 || len(task.Chunks[0].Targets) == 0 {
		return nil, fmt.Errorf("invalid engine task")
	}
	if err := os.MkdirAll(r.RuntimeDir, 0700); err != nil {
		return nil, err
	}
	dir, err := os.MkdirTemp(r.RuntimeDir, "scan-")
	if err != nil {
		return nil, err
	}
	if r.Rate == 0 {
		r.Rate = 5
	}
	if r.Timeout == 0 {
		r.Timeout = 10
	}
	switch task.Engines[0] {
	case "nuclei":
		return r.nuclei(ctx, task, dir)
	case "trivy":
		return r.trivy(ctx, task, dir)
	case "zap":
		return r.zap(ctx, task, dir)
	default:
		return nil, fmt.Errorf("unsupported engine")
	}
}

// ProbePorts performs a bounded TCP connect probe for the single Server-bound
// asset IP in the task. It does not send application data or identify services.
func (r *Runner) ProbePorts(ctx context.Context, task taskflow.Task) ([]taskflow.PortProbeResult, error) {
	if os.Geteuid() == 0 {
		return nil, fmt.Errorf("run scanning Worker as an ordinary user")
	}
	if task.Synthetic || len(task.Engines) != 1 || task.Engines[0] != "port-probe" || len(task.Chunks) != 1 || len(task.Chunks[0].Targets) != 1 || task.AssetID == "" || !task.PortProbeConfig.OpsApproved {
		return nil, fmt.Errorf("invalid TCP port probe task")
	}
	if !validProbePortPlan(task.PortProbeConfig, task.PortProbePorts) {
		return nil, fmt.Errorf("invalid TCP port probe task")
	}
	open, err := portprobe.Scan(ctx, task.Chunks[0].Targets[0], task.PortProbePorts)
	if err != nil {
		return nil, err
	}
	results := make([]taskflow.PortProbeResult, 0, len(open))
	for _, port := range open {
		results = append(results, taskflow.PortProbeResult{Port: port})
	}
	return results, nil
}

func validProbePortPlan(config portprobe.Config, dispatched []int) bool {
	selected, err := portprobe.SelectPorts(config)
	if err != nil || len(dispatched) == 0 || len(dispatched) > portprobe.MaxPorts {
		return false
	}
	allowed := make(map[int]bool, len(selected))
	for _, port := range selected {
		allowed[port] = true
	}
	previous := 0
	for _, port := range dispatched {
		if !allowed[port] || port <= previous {
			return false
		}
		previous = port
	}
	return true
}

func decodeStrict(data []byte, value any) error {
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	if decoder.Decode(new(any)) != io.EOF {
		return fmt.Errorf("trailing JSON")
	}
	return nil
}

func (r *Runner) checkVersions() {
	r.versionOnce.Do(func() {
		r.versionErrors = map[string]error{}
		for _, engine := range []string{"nuclei", "trivy", "zap"} {
			binary := r.binary(engine)
			args := []string{"--version"}
			expected := TrivyVersion
			if engine == "nuclei" {
				args = []string{"-version"}
				expected = NucleiVersion
			}
			if engine == "zap" {
				var err error
				binary, err = exec.LookPath("java")
				if err != nil {
					r.versionErrors[engine] = fmt.Errorf("Java 17+ required")
					continue
				}
				args = []string{"-jar", r.zapJAR(), "-version"}
				expected = ZAPVersion
			}
			dir, err := os.MkdirTemp("", "scanner-engine-version-")
			if err != nil {
				r.versionErrors[engine] = err
				continue
			}
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			command := exec.CommandContext(ctx, binary, args...)
			command.Env = privateEnv(dir)
			command.Dir = dir
			command.WaitDelay = time.Second
			var output bytes.Buffer
			command.Stdout = &output
			command.Stderr = &output
			err = command.Run()
			cancel()
			_ = os.RemoveAll(dir)
			if err != nil || !strings.Contains(output.String(), expected) {
				r.versionErrors[engine] = fmt.Errorf("%s %s required; verify installed binary/runtime", engine, expected)
			}
		}
	})
}
