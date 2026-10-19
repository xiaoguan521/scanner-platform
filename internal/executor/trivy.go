package executor

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"scanner-platform/internal/executor/engineflags"
	"scanner-platform/internal/taskflow"
)

func localInput(root, relative string, kind string) (string, error) {
	if !filepath.IsLocal(relative) || strings.ContainsAny(relative, "\\:\x00") {
		return "", fmt.Errorf("input must be a relative path beneath Worker inputs directory")
	}
	root, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	path := filepath.Join(root, relative)
	for p := path; ; p = filepath.Dir(p) {
		info, err := os.Lstat(p)
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("input missing or contains a symlink")
		}
		if p == root {
			break
		}
	}
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if kind == "image-archive" {
		if !info.Mode().IsRegular() {
			return "", fmt.Errorf("image archive must be a regular file")
		}
	} else if kind == "filesystem" || kind == "rootfs" || kind == "artifact" {
		if !info.IsDir() {
			return "", fmt.Errorf("filesystem input must be a directory")
		}
		count := 0
		if err := filepath.WalkDir(path, func(_ string, entry os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			count++
			if count > 200000 || entry.Type()&os.ModeSymlink != 0 || (!entry.IsDir() && !entry.Type().IsRegular()) {
				return fmt.Errorf("filesystem input has too many entries, a symlink or a special file")
			}
			return nil
		}); err != nil {
			return "", err
		}
	} else {
		return "", fmt.Errorf("invalid Trivy input kind")
	}
	return path, nil
}

func copyDBFile(src, dst string) error {
	input, err := os.Open(src)
	if err != nil {
		return err
	}
	defer input.Close()
	output, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer output.Close()
	_, err = io.Copy(output, input)
	return err
}

func (r *Runner) trivy(ctx context.Context, task taskflow.Task, dir string) ([]taskflow.Detection, error) {
	input, err := localInput(r.InputsDir, task.InputPath, task.InputKind)
	if err != nil {
		return nil, err
	}
	if task.InputKind == "rootfs" {
		if err := validateLinuxRelease(input); err != nil {
			return nil, err
		}
	}
	snapshot, err := verifyInputSnapshot(ctx, input, task.InputKind)
	if err != nil {
		if ctx.Err() == nil {
			return nil, &taskflow.ExecutionError{UserMessage: "离线快照校验失败，请完整重新采集和传输文件（包含隐藏清单），不要在扫描期间修改输入"}
		}
		return nil, err
	}
	sourceInput := input
	if task.InputKind == "image-archive" {
		layout := filepath.Join(dir, "oci-input")
		defer os.RemoveAll(layout)
		input, err = prepareImageInput(ctx, input, layout)
		if err != nil {
			return nil, err
		}
	}
	rulesDir, err := r.ruleDirectory(ctx, task.RuleVersion, "trivy")
	if err != nil {
		return nil, err
	}
	if task.InputKind == "filesystem" || task.InputKind == "artifact" {
		java, artifacts, err := inspectApplicationInput(ctx, input, task.InputKind == "artifact")
		if err != nil {
			return nil, err
		}
		if task.InputKind == "filesystem" && artifacts {
			return nil, &taskflow.ExecutionError{UserMessage: "该目录含 JAR 或 ELF，请用已部署应用类型检查；依赖清单与部署产物混合时请用采集工具拆分"}
		}
		if java {
			if !hasJavaDB(rulesDir) {
				return nil, &taskflow.ExecutionError{UserMessage: "此任务包含 Java 归档，但固定规则版本没有 Java 索引；请运行 make engines-java，待新版本同步后重新创建任务"}
			}
		}
	}
	// Private writable cache; immutable release files are never opened for writing.
	cache := filepath.Join(r.RuntimeDir, "trivy-cache-v"+TrivyVersion+"-"+task.RuleVersion)
	if _, err := os.Stat(filepath.Join(cache, ".ready")); os.IsNotExist(err) {
		_ = os.RemoveAll(cache)
		for _, sub := range []string{"db", "java-db"} {
			source := filepath.Join(rulesDir, sub)
			if _, err := os.Stat(source); os.IsNotExist(err) && sub == "java-db" {
				continue
			}
			if err := os.MkdirAll(filepath.Join(cache, sub), 0700); err != nil {
				return nil, err
			}
			entries, err := os.ReadDir(source)
			if err != nil {
				return nil, fmt.Errorf("Trivy rule layout requires trivy/db/{trivy.db,metadata.json}")
			}
			for _, entry := range entries {
				if entry.IsDir() {
					return nil, fmt.Errorf("unexpected DB directory")
				}
				if err := copyDBFile(filepath.Join(source, entry.Name()), filepath.Join(cache, sub, entry.Name())); err != nil {
					return nil, err
				}
			}
		}
		if err := os.WriteFile(filepath.Join(cache, ".ready"), []byte(task.RuleVersion), 0600); err != nil {
			return nil, err
		}
	}
	output := filepath.Join(dir, "trivy.json")
	if err := runProcess(ctx, r.binary("trivy"), engineflags.TrivyArgs(task.InputKind, input, cache, output), dir, io.Discard); err != nil {
		return nil, err
	}
	info, err := os.Stat(output)
	if err != nil || info.Size() > 32<<20 {
		return nil, fmt.Errorf("missing or oversized Trivy report")
	}
	data, err := os.ReadFile(output)
	if err != nil {
		return nil, err
	}
	detections, err := parseTrivy(data, task.InputPath, task.InputKind == "rootfs")
	if err != nil {
		return nil, err
	}
	// An operator must not refresh an input while a task is reading it. Check
	// a collected snapshot again before accepting the engine's full result.
	if snapshot != "" {
		after, err := verifyInputSnapshot(ctx, sourceInput, task.InputKind)
		if err != nil {
			return nil, fmt.Errorf("verify completed snapshot: %w", err)
		}
		if after != snapshot {
			return nil, fmt.Errorf("input snapshot changed during scan")
		}
	}
	for i := range detections {
		if task.InputKind == "rootfs" {
			detections[i].MatchedPath = "OS packages"
		} else if task.InputKind == "filesystem" || task.InputKind == "artifact" {
			detections[i].MatchedPath = strings.TrimPrefix(detections[i].MatchedPath, filepath.ToSlash(input)+"/")
		}
		if snapshot != "" {
			detections[i].Description = strings.TrimSpace(detections[i].Description + "\n" + snapshot)
		}
	}
	return detections, nil
}

func hasJavaDB(rulesDir string) bool {
	return hasDBFiles(filepath.Join(rulesDir, "java-db"), "trivy-java.db")
}

func hasDBFiles(dir, database string) bool {
	for _, name := range []string{database, "metadata.json"} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
			return false
		}
	}
	return true
}

func inspectApplicationInput(ctx context.Context, root string, artifactsOnly bool) (bool, bool, error) {
	found := false
	artifacts := false
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if !entry.IsDir() {
			switch strings.ToLower(filepath.Ext(path)) {
			case ".jar", ".war", ".ear", ".par":
				found = true
				artifacts = true
				return nil
			}
			if entry.Name() == snapshotName {
				return nil
			}
			file, err := os.Open(path)
			if err != nil {
				return err
			}
			var magic [4]byte
			_, readErr := io.ReadFull(file, magic[:])
			file.Close()
			if readErr != nil && readErr != io.EOF && readErr != io.ErrUnexpectedEOF {
				return readErr
			}
			if string(magic[:]) == "\x7fELF" {
				artifacts = true
				return nil
			}
			if artifactsOnly {
				return &taskflow.ExecutionError{UserMessage: "已部署应用输入只接受 JAR/WAR/EAR/PAR 和 Go ELF；锁文件请使用依赖目录类型，混合目录请先采集拆分"}
			}
		}
		return nil
	})
	return found, artifacts, err
}

func ParseTrivy(data []byte, target string) ([]taskflow.Detection, error) {
	return parseTrivy(data, target, false)
}

func parseTrivy(data []byte, target string, requireOS bool) ([]taskflow.Detection, error) {
	var report struct {
		Metadata struct {
			ImageID string `json:"ImageID"`
			OS      struct {
				EOSL bool `json:"EOSL"`
			} `json:"OS"`
		} `json:"Metadata"`
		Results []struct {
			Class           string `json:"Class"`
			Target          string `json:"Target"`
			Vulnerabilities []struct {
				ID          string   `json:"VulnerabilityID"`
				Name        string   `json:"PkgName"`
				Installed   string   `json:"InstalledVersion"`
				Fixed       string   `json:"FixedVersion"`
				Title       string   `json:"Title"`
				Severity    string   `json:"Severity"`
				Description string   `json:"Description"`
				References  []string `json:"References"`
				CVSS        map[string]struct {
					V3Score *float64 `json:"V3Score"`
					V2Score *float64 `json:"V2Score"`
				} `json:"CVSS"`
			} `json:"Vulnerabilities"`
		} `json:"Results"`
	}
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("invalid Trivy JSON report")
	}
	if len(report.Results) == 0 {
		return nil, fmt.Errorf("Trivy found no supported package manifests or OS packages in the input")
	}
	if requireOS {
		found := false
		for _, result := range report.Results {
			found = found || result.Class == "os-pkgs"
		}
		if !found {
			return nil, fmt.Errorf("Trivy could not analyze OS packages; check Linux distribution and collected package database")
		}
	}
	out := []taskflow.Detection{}
	for _, result := range report.Results {
		if requireOS && result.Class != "os-pkgs" {
			continue
		}
		for _, v := range result.Vulnerabilities {
			if v.ID == "" || v.Name == "" {
				return nil, fmt.Errorf("incomplete Trivy vulnerability")
			}
			title := v.Title
			if title == "" {
				title = v.ID + " in " + v.Name
			}
			description := safeText(v.Description, 3000)
			if report.Metadata.OS.EOSL {
				description += "\n系统版本已超出上游常规维护期；漏洞结果和修复版本受公告源覆盖限制，未检出不表示系统无漏洞。"
			}
			var score *float64
			vendors := make([]string, 0, len(v.CVSS))
			for vendor := range v.CVSS {
				vendors = append(vendors, vendor)
			}
			sort.Strings(vendors)
			for _, vendor := range vendors {
				item := v.CVSS[vendor]
				candidate := item.V3Score
				if candidate == nil {
					candidate = item.V2Score
				}
				if candidate != nil && *candidate >= 0 && *candidate <= 10 {
					score = candidate
					if vendor == "nvd" {
						break
					}
				}
			}
			refs := []string{}
			for _, ref := range v.References {
				if len(refs) < 20 {
					refs = append(refs, safeText(ref, 2000))
				}
			}
			solution := ""
			if v.Fixed != "" {
				solution = "结合发行版或软件厂商公告，升级至引擎报告的修复版本：" + safeText(v.Fixed, 1000)
			}
			out = append(out, taskflow.Detection{RiskType: "system", DetectMethod: "version", Confidence: "medium", CVSSScore: score, References: refs, Solution: solution, Component: safeText(v.Name+":"+v.Installed, 300), VulnCategory: "软件版本漏洞", Evidence: safeText(v.Name+":"+v.Installed, 300) + "；根据漏洞库匹配，未进行原理验证。", ContentLanguage: "original", Engine: "trivy", TemplateID: safeText(v.ID, 200), Target: target, Title: safeText(title, 500), Severity: severity(v.Severity), MatchedPath: safeText(filepath.ToSlash(result.Target), 1000), Package: safeText(v.Name, 300), InstalledVersion: safeText(v.Installed, 200), FixedVersion: safeText(v.Fixed, 1000), ArtifactID: report.Metadata.ImageID, Description: description})
			if len(out) > 2000 {
				return nil, fmt.Errorf("too many findings; split the input")
			}
		}
	}
	return out, nil
}
