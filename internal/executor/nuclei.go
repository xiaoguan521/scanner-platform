package executor

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"scanner-platform/internal/executor/engineflags"
	"scanner-platform/internal/rules"
	"scanner-platform/internal/taskflow"
)

type Template struct {
	ID   string `json:"id"`
	Info struct {
		Name        string `json:"name"`
		Author      string `json:"author"`
		Severity    string `json:"severity"`
		Description string `json:"description,omitempty"`
		Tags        string `json:"tags,omitempty"`
	} `json:"info"`
	HTTP []struct {
		Method    string   `json:"method"`
		Path      []string `json:"path"`
		Condition string   `json:"matchers-condition,omitempty"`
		Matchers  []struct {
			Type            string   `json:"type"`
			Part            string   `json:"part,omitempty"`
			Words           []string `json:"words,omitempty"`
			Regex           []string `json:"regex,omitempty"`
			Status          []int    `json:"status,omitempty"`
			Negative        bool     `json:"negative,omitempty"`
			Condition       string   `json:"condition,omitempty"`
			CaseInsensitive bool     `json:"case-insensitive,omitempty"`
		} `json:"matchers"`
	} `json:"http"`
}

// JSON is a YAML subset understood by Nuclei. Accept a deliberately narrow
// read-only profile; unreviewed upstream templates cannot execute arbitrary
// protocols, requests, payloads, workflows or external addresses.
func ValidateTemplate(data []byte) (Template, error) {
	var t Template
	if len(data) > 64<<10 || decodeStrict(data, &t) != nil || !regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,99}$`).MatchString(t.ID) || t.Info.Name == "" || len(t.HTTP) != 1 {
		return t, fmt.Errorf("template must use the supported JSON root-GET baseline profile")
	}
	request := t.HTTP[0]
	if request.Method != "GET" || len(request.Path) != 1 || request.Path[0] != "{{BaseURL}}" && request.Path[0] != "{{BaseURL}}/" || len(request.Matchers) == 0 || len(request.Matchers) > 8 {
		return t, fmt.Errorf("only a single root GET is permitted")
	}
	for _, m := range request.Matchers {
		if m.Condition != "" && m.Condition != "and" && m.Condition != "or" {
			return t, fmt.Errorf("unsupported matcher condition")
		}
		if m.Part != "" && m.Part != "header" && m.Part != "body" {
			return t, fmt.Errorf("unsupported matcher part")
		}
		switch m.Type {
		case "word":
			if len(m.Words) == 0 {
				return t, fmt.Errorf("empty word matcher")
			}
		case "regex":
			if len(m.Regex) == 0 {
				return t, fmt.Errorf("empty regex matcher")
			}
			for _, s := range m.Regex {
				if _, err := regexp.Compile(s); err != nil {
					return t, err
				}
			}
		case "status":
			if len(m.Status) == 0 {
				return t, fmt.Errorf("empty status matcher")
			}
		default:
			return t, fmt.Errorf("unsupported matcher type")
		}
	}
	return t, nil
}

func (r *Runner) nuclei(ctx context.Context, task taskflow.Task, dir string) ([]taskflow.Detection, error) {
	if task.Scheme != "http" && task.Scheme != "https" {
		return nil, fmt.Errorf("HTTP scheme required")
	}
	rulesDir, err := r.ruleDirectory(ctx, task.RuleVersion, "nuclei")
	if err != nil {
		return nil, err
	}
	destination := filepath.Join(dir, "templates")
	if err := os.Mkdir(destination, 0700); err != nil {
		return nil, err
	}
	manifestData, err := os.ReadFile(filepath.Join(filepath.Dir(rulesDir), "manifest.json"))
	if err != nil {
		return nil, err
	}
	var manifest rules.Manifest
	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		return nil, err
	}
	count := 0
	for name := range manifest.Files {
		if !strings.HasPrefix(name, "nuclei/") || !strings.HasSuffix(name, ".json") {
			continue
		}
		path := filepath.Join(filepath.Dir(rulesDir), filepath.FromSlash(name))
		info, err := os.Stat(path)
		if err != nil || info.Size() > 64<<10 {
			return nil, fmt.Errorf("baseline template too large or missing")
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		t, err := ValidateTemplate(data)
		if err != nil {
			return nil, err
		}
		if _, err := os.Stat(filepath.Join(destination, t.ID+".json")); err == nil {
			return nil, fmt.Errorf("duplicate template ID")
		}
		count++
		if count > 100 {
			return nil, fmt.Errorf("baseline profile allows at most 100 templates")
		}
		if err := os.WriteFile(filepath.Join(destination, t.ID+".json"), data, 0600); err != nil {
			return nil, err
		}
	}

	if count == 0 {
		return nil, fmt.Errorf("no supported baseline JSON templates in pinned rules")
	}
	for _, data := range task.CustomTemplates {
		t, err := ValidateTemplate(data)
		if err != nil || t.Info.Author != "scanner-platform custom rule" || !strings.Contains(t.Info.Tags, "custom") {
			return nil, fmt.Errorf("task contains an invalid custom read-only rule")
		}
		if _, err := os.Stat(filepath.Join(destination, t.ID+".json")); err == nil {
			return nil, fmt.Errorf("duplicate custom template ID")
		}
		count++
		if count > 120 {
			return nil, fmt.Errorf("baseline and custom template limit exceeded")
		}
		if err := os.WriteFile(filepath.Join(destination, t.ID+".json"), data, 0600); err != nil {
			return nil, err
		}
	}
	targets := task.Chunks[0].Targets
	urls := []string{}
	for _, target := range targets {
		if _, err := numericTarget(target); err != nil {
			return nil, err
		}
		urls = append(urls, task.Scheme+"://"+target)
	}
	input := filepath.Join(dir, "targets.txt")
	if err := os.WriteFile(input, []byte(strings.Join(urls, "\n")+"\n"), 0600); err != nil {
		return nil, err
	}
	proxy, err := startScopeProxy(ctx, targets)
	if err != nil {
		return nil, err
	}
	defer proxy.Close()
	// A successful process with no matches cannot prove that its targets answered.
	// Check reachability with the same bounded, no-redirect root GET used by ZAP.
	for _, raw := range urls {
		if _, err := fetchRoot(ctx, raw, r.Timeout); err != nil {
			return nil, fmt.Errorf("target did not return an HTTP response: %w", err)
		}
	}
	var output bytes.Buffer
	errorFile := filepath.Join(dir, "requests.errors")
	if err := runProcess(ctx, r.binary("nuclei"), engineflags.NucleiArgs(input, destination, proxy.URL(), errorFile, httpRequestRate(ctx, r.Rate), r.Timeout), dir, &output); err != nil {
		return nil, err
	}
	if info, err := os.Stat(errorFile); err == nil && info.Size() > 0 {
		return nil, fmt.Errorf("Nuclei reported request errors; scan is incomplete")
	}
	proxy.mu.Lock()
	blocked := proxy.blocked
	failed := proxy.failed
	proxy.mu.Unlock()
	if failed > 0 {
		return nil, fmt.Errorf("engine proxy encountered a failed or incomplete target response")
	}
	if blocked > 0 {
		return nil, fmt.Errorf("engine attempted a target outside explicit list")
	}
	parsed, err := ParseNuclei(output.Bytes(), targets)
	if err != nil {
		return nil, err
	}
	checks, err := checkWebConfiguration(ctx, task.Scheme, targets, r.Rate, r.Timeout)
	if err != nil {
		return nil, err
	}
	keys := map[string]bool{}
	for _, check := range checks {
		keys[check.TemplateID+"\x00"+check.Target+"\x00"+check.MatchedPath] = true
	}
	out := make([]taskflow.Detection, 0, len(parsed)+len(checks))
	for _, finding := range parsed {
		if finding.TemplateID == "baseline-nosniff" || finding.TemplateID == "baseline-csp" || finding.TemplateID == "baseline-frame-options" {
			continue
		}
		if !keys[finding.TemplateID+"\x00"+finding.Target+"\x00"+finding.MatchedPath] {
			out = append(out, finding)
		}
	}
	return append(out, checks...), nil
}

func ParseNuclei(data []byte, targets []string) ([]taskflow.Detection, error) {
	allowed := map[string]bool{}
	for _, target := range targets {
		allowed[target] = true
	}
	out := []taskflow.Detection{}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 4096), 1<<20)
	for scanner.Scan() {
		if strings.TrimSpace(scanner.Text()) == "" {
			continue
		}
		var result struct {
			TemplateID string `json:"template-id"`
			MatchedAt  string `json:"matched-at"`
			Info       struct {
				Name        string `json:"name"`
				Severity    string `json:"severity"`
				Description string `json:"description"`
			} `json:"info"`
		}
		if json.Unmarshal(scanner.Bytes(), &result) != nil || result.TemplateID == "" {
			return nil, fmt.Errorf("invalid Nuclei JSONL")
		}
		u, err := url.Parse(result.MatchedAt)
		if err != nil || u.User != nil || u.Scheme != "http" && u.Scheme != "https" {
			return nil, fmt.Errorf("invalid matched URL")
		}
		port := u.Port()
		if port == "" {
			port = "80"
			if u.Scheme == "https" {
				port = "443"
			}
		}
		target, err := numericTarget(net.JoinHostPort(u.Hostname(), port))
		if err != nil || !allowed[target] {
			return nil, fmt.Errorf("out-of-scope Nuclei result")
		}
		path := u.EscapedPath()
		if path == "" {
			path = "/"
		}
		out = append(out, taskflow.Detection{Engine: "nuclei", TemplateID: result.TemplateID, Target: target, Title: safeText(result.Info.Name, 500), Severity: severity(result.Info.Severity), MatchedPath: path, Description: safeText(result.Info.Description, 4000)})
		if len(out) > 2000 {
			return nil, fmt.Errorf("too many findings")
		}
	}
	return out, scanner.Err()
}

func severity(raw string) string {
	switch strings.ToUpper(raw) {
	case "CRITICAL", "HIGH", "MEDIUM", "LOW":
		return strings.ToUpper(raw)
	default:
		return "INFO"
	}
}
