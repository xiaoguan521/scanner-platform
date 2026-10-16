package executor

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"scanner-platform/internal/executor/engineflags"
	"scanner-platform/internal/taskflow"
)

type capturedResponse struct {
	URL        string
	Status     int
	StatusText string
	Headers    http.Header
	Body       []byte
	Duration   int64
}

func fetchRoot(ctx context.Context, raw string, timeout int) (capturedResponse, error) {
	u, err := url.Parse(raw)
	if err != nil || u.User != nil || u.Scheme != "http" && u.Scheme != "https" || u.Path != "" && u.Path != "/" || u.RawQuery != "" || u.Fragment != "" {
		return capturedResponse{}, fmt.Errorf("only explicit root HTTP URLs are allowed")
	}
	if _, err := numericTarget(u.Host); err != nil {
		return capturedResponse{}, err
	}
	transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, DialContext: (&net.Dialer{Timeout: time.Duration(timeout) * time.Second}).DialContext} // Scanner accepts self-signed test services; no credentials are sent.
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: time.Duration(timeout) * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return capturedResponse{}, err
	}
	req.Header.Set("User-Agent", "scanner-platform/baseline")
	start := time.Now()
	response, err := client.Do(req)
	if err != nil {
		return capturedResponse{}, fmt.Errorf("root request failed")
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, (2<<20)+1))
	if err != nil {
		return capturedResponse{}, fmt.Errorf("read root response failed")
	}
	if len(body) > 2<<20 {
		return capturedResponse{}, fmt.Errorf("response exceeds 2 MiB; result incomplete")
	}
	return capturedResponse{URL: raw, Status: response.StatusCode, StatusText: http.StatusText(response.StatusCode), Headers: response.Header, Body: body, Duration: time.Since(start).Milliseconds()}, nil
}

func harEntry(c capturedResponse) map[string]any {
	headers := []map[string]string{}
	for name, values := range c.Headers {
		for _, value := range values {
			headers = append(headers, map[string]string{"name": name, "value": value})
		}
	}
	return map[string]any{"startedDateTime": time.Now().UTC().Format(time.RFC3339Nano), "time": c.Duration,
		"request":  map[string]any{"method": "GET", "url": c.URL, "httpVersion": "HTTP/1.1", "headers": []any{}, "cookies": []any{}, "queryString": []any{}, "headersSize": -1, "bodySize": 0},
		"response": map[string]any{"status": c.Status, "statusText": c.StatusText, "httpVersion": "HTTP/1.1", "headers": headers, "cookies": []any{}, "content": map[string]any{"size": len(c.Body), "mimeType": c.Headers.Get("Content-Type"), "text": base64.StdEncoding.EncodeToString(c.Body), "encoding": "base64"}, "redirectURL": c.Headers.Get("Location"), "headersSize": -1, "bodySize": len(c.Body)},
		"cache":    map[string]any{}, "timings": map[string]any{"send": 0, "wait": c.Duration, "receive": 0}}
}

func ZAPPlan(harFile, dir string, urls []string) map[string]any {
	include := []string{}
	for _, u := range urls {
		include = append(include, regexp.QuoteMeta(u)+"/?.*")
	}
	return map[string]any{
		"env": map[string]any{"contexts": []any{map[string]any{"name": "explicit-targets", "urls": urls, "includePaths": include}}, "parameters": map[string]any{"failOnError": true, "failOnWarning": true, "continueOnFailure": false}},
		"jobs": []any{
			map[string]any{"type": "passiveScan-config", "parameters": map[string]any{"scanOnlyInScope": true, "maxAlertsPerRule": 20, "maxBodySizeInBytesToScan": 2 << 20}},
			map[string]any{"type": "import", "parameters": map[string]any{"type": "har", "fileName": harFile}},
			map[string]any{"type": "passiveScan-wait", "parameters": map[string]any{"maxDuration": 3}},
			map[string]any{"type": "report", "parameters": map[string]any{"template": "traditional-json", "reportDir": dir, "reportFile": "zap-report", "displayReport": false}},
		},
	}
}

func (r *Runner) zap(ctx context.Context, task taskflow.Task, dir string) ([]taskflow.Detection, error) {
	if task.Scheme != "http" && task.Scheme != "https" {
		return nil, fmt.Errorf("HTTP scheme required")
	}
	entries := []any{}
	urls := []string{}
	for _, target := range task.Chunks[0].Targets {
		raw := task.Scheme + "://" + target
		response, err := fetchRoot(ctx, raw, r.Timeout)
		if err != nil {
			return nil, err
		}
		entries = append(entries, harEntry(response))
		urls = append(urls, raw)
	}
	har, _ := json.Marshal(map[string]any{"log": map[string]any{"version": "1.2", "creator": map[string]string{"name": "scanner-platform", "version": "1"}, "entries": entries}})
	harFile := filepath.Join(dir, "responses.har")
	if err := os.WriteFile(harFile, har, 0600); err != nil {
		return nil, err
	}
	plan, _ := json.MarshalIndent(ZAPPlan(harFile, dir, urls), "", "  ")
	planFile := filepath.Join(dir, "plan.yaml")
	if err := os.WriteFile(planFile, plan, 0600); err != nil {
		return nil, err
	}
	java, err := exec.LookPath("java")
	if err != nil {
		return nil, fmt.Errorf("Java 17+ is required for ZAP")
	}
	var output bytes.Buffer
	args := engineflags.ZAPArgs(r.zapJAR(), filepath.Join(dir, "zap-home"), planFile)
	if err := runProcess(ctx, java, args, dir, &output); err != nil {
		_ = os.WriteFile(filepath.Join(dir, "zap-startup.log"), output.Bytes(), 0600)
		return nil, err
	}
	info, err := os.Stat(filepath.Join(dir, "zap-report.json"))
	if err != nil || info.Size() > 32<<20 {
		return nil, fmt.Errorf("missing or oversized ZAP report")
	}
	report, err := os.ReadFile(filepath.Join(dir, "zap-report.json"))
	if err != nil {
		return nil, fmt.Errorf("ZAP did not create a report")
	}
	if len(report) > 32<<20 {
		return nil, fmt.Errorf("ZAP report too large")
	}
	return ParseZAP(report, task.Chunks[0].Targets)
}

func ParseZAP(data []byte, targets []string) ([]taskflow.Detection, error) {
	var report struct {
		Sites []struct {
			Alerts []struct {
				ID          string `json:"pluginid"`
				Name        string `json:"name"`
				Risk        string `json:"riskcode"`
				Description string `json:"desc"`
				Instances   []struct {
					URI string `json:"uri"`
				} `json:"instances"`
			} `json:"alerts"`
		} `json:"site"`
	}
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("invalid ZAP JSON report")
	}
	if len(report.Sites) == 0 {
		return nil, fmt.Errorf("ZAP report contains no imported sites")
	}
	allowed := map[string]bool{}
	for _, target := range targets {
		allowed[target] = true
	}
	out := []taskflow.Detection{}
	for _, site := range report.Sites {
		for _, alert := range site.Alerts {
			for _, instance := range alert.Instances {
				u, err := url.Parse(instance.URI)
				if err != nil || u.User != nil || u.Scheme != "http" && u.Scheme != "https" {
					return nil, fmt.Errorf("invalid ZAP result URL")
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
					return nil, fmt.Errorf("out-of-scope ZAP result")
				}
				risk := map[string]string{"0": "INFO", "1": "LOW", "2": "MEDIUM", "3": "HIGH"}[alert.Risk]
				if risk == "" {
					return nil, fmt.Errorf("invalid ZAP risk")
				}
				path := u.EscapedPath()
				if path == "" {
					path = "/"
				}
				description := regexp.MustCompile(`<[^>]+>`).ReplaceAllString(alert.Description, " ")
				out = append(out, taskflow.Detection{Engine: "zap", TemplateID: alert.ID, Target: target, Title: safeText(alert.Name, 500), Severity: risk, MatchedPath: path, Description: safeText(strings.TrimSpace(description), 4000)})
				if len(out) > 2000 {
					return nil, fmt.Errorf("too many findings")
				}
			}
		}
	}
	return out, nil
}
