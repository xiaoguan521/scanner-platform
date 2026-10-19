package executor

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"scanner-platform/internal/taskflow"
)

var readOnlyWebPaths = map[string]bool{"/": true, "/actuator/env": true, "/server-status?auto": true}

// checkWebConfiguration issues only four fixed read-only requests per explicit
// endpoint. It never submits credentials, follows links or attempts a write.
func checkWebConfiguration(ctx context.Context, scheme string, targets []string, rate, timeout int) ([]taskflow.Detection, error) {
	if scheme != "http" && scheme != "https" {
		return nil, fmt.Errorf("invalid web check scheme")
	}
	if rate < 1 || rate > 250 {
		rate = 5
	}
	if timeout < 1 || timeout > 60 {
		timeout = 10
	}
	allowed := make(map[string]bool, len(targets))
	for _, t := range targets {
		canonical, err := numericTarget(t)
		if err != nil {
			return nil, err
		}
		allowed[canonical] = true
	}
	budget := &identificationBudget{remaining: len(targets) * 4, interval: time.Second / time.Duration(rate)}
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, MaxConnsPerHost: 1, MaxResponseHeaderBytes: 32 << 10, TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		canonical, err := numericTarget(address)
		if err != nil || !allowed[canonical] || network != "tcp" {
			return nil, fmt.Errorf("web check connection outside explicit endpoints")
		}
		if !budget.take(ctx) {
			return nil, fmt.Errorf("web check request budget exhausted")
		}
		return (&net.Dialer{Timeout: time.Duration(timeout) * time.Second}).DialContext(ctx, network, canonical)
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: time.Duration(timeout) * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	findings := []taskflow.Detection{}
	for _, target := range targets {
		for _, check := range []struct{ method, path string }{{http.MethodGet, "/"}, {http.MethodOptions, "/"}, {http.MethodGet, "/actuator/env"}, {http.MethodGet, "/server-status?auto"}} {
			c, err := fetchReadOnlyWeb(ctx, client, scheme, target, check.method, check.path)
			if err != nil {
				return nil, fmt.Errorf("read-only web check incomplete: %w", err)
			}
			add := func(id, title, severity, category, evidence, solution string) {
				u, _ := url.Parse(c.URL)
				port := 0
				fmt.Sscanf(u.Port(), "%d", &port)
				findings = append(findings, taskflow.Detection{Engine: "nuclei", TemplateID: webCheckID(id), Target: target, Title: title, Severity: severity, MatchedPath: u.EscapedPath(), Description: "只读配置检查；未执行写入、登录或漏洞利用。", RiskType: "web", DetectMethod: "configuration", Confidence: "high", VulnCategory: category, Evidence: evidence, Solution: solution, Port: port, ContentLanguage: "zh-CN"})
			}
			if check.method == http.MethodOptions {
				advertised := []string{}
				for _, method := range strings.Split(strings.ToUpper(c.Headers.Get("Allow")), ",") {
					m := strings.TrimSpace(method)
					if m == "PUT" || m == "DELETE" || m == "PATCH" || m == "TRACE" {
						advertised = append(advertised, m)
					}
				}
				if len(advertised) > 0 {
					add("methods-advertised", "服务声明启用需审查的 HTTP 方法", "LOW", "misconfiguration", "OPTIONS Allow 声明: "+strings.Join(advertised, ", ")+"；仅检查声明，未实际调用这些方法", "按业务需要限制 HTTP 方法，并复核网关与应用配置。")
				}
				continue
			}
			body := strings.ToLower(string(c.Body))
			switch check.path {
			case "/":
				if c.Status < 200 || c.Status >= 400 {
					continue
				}
				for _, h := range []struct{ name, id, title string }{{"X-Content-Type-Options", "nosniff", "响应缺少 X-Content-Type-Options"}, {"Content-Security-Policy", "csp", "响应缺少 Content-Security-Policy"}, {"X-Frame-Options", "frame-options", "响应缺少点击劫持保护头"}} {
					if c.Headers.Get(h.name) == "" && (h.id != "frame-options" || !strings.Contains(strings.ToLower(c.Headers.Get("Content-Security-Policy")), "frame-ancestors")) {
						add(h.id, h.title, "LOW", "misconfiguration", "根路径 HTTP 响应未提供 "+h.name, "结合应用用途配置相应安全响应头。")
					}
				}
				if scheme == "https" && c.Headers.Get("Strict-Transport-Security") == "" {
					add("hsts", "HTTPS 响应缺少 HSTS", "LOW", "misconfiguration", "HTTPS 根路径响应未提供 Strict-Transport-Security", "确认全站 HTTPS 后配置合理的 HSTS 策略。")
				}
				origin := c.Headers.Get("Access-Control-Allow-Origin")
				if strings.EqualFold(c.Headers.Get("Access-Control-Allow-Credentials"), "true") && (origin == "*" || origin == "https://audit.example.test") {
					add("cors-credentials", "CORS 凭据策略需要审查", "MEDIUM", "misconfiguration", "响应允许凭据，并允许通配来源或回显本次测试来源；未读取任何用户会话", "仅允许业务信任的明确来源，避免对任意来源启用凭据。")
				}
				if strings.Contains(body, "welcome to nginx") || strings.Contains(body, "apache tomcat") && strings.Contains(body, "successfully installed") {
					add("default-page", "发现中间件默认欢迎页面", "LOW", "information_disclosure", "根路径页面包含中间件默认欢迎页特征", "移除默认页面和不需要的示例应用。")
				}
			case "/actuator/env":
				var data map[string]json.RawMessage
				if c.Status == 200 && json.Unmarshal(c.Body, &data) == nil && (len(data["propertySources"]) > 0 || len(data["systemProperties"]) > 0) {
					add("actuator-env", "环境配置接口可无需认证读取", "MEDIUM", "unauthorized_access", "GET /actuator/env 返回环境配置结构；举证不保留配置值", "关闭公开环境端点，或使用严格的网络范围与身份认证。")
				}
			case "/server-status?auto":
				if c.Status == 200 && strings.Contains(body, "total accesses:") && strings.Contains(body, "busyworkers:") {
					add("server-status", "服务器运行状态接口可无需认证读取", "LOW", "information_disclosure", "GET /server-status?auto 返回 Apache 状态字段；举证不保留运行数据", "限制状态接口只对运维身份或明确授权来源开放。")
				}
			}
		}
	}
	return findings, nil
}

func fetchReadOnlyWeb(ctx context.Context, client *http.Client, scheme, target, method, path string) (capturedResponse, error) {
	if !readOnlyWebPaths[path] || method != http.MethodGet && method != http.MethodOptions || method == http.MethodOptions && path != "/" {
		return capturedResponse{}, fmt.Errorf("request outside read-only web allowlist")
	}
	if _, err := numericTarget(target); err != nil {
		return capturedResponse{}, err
	}
	raw := scheme + "://" + target + path
	req, err := http.NewRequestWithContext(ctx, method, raw, nil)
	if err != nil {
		return capturedResponse{}, err
	}
	req.Header.Set("User-Agent", "scanner-platform/configuration")
	req.Header.Set("Origin", "https://audit.example.test")
	if err := takeHTTPRequest(ctx, target); err != nil {
		return capturedResponse{}, err
	}
	response, err := client.Do(req)
	if err != nil {
		return capturedResponse{}, fmt.Errorf("HTTP endpoint did not answer")
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 64<<10))
	if err != nil {
		return capturedResponse{}, fmt.Errorf("HTTP response incomplete")
	}
	return capturedResponse{URL: raw, Status: response.StatusCode, Headers: response.Header, Body: body}, nil
}

func webCheckID(id string) string {
	if id == "nosniff" || id == "csp" || id == "frame-options" {
		return "baseline-" + id
	}
	return "web-" + id
}
