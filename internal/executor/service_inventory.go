package executor

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"scanner-platform/internal/inventory"
	"scanner-platform/internal/portprobe"
	"scanner-platform/internal/taskflow"
)

type identificationBudget struct {
	mu        sync.Mutex
	remaining int
	interval  time.Duration
	next      time.Time
}

func (b *identificationBudget) take(ctx context.Context) bool {
	b.mu.Lock()
	if b.remaining <= 0 {
		b.mu.Unlock()
		return false
	}
	b.remaining--
	delay := time.Until(b.next)
	if delay < 0 {
		delay = 0
	}
	b.next = time.Now().Add(delay + b.interval)
	b.mu.Unlock()
	return waitSmall(ctx, delay) == nil
}

func identifyServices(ctx context.Context, host string, ports []int, config portprobe.Config) []taskflow.ServiceResult {
	policy, err := portprobe.PolicyFor(config)
	if err != nil {
		return nil
	}
	attempts := config.IdentificationMaxAttempts
	if attempts == 0 {
		attempts = 3
	}
	attempts-- // Includes the successful discovery TCP connection.
	budget := config.IdentificationBudget
	if budget == 0 {
		budget = len(ports) * attempts
	}
	limiter := &identificationBudget{remaining: budget, interval: time.Second / time.Duration(policy.Rate)}
	results := make([]taskflow.ServiceResult, len(ports))
	jobs := make(chan int)
	var group sync.WaitGroup
	for range min(policy.Concurrency, autoProbeWorkers, len(ports)) {
		group.Add(1)
		go func() {
			defer group.Done()
			for i := range jobs {
				results[i] = identifyService(ctx, host, ports[i], policy.Timeout, attempts, config.QuarantineThreshold, limiter)
			}
		}()
	}
	for i := range ports {
		select {
		case jobs <- i:
		case <-ctx.Done():
			close(jobs)
			group.Wait()
			return results
		}
	}
	close(jobs)
	group.Wait()
	return results
}

func identifyService(ctx context.Context, host string, port int, timeout time.Duration, attempts, threshold int, budget *identificationBudget) inventory.Service {
	now := time.Now().UTC()
	s := inventory.Service{Port: port, Protocol: "tcp", State: "open", Kind: "OTHER", FirstSeen: now, LastSeen: now}
	target, err := numericTarget(net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return s
	}
	resets := 0
	if threshold == 0 {
		threshold = 2
	}
	for attempt := 0; attempt < attempts; attempt++ {
		if !budget.take(ctx) {
			s.State = "unidentified"
			break
		}
		probeCtx, cancel := context.WithTimeout(ctx, timeout)
		scheme := "http"
		if attempt > 0 {
			scheme = "https"
		}
		response, banner, err := identifyConnection(probeCtx, target, scheme, timeout)
		cancel()
		if banner != "" {
			if applyBanner(&s, banner) {
				return s
			}
			if strings.Contains(strings.ToLower(banner), "proxy protocol") {
				s.Quarantined = true
				s.QuarantineReason = "服务要求代理协议，疑似转发端口"
				return s
			}
			return s // An unsolicited non-HTTP banner is an open unknown protocol.
		}
		if err == nil {
			s.Kind = "HTTP"
			s.Scheme = scheme
			s.TLS = scheme == "https"
			s.ServiceName = "http"
			if s.TLS {
				s.ServiceName = "https"
			}
			s.URL = response.URL
			applyHTTPInventory(&s, response)
			return s
		}
		var netErr net.Error
		if errors.Is(err, io.EOF) || strings.Contains(strings.ToLower(err.Error()), "connection reset") || (errors.As(err, &netErr) && netErr.Timeout()) || errors.Is(err, context.DeadlineExceeded) {
			resets++
		}
	}
	if resets >= threshold {
		s.Quarantined = true
		s.QuarantineReason = "有限识别连接连续无响应、被关闭或复位，疑似转发；待人工核对"
	}
	return s
}

func identifyConnection(ctx context.Context, target, scheme string, timeout time.Duration) (capturedResponse, string, error) {
	canonical, err := numericTarget(target)
	if err != nil {
		return capturedResponse{}, "", err
	}
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", canonical)
	if err != nil {
		return capturedResponse{}, "", err
	}
	defer conn.Close()
	deadline := time.Now().Add(timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	var stream net.Conn = conn
	if scheme == "https" {
		c := tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
		if err := c.HandshakeContext(ctx); err != nil {
			return capturedResponse{}, "", err
		}
		stream = c
	} // No credentials are sent; inventory accepts self-signed endpoint certificates.
	reader := bufio.NewReaderSize(io.LimitReader(stream, 128<<10), 8192)
	if scheme == "http" {
		_ = conn.SetReadDeadline(time.Now().Add(min(100*time.Millisecond, timeout/4)))
		first, peekErr := reader.Peek(1)
		_ = conn.SetReadDeadline(deadline)
		if len(first) > 0 {
			lineBytes, _ := reader.ReadSlice('\n')
			line := string(lineBytes)
			if !strings.HasPrefix(line, "HTTP/") {
				return capturedResponse{}, safeText(line, 512), nil
			}
			return capturedResponse{}, "", fmt.Errorf("unsolicited HTTP response")
		}
		if peekErr != nil {
			var ne net.Error
			if !errors.As(peekErr, &ne) || !ne.Timeout() {
				return capturedResponse{}, "", peekErr
			}
		}
	}
	raw := scheme + "://" + canonical + "/"
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	req.Header.Set("User-Agent", "scanner-platform/inventory")
	req.Close = true
	if err := req.Write(stream); err != nil {
		return capturedResponse{}, "", err
	}
	response, err := http.ReadResponse(reader, req)
	if err != nil {
		return capturedResponse{}, "", err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 64<<10))
	if err != nil {
		return capturedResponse{}, "", err
	}
	return capturedResponse{URL: raw, Status: response.StatusCode, Headers: response.Header, Body: body}, "", nil
}

var titlePattern = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
var tagPattern = regexp.MustCompile(`<[^>]+>`)
var componentPattern = regexp.MustCompile(`(?i)(nginx|apache(?:-coyote)?|tomcat|jetty|microsoft-iis|openresty|caddy|gunicorn|werkzeug|express|php|asp\.net)[/ :]*([0-9][a-z0-9._+-]*)?`)
var linkPattern = regexp.MustCompile(`(?is)(?:href|action)\s*=\s*["']([^"']+)["']`)

func applyHTTPInventory(s *inventory.Service, c capturedResponse) {
	body := string(c.Body)
	lower := strings.ToLower(body)
	if match := titlePattern.FindStringSubmatch(body); len(match) > 1 {
		s.Title = safeText(strings.TrimSpace(html.UnescapeString(tagPattern.ReplaceAllString(match[1], " "))), 300)
	}
	header := c.Headers.Get("Server") + " " + c.Headers.Get("X-Powered-By")
	for _, m := range componentPattern.FindAllStringSubmatch(header, -1) {
		name := strings.ToLower(m[1])
		if s.Software == "" {
			s.Software = name
			s.Version = safeText(m[2], 100)
		}
		switch name {
		case "php":
			s.Language = "PHP"
		case "asp.net":
			s.Language = ".NET"
		case "express":
			s.Framework = "Express"
			s.Language = "JavaScript"
		default:
			s.Middleware = name
		}
	}
	if strings.Contains(lower, "apache tomcat") {
		s.Middleware = "tomcat"
		s.Application = "Apache Tomcat"
		s.Language = "Java"
		if s.Software == "" {
			s.Software = "tomcat"
		}
	}
	if strings.Contains(lower, "welcome to nginx") && s.Software == "" {
		s.Software = "nginx"
		s.Middleware = "nginx"
	}
	if strings.Contains(lower, "spring") && strings.Contains(lower, "whitelabel error page") {
		s.Framework = "Spring"
		s.Language = "Java"
	}
	root, _ := url.Parse(c.URL)
	add := func(raw, evidence string) {
		u, err := url.Parse(raw)
		if err != nil {
			return
		}
		u = root.ResolveReference(u)
		if u.User != nil || u.Scheme != root.Scheme || u.Host != root.Host {
			return
		}
		u.RawQuery = ""
		u.Fragment = ""
		if len(u.String()) > 2000 {
			return
		}
		for _, e := range s.LoginEntries {
			if e.URL == u.String() {
				return
			}
		}
		if len(s.LoginEntries) >= 10 {
			return
		}
		entry := inventory.LoginEntry{Type: "web", Name: "Web 登录入口", Port: s.Port, URL: u.String(), HTTPS: s.TLS, Evidence: evidence}
		if u.String() == c.URL && (strings.Contains(lower, "captcha") || strings.Contains(lower, "验证码")) {
			present := true
			entry.Captcha = &present
			entry.Evidence += "；页面存在验证码标识"
		}
		s.LoginEntries = append(s.LoginEntries, entry)
	}
	if strings.Contains(lower, "type=\"password\"") || strings.Contains(lower, "type='password'") {
		add(c.URL, "页面存在密码输入框；未尝试登录")
	}
	for _, m := range linkPattern.FindAllStringSubmatch(body, 100) {
		v := strings.ToLower(m[1])
		if strings.Contains(v, "login") || strings.Contains(v, "signin") || strings.Contains(v, "sign-in") {
			add(m[1], "页面链接指向登录路径；未访问或尝试登录")
		}
	}
	if c.Status == http.StatusUnauthorized && c.Headers.Get("WWW-Authenticate") != "" {
		add(c.URL, "服务返回 HTTP 认证要求；未尝试认证")
	}
}

func applyBanner(s *inventory.Service, banner string) bool {
	b := strings.TrimSpace(banner)
	lower := strings.ToLower(b)
	switch {
	case strings.HasPrefix(b, "SSH-"):
		s.ServiceName = "ssh"
		s.Application = "SSH"
		if at := strings.Index(lower, "openssh_"); at >= 0 {
			s.Software = "openssh"
			if fields := strings.Fields(strings.TrimPrefix(lower[at:], "openssh_")); len(fields) > 0 {
				s.Version = safeText(fields[0], 100)
			}
		}
		s.LoginEntries = []inventory.LoginEntry{{Type: "system", Name: "SSH 系统登录入口", Port: s.Port, Evidence: "服务返回 SSH 协议标识；未尝试认证"}}
		return true
	case strings.HasPrefix(b, "220") && (strings.Contains(lower, "ftp") || strings.Contains(lower, "smtp")):
		if strings.Contains(lower, "ftp") {
			s.ServiceName = "ftp"
		} else {
			s.ServiceName = "smtp"
		}
		s.Software = s.ServiceName
		return true
	case strings.HasPrefix(b, "+OK") && strings.Contains(lower, "pop3"):
		s.ServiceName = "pop3"
		return true
	case strings.HasPrefix(b, "* OK") && strings.Contains(lower, "imap"):
		s.ServiceName = "imap"
		return true
	case strings.Contains(lower, "mysql") || strings.Contains(lower, "mariadb"):
		s.ServiceName = "mysql"
		s.Database = "MySQL"
		s.Software = "mysql"
		return true
	case strings.HasPrefix(b, "-NOAUTH"):
		s.ServiceName = "redis"
		s.Database = "Redis"
		s.Software = "redis"
		return true
	}
	return false
}

// inferProfile records only explicit remote characteristics; an SSH version does not identify an OS.
func inferProfile(services []taskflow.ServiceResult) inventory.Profile {
	p := inventory.Profile{}
	for _, s := range services {
		if s.Software == "microsoft-iis" {
			p.OSFamily = "Windows"
			p.DeviceType = "服务器"
		}
	}
	return p
}

// profileFromRootfs reads only already-collected, validated local metadata.
func profileFromRootfs(root string) inventory.Profile {
	p := inventory.Profile{}
	for _, name := range []string{"etc/os-release", "usr/lib/os-release"} {
		f, err := os.Open(filepath.Join(root, filepath.FromSlash(name)))
		if err != nil {
			continue
		}
		data, err := io.ReadAll(io.LimitReader(f, (64<<10)+1))
		f.Close()
		if err != nil || len(data) > 64<<10 {
			return p
		}
		values := map[string]string{}
		for _, line := range strings.Split(string(data), "\n") {
			key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
			if !ok || strings.HasPrefix(key, "#") {
				continue
			}
			if _, exists := values[key]; exists {
				return p
			}
			values[key] = strings.Trim(value, `"'`)
		}
		if values["ID"] != "" {
			p.OSName = safeText(values["PRETTY_NAME"], 200)
			if p.OSName == "" {
				p.OSName = safeText(values["NAME"]+" "+values["VERSION_ID"], 200)
			}
			p.OSFamily = "Linux"
			p.DeviceType = "服务器"
		}
		return p
	}
	return p
}
