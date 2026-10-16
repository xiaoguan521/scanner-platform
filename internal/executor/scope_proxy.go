package executor

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
)

func numericTarget(raw string) (string, error) {
	host, port, err := net.SplitHostPort(raw)
	if err != nil {
		return "", fmt.Errorf("explicit IP:port required")
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || ip.Zone() != "" || ip.IsMulticast() || ip.IsUnspecified() {
		return "", fmt.Errorf("numeric unicast IP required")
	}
	p, err := strconv.Atoi(port)
	if err != nil || p < 1 || p > 65535 {
		return "", fmt.Errorf("invalid port")
	}
	return net.JoinHostPort(ip.Unmap().String(), strconv.Itoa(p)), nil
}

type scopeProxy struct {
	server      *http.Server
	listener    net.Listener
	transport   *http.Transport
	allowed     map[string]bool
	mu          sync.Mutex
	connections []net.Conn
	blocked     int
	failed      int
}

func startScopeProxy(ctx context.Context, targets []string) (*scopeProxy, error) {
	p := &scopeProxy{allowed: map[string]bool{}, transport: &http.Transport{Proxy: nil, ResponseHeaderTimeout: 15 * time.Second}}
	for _, target := range targets {
		canonical, err := numericTarget(target)
		if err != nil {
			return nil, err
		}
		p.allowed[canonical] = true
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	p.listener = listener
	p.server = &http.Server{Handler: p, ReadHeaderTimeout: 5 * time.Second, BaseContext: func(net.Listener) context.Context { return ctx }}
	go func() { _ = p.server.Serve(listener) }()
	return p, nil
}
func (p *scopeProxy) URL() string { return "http://" + p.listener.Addr().String() }
func (p *scopeProxy) Close() {
	_ = p.server.Close()
	p.transport.CloseIdleConnections()
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, c := range p.connections {
		_ = c.Close()
	}
}
func (p *scopeProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	authority := r.URL.Host
	if r.Method == http.MethodConnect {
		authority = r.Host
	}
	canonical, err := numericTarget(authority)
	if err != nil || !p.allowed[canonical] || r.URL.User != nil {
		p.mu.Lock()
		p.blocked++
		p.mu.Unlock()
		http.Error(w, "target outside explicit IP:port list", 403)
		return
	}
	if r.Method == http.MethodConnect {
		remote, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(r.Context(), "tcp", canonical)
		if err != nil {
			p.mu.Lock()
			p.failed++
			p.mu.Unlock()
			http.Error(w, "target unavailable", 502)
			return
		}
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			remote.Close()
			http.Error(w, "tunnel unavailable", 500)
			return
		}
		client, buffer, err := hijacker.Hijack()
		if err != nil {
			remote.Close()
			return
		}
		p.mu.Lock()
		p.connections = append(p.connections, client, remote)
		p.mu.Unlock()
		_, _ = buffer.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
		_ = buffer.Flush()
		defer client.Close()
		defer remote.Close()
		go func() { _, _ = io.Copy(remote, buffer); remote.Close() }()
		_, _ = io.Copy(client, remote)
		return
	}
	if r.URL.Scheme != "http" || r.Method != http.MethodGet || r.URL.Path != "" && r.URL.Path != "/" || r.URL.RawQuery != "" {
		p.mu.Lock()
		p.blocked++
		p.mu.Unlock()
		http.Error(w, "only root GET baseline requests allowed", 403)
		return
	}
	request := r.Clone(r.Context())
	request.RequestURI = ""
	request.URL.Host = canonical
	request.Header.Del("Proxy-Authorization")
	request.Header.Del("Proxy-Connection")
	response, err := p.transport.RoundTrip(request)
	if err != nil {
		p.mu.Lock()
		p.failed++
		p.mu.Unlock()
		http.Error(w, "target unavailable", 502)
		return
	}
	defer response.Body.Close()
	for key, values := range response.Header {
		if strings.EqualFold(key, "Connection") {
			continue
		}
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(response.StatusCode)
	count, copyErr := io.Copy(w, io.LimitReader(response.Body, (2<<20)+1))
	if copyErr != nil || count > 2<<20 {
		p.mu.Lock()
		p.failed++
		p.mu.Unlock()
	}
}
