package bootstrap

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
)

const maxTLSPEMBytes = 4 << 20

// validateNodeListen accepts only an explicit numeric address. The node API
// must be bound separately from the loopback web listener; refusing an empty
// host or an unspecified address avoids accidentally publishing it on every
// interface from a local development command.
func validateNodeListen(addr string) error {
	host, portText, err := net.SplitHostPort(strings.TrimSpace(addr))
	if err != nil || host == "" || portText == "" {
		return errors.New("node listener must be a numeric IP:port")
	}
	if net.ParseIP(host) == nil {
		return errors.New("node listener host must be a numeric IP")
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return errors.New("node listener port is invalid")
	}
	if ip := net.ParseIP(host); ip.IsUnspecified() || ip.IsMulticast() {
		return errors.New("node listener host must be a specific unicast IP")
	}
	return nil
}

func readTLSPEM(path string, privateKey bool) ([]byte, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("TLS file path is required")
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("TLS file must be a regular non-symlink file")
	}
	if privateKey && info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("TLS private key must be owner-only")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("open TLS file failed")
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxTLSPEMBytes+1))
	if err != nil || len(data) == 0 || len(data) > maxTLSPEMBytes {
		return nil, errors.New("TLS file is empty or too large")
	}
	return data, nil
}

func loadNodeTLSConfig(certPath, keyPath string) (*tls.Config, error) {
	return loadNodeTLSConfigWithClientCA(certPath, keyPath, "")
}

func loadNodeTLSConfigWithClientCA(certPath, keyPath, clientCAPath string) (*tls.Config, error) {
	certPEM, err := readTLSPEM(certPath, false)
	if err != nil {
		return nil, fmt.Errorf("read node TLS certificate: %w", err)
	}
	keyPEM, err := readTLSPEM(keyPath, true)
	if err != nil {
		return nil, fmt.Errorf("read node TLS private key: %w", err)
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("load node TLS certificate: %w", err)
	}
	config := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{pair}}
	if strings.TrimSpace(clientCAPath) == "" {
		return config, nil
	}
	caPEM, err := readTLSPEM(clientCAPath, false)
	if err != nil {
		return nil, fmt.Errorf("read node client CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("read node client CA: no certificate found")
	}
	config.ClientCAs = pool
	config.ClientAuth = tls.RequireAndVerifyClientCert
	return config, nil
}

// nodeTLSReloader keeps the listener configuration immutable after the first
// handshake while allowing an operator to atomically replace the certificate
// and optional client CA with SIGHUP. A malformed replacement stays fail
// closed and leaves the last known-good configuration in place.
type nodeTLSReloader struct {
	certPath     string
	keyPath      string
	clientCAPath string

	mu     sync.RWMutex
	config *tls.Config
}

func newNodeTLSReloader(certPath, keyPath, clientCAPath string) (*nodeTLSReloader, error) {
	config, err := loadNodeTLSConfigWithClientCA(certPath, keyPath, clientCAPath)
	if err != nil {
		return nil, err
	}
	return &nodeTLSReloader{certPath: certPath, keyPath: keyPath, clientCAPath: clientCAPath, config: config}, nil
}

func (r *nodeTLSReloader) TLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
			r.mu.RLock()
			defer r.mu.RUnlock()
			config := r.config.Clone()
			config.GetConfigForClient = nil
			return config, nil
		},
	}
}

func (r *nodeTLSReloader) Reload() error {
	if r == nil {
		return errors.New("node TLS reloader is nil")
	}
	config, err := loadNodeTLSConfigWithClientCA(r.certPath, r.keyPath, r.clientCAPath)
	if err != nil {
		return err
	}
	r.mu.Lock()
	r.config = config
	r.mu.Unlock()
	return nil
}

func loadNodeClientTLSConfig(caPath, certPath, keyPath string) (*tls.Config, error) {
	if (strings.TrimSpace(certPath) == "") != (strings.TrimSpace(keyPath) == "") {
		return nil, errors.New("node client certificate and key must be provided together")
	}
	config := &tls.Config{MinVersion: tls.VersionTLS13}
	if strings.TrimSpace(caPath) != "" {
		caPEM, err := readTLSPEM(caPath, false)
		if err != nil {
			return nil, fmt.Errorf("read node server CA: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, errors.New("read node server CA: no certificate found")
		}
		config.RootCAs = pool
	}
	if strings.TrimSpace(certPath) == "" {
		return config, nil
	}
	certPEM, err := readTLSPEM(certPath, false)
	if err != nil {
		return nil, fmt.Errorf("read node client certificate: %w", err)
	}
	keyPEM, err := readTLSPEM(keyPath, true)
	if err != nil {
		return nil, fmt.Errorf("read node client key: %w", err)
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("load node client certificate: %w", err)
	}
	config.Certificates = []tls.Certificate{pair}
	return config, nil
}
