package bootstrap

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
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
	return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{pair}}, nil
}
