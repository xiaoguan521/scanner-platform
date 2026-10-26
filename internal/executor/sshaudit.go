package executor

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"scanner-platform/internal/taskflow"
)

// SSHAuditEngine names detections produced by the passive SSH algorithm check.
const SSHAuditEngine = "ssh-audit"

// sshAuditTimeout bounds the whole banner and algorithm exchange for one port.
const sshAuditTimeout = 5 * time.Second

const (
	sshMaxPacket    = 35000 // RFC 4253 section 6.1 minimum every server must accept
	sshKexInitType  = 20
	sshClientBanner = "SSH-2.0-SecScanner_1.0"
)

var errSSHProtocol = errors.New("invalid SSH key exchange message")

// sshAlgorithms holds the name-lists a server advertises in SSH_MSG_KEXINIT.
type sshAlgorithms struct {
	Kex, HostKey, Ciphers, MACs []string
}

// auditSSH performs the unauthenticated start of an SSH handshake: it exchanges
// protocol banners and reads the server's algorithm lists, then closes. It never
// reaches key exchange or authentication, so it cannot try any credential.
func auditSSH(ctx context.Context, host string, port int, timeout time.Duration) (sshAlgorithms, error) {
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return sshAlgorithms{}, fmt.Errorf("connect SSH service: %w", err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return sshAlgorithms{}, err
	}
	return exchangeSSHAlgorithms(conn)
}

func exchangeSSHAlgorithms(conn io.ReadWriter) (sshAlgorithms, error) {
	if _, err := io.WriteString(conn, sshClientBanner+"\r\n"); err != nil {
		return sshAlgorithms{}, fmt.Errorf("send SSH banner: %w", err)
	}
	if err := skipSSHBanner(conn); err != nil {
		return sshAlgorithms{}, err
	}
	var header [5]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return sshAlgorithms{}, fmt.Errorf("read SSH packet header: %w", err)
	}
	length := binary.BigEndian.Uint32(header[:4])
	padding := uint32(header[4])
	if length < padding+2 || length > sshMaxPacket {
		return sshAlgorithms{}, errSSHProtocol
	}
	body := make([]byte, length-1)
	if _, err := io.ReadFull(conn, body); err != nil {
		return sshAlgorithms{}, fmt.Errorf("read SSH key exchange message: %w", err)
	}
	return parseKexInit(body[:len(body)-int(padding)])
}

// skipSSHBanner reads lines until the server's "SSH-" identification string; RFC
// 4253 lets a server send other text lines first. Reading is bounded.
func skipSSHBanner(r io.Reader) error {
	line := make([]byte, 0, 255)
	var one [1]byte
	for total := 0; total < 4096; total++ {
		if _, err := io.ReadFull(r, one[:]); err != nil {
			return fmt.Errorf("read SSH banner: %w", err)
		}
		if one[0] != '\n' {
			if len(line) < 255 {
				line = append(line, one[0])
			}
			continue
		}
		if strings.HasPrefix(string(line), "SSH-") {
			if !strings.HasPrefix(string(line), "SSH-2.0-") && !strings.HasPrefix(string(line), "SSH-1.99-") {
				return errSSHProtocol
			}
			return nil
		}
		line = line[:0]
	}
	return errSSHProtocol
}

// parseKexInit decodes an SSH_MSG_KEXINIT payload (RFC 4253 section 7.1).
func parseKexInit(payload []byte) (sshAlgorithms, error) {
	if len(payload) < 17 || payload[0] != sshKexInitType {
		return sshAlgorithms{}, errSSHProtocol
	}
	rest := payload[17:] // message type and 16-byte cookie
	lists := make([][]string, 0, 10)
	for i := 0; i < 10; i++ {
		if len(rest) < 4 {
			return sshAlgorithms{}, errSSHProtocol
		}
		size := binary.BigEndian.Uint32(rest[:4])
		rest = rest[4:]
		if uint64(size) > uint64(len(rest)) {
			return sshAlgorithms{}, errSSHProtocol
		}
		var names []string
		if size > 0 {
			names = strings.Split(string(rest[:size]), ",")
		}
		lists = append(lists, names)
		rest = rest[size:]
	}
	return sshAlgorithms{Kex: lists[0], HostKey: lists[1], Ciphers: dedupe(lists[2], lists[3]), MACs: dedupe(lists[4], lists[5])}, nil
}

func dedupe(groups ...[]string) []string {
	seen := map[string]bool{}
	var out []string
	for _, group := range groups {
		for _, name := range group {
			if name != "" && !seen[name] {
				seen[name] = true
				out = append(out, name)
			}
		}
	}
	return out
}

func matching(names []string, weak func(string) bool) []string {
	var out []string
	for _, name := range names {
		if weak(strings.ToLower(name)) {
			out = append(out, name)
		}
	}
	return out
}

func weakSSHCipher(name string) bool {
	for _, marker := range []string{"-cbc", "arcfour", "3des", "blowfish", "cast128", "rc4"} {
		if strings.Contains(name, marker) {
			return true
		}
	}
	return name == "none"
}

func weakSSHMAC(name string) bool {
	return strings.Contains(name, "md5") || strings.HasSuffix(name, "-96") || strings.Contains(name, "-96-") || name == "none" || strings.HasPrefix(name, "umac-64")
}

func weakSSHKex(name string) bool {
	return name == "diffie-hellman-group1-sha1" || name == "diffie-hellman-group-exchange-sha1"
}

func weakSSHHostKey(name string) bool { return name == "ssh-dss" }

// sshWeakAlgorithmFindings turns advertised weak algorithms into at most one
// low-severity finding per category. Findings only report what the server offers.
func sshWeakAlgorithmFindings(host string, port int, algorithms sshAlgorithms) []taskflow.Detection {
	target := net.JoinHostPort(host, strconv.Itoa(port))
	type category struct {
		id, title, advice string
		weak              []string
	}
	categories := []category{
		{"ssh-weak-cipher", "SSH 服务支持弱加密算法", "在 sshd_config 的 Ciphers 中移除 CBC、3DES、RC4 等弱对称加密算法，仅保留 AES-GCM、AES-CTR、ChaCha20。", matching(algorithms.Ciphers, weakSSHCipher)},
		{"ssh-weak-mac", "SSH 服务支持弱消息认证算法", "在 sshd_config 的 MACs 中移除 MD5 与 96 位截断算法，优先使用 hmac-sha2-* 的 etm 变体。", matching(algorithms.MACs, weakSSHMAC)},
		{"ssh-weak-kex", "SSH 服务支持弱密钥交换算法", "在 sshd_config 的 KexAlgorithms 中移除基于 SHA-1 的 Diffie-Hellman 算法，使用 curve25519 或 group14-sha256 以上。", matching(algorithms.Kex, weakSSHKex)},
		{"ssh-weak-hostkey", "SSH 服务支持弱主机密钥算法", "移除 DSA（ssh-dss）主机密钥，使用 ed25519 或 RSA 3072 位以上。", matching(algorithms.HostKey, weakSSHHostKey)},
	}
	var findings []taskflow.Detection
	for _, c := range categories {
		if len(c.weak) == 0 {
			continue
		}
		findings = append(findings, taskflow.Detection{
			Engine: SSHAuditEngine, TemplateID: c.id, Target: target, Title: c.title, Severity: "LOW", Port: port,
			RiskType: "system", DetectMethod: "configuration", Confidence: "high", ContentLanguage: "zh-CN",
			Description: "SSH 服务在算法协商中公布了已不推荐使用的算法。",
			Evidence:    "服务端公布的弱算法：" + truncateRunes(strings.Join(c.weak, "、"), 1000) + "；仅读取算法列表，未进行密钥交换或认证。",
			Solution:    c.advice,
		})
	}
	return findings
}

func truncateRunes(value string, limit int) string {
	runes := []rune(value)
	if len(runes) <= limit {
		return value
	}
	return string(runes[:limit])
}
