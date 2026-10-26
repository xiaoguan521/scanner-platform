package executor

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"scanner-platform/internal/taskflow"
)

// TLSAuditEngine names detections produced by the passive TLS configuration check.
const TLSAuditEngine = "tls-audit"

const (
	tlsAuditTimeout    = 5 * time.Second
	certExpiryWarnDays = 30
)

// weakTLSSuites are RC4 and 3DES suites. ECDHE variants are included so the probe
// does not depend on RSA key exchange, which Go disables by default.
var weakTLSSuites = []uint16{
	tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA, tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA, tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
	tls.TLS_RSA_WITH_RC4_128_SHA, tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
}

// tlsObservation is everything the check learns about one TLS endpoint. It holds
// no payload, only handshake outcomes and public certificate fields.
type tlsObservation struct {
	TLS10, TLS11 bool
	WeakSuite    string
	Leaf         *x509.Certificate
	Chain        []*x509.Certificate
	VerifyErr    error
}

// handshake opens one connection, offers only the given protocol window and suites,
// completes the TLS handshake and closes. No application data is sent.
func handshake(ctx context.Context, address string, timeout time.Duration, config *tls.Config) (tls.ConnectionState, error) {
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	dialer := &tls.Dialer{NetDialer: &net.Dialer{Timeout: timeout}, Config: config}
	conn, err := dialer.DialContext(dialCtx, "tcp", address)
	if err != nil {
		return tls.ConnectionState{}, err
	}
	defer conn.Close()
	return conn.(*tls.Conn).ConnectionState(), nil
}

// observeTLS runs a bounded number of handshakes (at most six) against one
// authorized endpoint. Certificate verification is done locally afterwards, so
// untrusted certificates never block the check.
func observeTLS(ctx context.Context, host string, port int, timeout time.Duration) (tlsObservation, error) {
	address := net.JoinHostPort(host, strconv.Itoa(port))
	var obs tlsObservation
	// The endpoint may only speak old protocols or weak suites. Try progressively
	// older windows so such a service is still examined instead of skipped.
	var state tls.ConnectionState
	var err error
	for _, config := range []*tls.Config{
		{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12},
		{InsecureSkipVerify: true, MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS12},
		{InsecureSkipVerify: true, MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS12, CipherSuites: weakTLSSuites},
	} {
		if state, err = handshake(ctx, address, timeout, config); err == nil {
			break
		}
		if ctx.Err() != nil {
			return obs, ctx.Err()
		}
	}
	if err != nil {
		return obs, fmt.Errorf("TLS handshake: %w", err)
	}
	if len(state.PeerCertificates) > 0 {
		obs.Chain = state.PeerCertificates
		obs.Leaf = state.PeerCertificates[0]
		obs.VerifyErr = verifyCertificate(obs.Chain)
	}
	for _, old := range []struct {
		version uint16
		seen    *bool
	}{{tls.VersionTLS10, &obs.TLS10}, {tls.VersionTLS11, &obs.TLS11}} {
		if ctx.Err() != nil {
			return obs, ctx.Err()
		}
		if _, err := handshake(ctx, address, timeout, &tls.Config{InsecureSkipVerify: true, MinVersion: old.version, MaxVersion: old.version}); err == nil {
			*old.seen = true
		}
	}
	if ctx.Err() != nil {
		return obs, ctx.Err()
	}
	if weak, err := handshake(ctx, address, timeout, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS12, CipherSuites: weakTLSSuites}); err == nil {
		obs.WeakSuite = tls.CipherSuiteName(weak.CipherSuite)
	}
	return obs, nil
}

func verifyCertificate(chain []*x509.Certificate) error {
	intermediates := x509.NewCertPool()
	for _, cert := range chain[1:] {
		intermediates.AddCert(cert)
	}
	// An empty DNSName skips hostname matching: targets are numeric IPs, so a name
	// mismatch is expected and is not reported as an untrusted certificate.
	_, err := chain[0].Verify(x509.VerifyOptions{Intermediates: intermediates, CurrentTime: time.Now()})
	return err
}

func auditTLS(ctx context.Context, host string, port int, timeout time.Duration) ([]taskflow.Detection, error) {
	obs, err := observeTLS(ctx, host, port, timeout)
	if err != nil {
		return nil, err
	}
	return tlsFindings(host, port, obs, time.Now()), nil
}

func tlsFindings(host string, port int, obs tlsObservation, now time.Time) []taskflow.Detection {
	target := net.JoinHostPort(host, strconv.Itoa(port))
	newFinding := func(id, title, severity, evidence, solution string) taskflow.Detection {
		return taskflow.Detection{
			Engine: TLSAuditEngine, TemplateID: id, Target: target, Title: title, Severity: severity, Port: port,
			RiskType: "system", DetectMethod: "configuration", Confidence: "high", ContentLanguage: "zh-CN",
			Description: title + "。", Evidence: truncateRunes(evidence, 1000) + "；仅完成 TLS 握手，未发送应用数据。", Solution: solution,
		}
	}
	var findings []taskflow.Detection
	if obs.TLS10 {
		findings = append(findings, newFinding("tls-protocol-tls10", "启用不安全的 TLS 1.0 协议", "MEDIUM", "服务端接受 TLS 1.0 握手", "在服务端禁用 TLS 1.0，仅启用 TLS 1.2 及以上。"))
	}
	if obs.TLS11 {
		findings = append(findings, newFinding("tls-protocol-tls11", "目标使用过期的 TLS 1.1 协议", "LOW", "服务端接受 TLS 1.1 握手", "在服务端禁用 TLS 1.1，仅启用 TLS 1.2 及以上。"))
	}
	if obs.WeakSuite != "" {
		findings = append(findings, newFinding("tls-weak-cipher", "TLS 服务支持 RC4/3DES 弱加密套件", "MEDIUM", "服务端接受弱套件 "+obs.WeakSuite, "移除 RC4 与 3DES 套件，优先使用 AES-GCM 与 ChaCha20。"))
	}
	if obs.Leaf != nil {
		cert := obs.Leaf
		subject := truncateRunes(cert.Subject.CommonName, 120)
		switch {
		case now.After(cert.NotAfter):
			findings = append(findings, newFinding("tls-cert-expired", "SSL 证书已过期", "MEDIUM", fmt.Sprintf("证书 %q 于 %s 过期", subject, cert.NotAfter.UTC().Format("2006-01-02")), "更换为有效期内的证书。"))
		case now.Before(cert.NotBefore):
			findings = append(findings, newFinding("tls-cert-not-yet-valid", "SSL 证书尚未生效", "LOW", fmt.Sprintf("证书 %q 于 %s 才生效", subject, cert.NotBefore.UTC().Format("2006-01-02")), "检查证书生效时间与服务器时钟。"))
		case cert.NotAfter.Sub(now) < certExpiryWarnDays*24*time.Hour:
			findings = append(findings, newFinding("tls-cert-expiring", "SSL 证书即将到期", "LOW", fmt.Sprintf("证书 %q 将于 %s 到期", subject, cert.NotAfter.UTC().Format("2006-01-02")), "在到期前更换证书。"))
		}
		if obs.VerifyErr != nil {
			if isSelfSigned(cert) {
				findings = append(findings, newFinding("tls-cert-self-signed", "无效的自签名 SSL 证书", "MEDIUM", fmt.Sprintf("证书 %q 为自签名，不被系统信任库信任", subject), "使用受信任 CA 签发的证书。"))
			} else if strings.Contains(obs.VerifyErr.Error(), "unknown authority") {
				findings = append(findings, newFinding("tls-cert-untrusted", "SSL 证书无法受到信任", "LOW", fmt.Sprintf("证书 %q 的签发链无法追溯到系统信任库", subject), "使用受信任 CA 签发的证书，并在服务端提供完整证书链。"))
			}
		}
	}
	return findings
}

func isSelfSigned(cert *x509.Certificate) bool {
	return cert.Issuer.String() == cert.Subject.String() && cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature) == nil
}
