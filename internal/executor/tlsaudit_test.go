package executor

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"strconv"
	"testing"
	"time"
)

func testCertificate(t *testing.T, notBefore, notAfter time.Time) tls.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fixture.example"}, NotBefore: notBefore, NotAfter: notAfter,
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// serveTLS starts a loopback TLS listener that completes handshakes and closes.
func serveTLS(t *testing.T, config *tls.Config) int {
	t.Helper()
	listener, err := tls.Listen("tcp", "127.0.0.1:0", config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				if tlsConn, ok := conn.(*tls.Conn); ok {
					_ = tlsConn.SetDeadline(time.Now().Add(3 * time.Second))
					_ = tlsConn.Handshake()
				}
			}()
		}
	}()
	return listener.Addr().(*net.TCPAddr).Port
}

func templateIDs(findings []string) map[string]bool {
	ids := map[string]bool{}
	for _, id := range findings {
		ids[id] = true
	}
	return ids
}

func auditIDs(t *testing.T, port int) map[string]bool {
	t.Helper()
	findings, err := auditTLS(context.Background(), "127.0.0.1", port, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, f := range findings {
		if f.Engine != TLSAuditEngine || f.Target != net.JoinHostPort("127.0.0.1", strconv.Itoa(port)) || f.Port != port || f.Evidence == "" {
			t.Fatalf("unexpected finding %#v", f)
		}
		ids = append(ids, f.TemplateID)
	}
	return templateIDs(ids)
}

func TestAuditTLSReportsSelfSignedOnModernServerOnly(t *testing.T) {
	cert := testCertificate(t, time.Now().Add(-time.Hour), time.Now().Add(365*24*time.Hour))
	port := serveTLS(t, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
	got := auditIDs(t, port)
	if !got["tls-cert-self-signed"] || len(got) != 1 {
		t.Fatalf("a modern server with a self-signed certificate must only report that: %v", got)
	}
}

func TestAuditTLSReportsExpiredCertificate(t *testing.T) {
	cert := testCertificate(t, time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour))
	port := serveTLS(t, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
	if got := auditIDs(t, port); !got["tls-cert-expired"] {
		t.Fatalf("expired certificate not reported: %v", got)
	}
}

func TestAuditTLSReportsLegacyProtocols(t *testing.T) {
	cert := testCertificate(t, time.Now().Add(-time.Hour), time.Now().Add(365*24*time.Hour))
	port := serveTLS(t, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS12})
	got := auditIDs(t, port)
	if !got["tls-protocol-tls10"] || !got["tls-protocol-tls11"] {
		t.Fatalf("TLS 1.0 and 1.1 support not reported: %v", got)
	}
}

func TestAuditTLSReportsWeakCipherSuite(t *testing.T) {
	cert := testCertificate(t, time.Now().Add(-time.Hour), time.Now().Add(365*24*time.Hour))
	port := serveTLS(t, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12, CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA}})
	if got := auditIDs(t, port); !got["tls-weak-cipher"] {
		t.Fatalf("3DES support not reported: %v", got)
	}
}

func TestAuditTLSFailsClosedForNonTLSService(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()
	if _, err := auditTLS(context.Background(), "127.0.0.1", listener.Addr().(*net.TCPAddr).Port, time.Second); err == nil {
		t.Fatal("a service that does not speak TLS must yield an error, not findings")
	}
}

func TestTLSFindingsExpiryWindow(t *testing.T) {
	now := time.Now()
	for name, tc := range map[string]struct {
		notAfter time.Time
		want     string
	}{
		"expiring soon": {now.Add(10 * 24 * time.Hour), "tls-cert-expiring"},
		"expired":       {now.Add(-time.Hour), "tls-cert-expired"},
		"far future":    {now.Add(200 * 24 * time.Hour), ""},
	} {
		leaf := &x509.Certificate{Subject: pkix.Name{CommonName: "fixture.example"}, NotBefore: now.Add(-24 * time.Hour), NotAfter: tc.notAfter}
		findings := tlsFindings("192.0.2.10", 443, tlsObservation{Leaf: leaf}, now)
		if tc.want == "" && len(findings) != 0 || tc.want != "" && (len(findings) != 1 || findings[0].TemplateID != tc.want) {
			t.Errorf("%s: unexpected findings %#v", name, findings)
		}
	}
}
