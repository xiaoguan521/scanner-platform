package executor

import (
	"encoding/binary"
	"io"
	"net"
	"reflect"
	"strings"
	"testing"
)

func kexInitPayload(lists ...string) []byte {
	payload := append([]byte{sshKexInitType}, make([]byte, 16)...)
	for i := 0; i < 10; i++ {
		value := ""
		if i < len(lists) {
			value = lists[i]
		}
		var size [4]byte
		binary.BigEndian.PutUint32(size[:], uint32(len(value)))
		payload = append(payload, size[:]...)
		payload = append(payload, value...)
	}
	return append(payload, 0, 0, 0, 0, 0) // first_kex_packet_follows and reserved
}

func sshPacket(payload []byte) []byte {
	padding := 8 - (len(payload)+5)%8
	if padding < 4 {
		padding += 8
	}
	packet := make([]byte, 5, 5+len(payload)+padding)
	binary.BigEndian.PutUint32(packet[:4], uint32(1+len(payload)+padding))
	packet[4] = byte(padding)
	packet = append(packet, payload...)
	return append(packet, make([]byte, padding)...)
}

// readClientBanner consumes the scanner's banner first: net.Pipe is unbuffered,
// so both sides writing at once would block forever, unlike a real TCP socket.
func readClientBanner(r io.Reader) {
	_, _ = io.ReadFull(r, make([]byte, len(sshClientBanner)+2))
}

func TestParseKexInitReadsAlgorithmLists(t *testing.T) {
	got, err := parseKexInit(kexInitPayload("curve25519-sha256,diffie-hellman-group1-sha1", "ssh-ed25519,ssh-dss", "aes128-ctr,aes128-cbc", "aes128-ctr", "hmac-sha2-256,hmac-md5-96", "hmac-sha2-256"))
	if err != nil {
		t.Fatal(err)
	}
	want := sshAlgorithms{Kex: []string{"curve25519-sha256", "diffie-hellman-group1-sha1"}, HostKey: []string{"ssh-ed25519", "ssh-dss"}, Ciphers: []string{"aes128-ctr", "aes128-cbc"}, MACs: []string{"hmac-sha2-256", "hmac-md5-96"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected algorithms: %#v", got)
	}
}

func TestParseKexInitRejectsMalformedMessages(t *testing.T) {
	valid := kexInitPayload("a", "b")
	for name, payload := range map[string][]byte{
		"empty":        nil,
		"wrong type":   append([]byte{21}, valid[1:]...),
		"short cookie": valid[:10],
		"truncated":    valid[:len(valid)-8],
		"huge list":    append(append([]byte{sshKexInitType}, make([]byte, 16)...), 0xff, 0xff, 0xff, 0xff),
	} {
		if _, err := parseKexInit(payload); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestSSHWeakAlgorithmFindings(t *testing.T) {
	findings := sshWeakAlgorithmFindings("192.0.2.10", 22, sshAlgorithms{
		Kex: []string{"curve25519-sha256", "diffie-hellman-group1-sha1"}, HostKey: []string{"ssh-ed25519", "ssh-dss"},
		Ciphers: []string{"aes256-gcm@openssh.com", "aes128-cbc", "3des-cbc"}, MACs: []string{"hmac-sha2-256", "hmac-md5", "hmac-sha1-96"},
	})
	ids := []string{}
	for _, f := range findings {
		ids = append(ids, f.TemplateID)
		if f.Engine != SSHAuditEngine || f.Target != "192.0.2.10:22" || f.Port != 22 || f.Severity != "LOW" || len(f.Evidence) > 4000 {
			t.Fatalf("unexpected finding %#v", f)
		}
	}
	if !reflect.DeepEqual(ids, []string{"ssh-weak-cipher", "ssh-weak-mac", "ssh-weak-kex", "ssh-weak-hostkey"}) {
		t.Fatalf("unexpected categories %v", ids)
	}
	if !strings.Contains(findings[0].Evidence, "aes128-cbc") || strings.Contains(findings[0].Evidence, "gcm") {
		t.Fatalf("evidence must list only weak ciphers: %s", findings[0].Evidence)
	}
	if got := sshWeakAlgorithmFindings("192.0.2.10", 22, sshAlgorithms{Kex: []string{"curve25519-sha256"}, Ciphers: []string{"chacha20-poly1305@openssh.com"}, MACs: []string{"hmac-sha2-512-etm@openssh.com"}, HostKey: []string{"ssh-ed25519"}}); len(got) != 0 {
		t.Fatalf("strong algorithms must produce no finding: %v", got)
	}
}

func TestExchangeSSHAlgorithmsOverConnection(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	go func() {
		defer server.Close()
		readClientBanner(server)
		_, _ = io.WriteString(server, "welcome\r\nSSH-2.0-OpenSSH_9.6\r\n")
		_, _ = server.Write(sshPacket(kexInitPayload("curve25519-sha256", "ssh-ed25519", "aes128-cbc", "aes128-cbc", "hmac-sha2-256", "hmac-sha2-256")))
		_, _ = io.Copy(io.Discard, server)
	}()
	got, err := exchangeSSHAlgorithms(client)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.Ciphers, []string{"aes128-cbc"}) {
		t.Fatalf("unexpected ciphers %v", got.Ciphers)
	}
}

func TestExchangeSSHAlgorithmsRejectsNonSSHPeer(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	go func() {
		defer server.Close()
		readClientBanner(server)
		_, _ = io.WriteString(server, "SSH-1.5-Legacy\r\n")
		_, _ = io.Copy(io.Discard, server)
	}()
	if _, err := exchangeSSHAlgorithms(client); err == nil {
		t.Fatal("SSH protocol 1 peers must be rejected")
	}
}

func FuzzParseKexInit(f *testing.F) {
	f.Add(kexInitPayload("a,b", "c", "d", "e", "f", "g"))
	f.Add([]byte{sshKexInitType})
	f.Fuzz(func(t *testing.T, payload []byte) {
		_, _ = parseKexInit(payload)
	})
}
