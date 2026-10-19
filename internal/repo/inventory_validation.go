package repo

import (
	"net"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"

	"scanner-platform/internal/inventory"
)

func validInventoryText(s string, limit int) bool {
	return len(s) <= limit && utf8.ValidString(s) && !strings.ContainsRune(s, 0)
}
func validScopedURL(raw, host string, port int) bool {
	if raw == "" {
		return true
	}
	u, err := url.Parse(raw)
	if err != nil || u.User != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Fragment != "" {
		return false
	}
	p := u.Port()
	if p == "" {
		p = "80"
		if u.Scheme == "https" {
			p = "443"
		}
	}
	parsed, err := strconv.Atoi(p)
	return err == nil && parsed == port && net.ParseIP(u.Hostname()) != nil && net.ParseIP(u.Hostname()).Equal(net.ParseIP(host))
}
func validService(s inventory.Service, host string) bool {
	if s.Port < 1 || s.Port > 65535 || s.Kind != "HTTP" && s.Kind != "OTHER" || s.Kind == "HTTP" && s.Scheme != "http" && s.Scheme != "https" || s.Kind == "OTHER" && s.Scheme != "" || len(s.LoginEntries) > 20 {
		return false
	}
	if s.Protocol != "" && s.Protocol != "tcp" {
		return false
	}
	for _, v := range []string{s.State, s.ServiceName, s.Software, s.Version, s.Middleware, s.Language, s.Framework, s.Database, s.Application, s.Title} {
		if !validInventoryText(v, 500) {
			return false
		}
	}
	if !validInventoryText(s.URL, 2000) || !validInventoryText(s.QuarantineReason, 1000) || !validScopedURL(s.URL, host, s.Port) {
		return false
	}
	for _, e := range s.LoginEntries {
		if e.Type != "system" && e.Type != "web" || e.Port != s.Port || !validInventoryText(e.Name, 500) || !validInventoryText(e.Evidence, 1000) || !validInventoryText(e.URL, 2000) || !validScopedURL(e.URL, host, e.Port) {
			return false
		}
	}
	return true
}
func validAssetProfile(p inventory.Profile) bool {
	for _, v := range []string{p.OSName, p.OSFamily, p.DeviceType, p.DeviceSubtype, p.Vendor, p.Model} {
		if !validInventoryText(v, 500) {
			return false
		}
	}
	return true
}
