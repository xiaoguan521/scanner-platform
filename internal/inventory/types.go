// Package inventory defines portable service observations without raw banners.
package inventory

import (
	"strings"
	"time"
	"unicode/utf8"
)

type LoginEntry struct {
	Type           string `json:"type"`
	Name           string `json:"name"`
	Port           int    `json:"port"`
	URL            string `json:"url,omitempty"`
	HTTPS          bool   `json:"https"`
	Captcha        *bool  `json:"captcha,omitempty"`
	AntiBruteForce *bool  `json:"antiBruteForce,omitempty"`
	Evidence       string `json:"evidence,omitempty"`
}

type Service struct {
	Port             int          `json:"port"`
	Protocol         string       `json:"protocol,omitempty"`
	State            string       `json:"state,omitempty"`
	Kind             string       `json:"kind"`
	Scheme           string       `json:"scheme,omitempty"`
	ServiceName      string       `json:"serviceName,omitempty"`
	Software         string       `json:"software,omitempty"`
	Version          string       `json:"version,omitempty"`
	Middleware       string       `json:"middleware,omitempty"`
	Language         string       `json:"language,omitempty"`
	Framework        string       `json:"framework,omitempty"`
	Database         string       `json:"database,omitempty"`
	Application      string       `json:"application,omitempty"`
	URL              string       `json:"url,omitempty"`
	Title            string       `json:"title,omitempty"`
	TLS              bool         `json:"tls"`
	FirstSeen        time.Time    `json:"firstSeen,omitempty"`
	LastSeen         time.Time    `json:"lastSeen,omitempty"`
	Excluded         bool         `json:"excluded,omitempty"`
	Quarantined      bool         `json:"quarantined,omitempty"`
	QuarantineReason string       `json:"quarantineReason,omitempty"`
	LoginEntries     []LoginEntry `json:"loginEntries,omitempty"`
}

// RuntimeService is a bounded, read-only observation of a service unit or
// process name collected over the explicitly configured SSH target. It does
// not contain command lines, PIDs, paths, arguments or user data.
type RuntimeService struct {
	Name    string `json:"name"`
	Manager string `json:"manager"`
	State   string `json:"state"`
}

// ValidateRuntimeServices checks the stable runtime inventory contract shared
// by the Worker, Server and asset repositories.
func ValidateRuntimeServices(services []RuntimeService) bool {
	if len(services) > 256 {
		return false
	}
	seen := make(map[string]struct{}, len(services))
	for _, service := range services {
		if len(service.Name) == 0 || len(service.Name) > 128 || !utf8.ValidString(service.Name) || strings.ContainsRune(service.Name, 0) || !validRuntimeServiceName(service.Name) {
			return false
		}
		if service.Manager != "systemd" && service.Manager != "init" && service.Manager != "process" {
			return false
		}
		if service.State != "installed" && service.State != "running" {
			return false
		}
		key := service.Manager + "\x00" + service.Name
		if _, ok := seen[key]; ok {
			return false
		}
		seen[key] = struct{}{}
	}
	return true
}

func validRuntimeServiceName(value string) bool {
	for i := 0; i < len(value); i++ {
		c := value[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("_.@:+-", rune(c)) {
			continue
		}
		return false
	}
	return true
}

type Profile struct {
	OSName          string           `json:"osName,omitempty"`
	OSFamily        string           `json:"osFamily,omitempty"`
	DeviceType      string           `json:"deviceType,omitempty"`
	DeviceSubtype   string           `json:"deviceSubtype,omitempty"`
	Vendor          string           `json:"vendor,omitempty"`
	Model           string           `json:"model,omitempty"`
	RuntimeServices []RuntimeService `json:"runtimeServices,omitempty"`
}
