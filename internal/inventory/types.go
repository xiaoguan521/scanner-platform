// Package inventory defines portable service observations without raw banners.
package inventory

import "time"

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

type Profile struct {
	OSName        string `json:"osName,omitempty"`
	OSFamily      string `json:"osFamily,omitempty"`
	DeviceType    string `json:"deviceType,omitempty"`
	DeviceSubtype string `json:"deviceSubtype,omitempty"`
	Vendor        string `json:"vendor,omitempty"`
	Model         string `json:"model,omitempty"`
}
