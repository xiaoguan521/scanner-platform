package taskflow

import "encoding/json"

// systemScanCodes maps the operator-facing system package status sentences
// to stable codes the UI can style and test against. The sentence stays the
// source of truth on the wire and in storage.
var systemScanCodes = map[string]string{
	SystemScanNotStarted:       "not_started",
	SystemScanNotConfigured:    "not_configured",
	SystemScanPortOutOfScope:   "port_out_of_scope",
	SystemScanPortClosed:       "port_closed",
	SystemScanClientMissing:    "client_missing",
	SystemScanHostKeyMismatch:  "host_key_mismatch",
	SystemScanAuthFailed:       "auth_failed",
	SystemScanPythonMissing:    "python_missing",
	SystemScanCollectionFailed: "collection_failed",
	SystemScanInvalidSnapshot:  "invalid_snapshot",
	SystemScanTrivyUnavailable: "trivy_unavailable",
	SystemScanUnsupportedOS:    "unsupported_os",
	SystemScanTrivyFailed:      "trivy_failed",
	SystemScanCompleted:        "completed",
}

// SystemScanCode returns the stable code for a system scan status sentence,
// "" when no status was reported and "unknown" for any other text.
func SystemScanCode(status string) string {
	if status == "" {
		return ""
	}
	if code, ok := systemScanCodes[status]; ok {
		return code
	}
	return "unknown"
}

// MarshalJSON adds the derived systemScanCode next to systemScanStatus.
func (t Task) MarshalJSON() ([]byte, error) {
	type plain Task
	return json.Marshal(struct {
		plain
		SystemScanCode string `json:"systemScanCode,omitempty"`
	}{plain(t), SystemScanCode(t.SystemScanStatus)})
}
