package repo

// isPassiveAuditEngine reports engines whose findings come from read-only protocol
// checks run by the Worker itself (handshake data only, no payloads or credentials).
func isPassiveAuditEngine(engine string) bool {
	return engine == "ssh-audit" || engine == "tls-audit"
}
