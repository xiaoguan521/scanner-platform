package api

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

const (
	maxNodeTokenFileBytes = 64 << 10
	minNodeTokenLength    = 16
	maxNodeTokenLength    = 4096
)

// NodeTokenSet is the Server-side mapping from a node identifier to its
// bearer token. The map is copied when middleware is created and is never
// mutated by request handling.
type NodeTokenSet map[string]string

var (
	ErrInvalidNodeTokenFile = errors.New("invalid node token file")
	ErrNodeAuthentication   = errors.New("node authentication failed")
)

// ReadNodeTokenFile reads one owner-only token file for a Worker or Updater.
// A single trailing LF (and its optional CR) is ignored so Docker secrets and
// manually-created files work the same way. Tokens are deliberately restricted
// to printable ASCII to avoid invisible characters in a bearer credential.
func ReadNodeTokenFile(path string) (string, error) {
	data, err := readOwnerOnlyFile(path)
	if err != nil {
		return "", err
	}
	token, err := normalizeNodeToken(data)
	if err != nil {
		return "", fmt.Errorf("%w: token: %v", ErrInvalidNodeTokenFile, err)
	}
	return token, nil
}

// ReadNodeTokenSetFile reads the Server-side node token registry. Each
// non-empty line has the form node-id=token. Node IDs are sent by clients in
// X-Node-ID and are also checked against the JSON body by the route handlers.
// Repeated IDs and malformed lines are rejected rather than silently allowing
// a stale or ambiguous credential.
func ReadNodeTokenSetFile(path string) (NodeTokenSet, error) {
	data, err := readOwnerOnlyFile(path)
	if err != nil {
		return nil, err
	}
	data = trimOneLineEnding(data)
	if len(data) == 0 {
		return nil, fmt.Errorf("%w: empty registry", ErrInvalidNodeTokenFile)
	}
	set := make(NodeTokenSet)
	for lineNo, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSuffix(raw, "\r")
		if line == "" {
			continue
		}
		key, token, ok := strings.Cut(line, "=")
		if !ok || !runtimeWorkerID.MatchString(key) {
			return nil, fmt.Errorf("%w: malformed entry on line %d", ErrInvalidNodeTokenFile, lineNo+1)
		}
		if _, exists := set[key]; exists {
			return nil, fmt.Errorf("%w: duplicate node on line %d", ErrInvalidNodeTokenFile, lineNo+1)
		}
		if _, err := normalizeNodeToken([]byte(token)); err != nil {
			return nil, fmt.Errorf("%w: token on line %d: %v", ErrInvalidNodeTokenFile, lineNo+1, err)
		}
		set[key] = token
	}
	if len(set) == 0 {
		return nil, fmt.Errorf("%w: empty registry", ErrInvalidNodeTokenFile)
	}
	return set, nil
}

func readOwnerOnlyFile(path string) ([]byte, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("%w: path is required", ErrInvalidNodeTokenFile)
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return nil, fmt.Errorf("%w: file must be a regular owner-only file", ErrInvalidNodeTokenFile)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("%w: open failed", ErrInvalidNodeTokenFile)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxNodeTokenFileBytes+1))
	if err != nil || len(data) > maxNodeTokenFileBytes {
		return nil, fmt.Errorf("%w: file is too large", ErrInvalidNodeTokenFile)
	}
	return data, nil
}

func trimOneLineEnding(data []byte) []byte {
	if len(data) > 0 && data[len(data)-1] == '\n' {
		data = data[:len(data)-1]
		if len(data) > 0 && data[len(data)-1] == '\r' {
			data = data[:len(data)-1]
		}
	}
	return data
}

func normalizeNodeToken(data []byte) (string, error) {
	data = trimOneLineEnding(append([]byte(nil), data...))
	if len(data) < minNodeTokenLength || len(data) > maxNodeTokenLength {
		return "", fmt.Errorf("length must be between %d and %d bytes", minNodeTokenLength, maxNodeTokenLength)
	}
	for _, b := range data {
		if b < 0x21 || b > 0x7e {
			return "", errors.New("must contain printable ASCII without whitespace")
		}
	}
	return string(data), nil
}

type nodeIdentityContextKey struct{}

// AuthenticatedNodeID returns the node identity established by
// NodeAuthMiddleware. An empty value means the request is running in the
// explicitly supported local compatibility mode without node authentication.
func AuthenticatedNodeID(r *http.Request) string {
	if r == nil {
		return ""
	}
	value, _ := r.Context().Value(nodeIdentityContextKey{}).(string)
	return value
}

// IsNodeAPIPath reports whether a request belongs to the Worker/Updater node
// protocol. UI and authenticated human APIs are intentionally outside this
// set so enabling node authentication does not change browser sessions.
func IsNodeAPIPath(path string) bool {
	return path == "/api/v1/nodes/heartbeat" ||
		strings.HasPrefix(path, "/api/v1/worker/") ||
		strings.HasPrefix(path, "/api/v1/updater/")
}

// NodeProtocolHandler limits an independently exposed node listener to the
// Worker/Updater protocol. The web UI and human session APIs must never be
// reachable through the internal node port, even when the same application
// handler is used underneath.
func NodeProtocolHandler(next http.Handler) http.Handler {
	if next == nil {
		next = http.NotFoundHandler()
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !IsNodeAPIPath(r.URL.Path) {
			runtimeJSON(w, http.StatusNotFound, APIError{Error: "not_found", Message: "节点接口不存在"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

// NodeAuthMiddleware protects the node protocol with an identity-bound bearer
// token. The caller must provide a non-empty set loaded from a protected file;
// local development without this middleware remains intentionally compatible.
func NodeAuthMiddleware(next http.Handler, tokens NodeTokenSet) http.Handler {
	copySet := make(NodeTokenSet, len(tokens))
	for id, token := range tokens {
		copySet[id] = token
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !IsNodeAPIPath(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		nodeID := r.Header.Get("X-Node-ID")
		expected, ok := copySet[nodeID]
		provided := r.Header.Get("Authorization")
		if !ok || subtle.ConstantTimeCompare([]byte(provided), []byte("Bearer "+expected)) != 1 {
			w.Header().Set("WWW-Authenticate", "Bearer")
			runtimeJSON(w, http.StatusUnauthorized, APIError{Error: "node_auth_required", Message: "节点认证失败"})
			return
		}
		ctx := contextWithNodeIdentity(r.Context(), nodeID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// contextWithNodeIdentity is kept private so handlers cannot manufacture an
// authenticated identity; only the middleware can set it.
func contextWithNodeIdentity(ctx context.Context, nodeID string) context.Context {
	return context.WithValue(ctx, nodeIdentityContextKey{}, nodeID)
}
