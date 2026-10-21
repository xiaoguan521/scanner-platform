package api

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"scanner-platform/internal/repo"
)

const (
	maxNodeTokenFileBytes = 64 << 10
	minNodeTokenLength    = 16
	maxNodeTokenLength    = 4096
)

// NodeTokenSet is the Server-side mapping from a node identifier to its
// bearer token. Values are copied before they are exposed to request
// handling, so an operator can replace a registry without a data race.
type NodeTokenSet map[string]string

// NodeTokenRegistry is an atomically replaceable node token registry. It is
// deliberately separate from the file reader so SIGHUP rotation can keep the
// last known-good credentials when a replacement file is malformed.
type NodeTokenRegistry struct {
	value atomic.Value // stores NodeTokenSet
	mu    sync.Mutex
}

func NewNodeTokenRegistry(tokens NodeTokenSet) *NodeTokenRegistry {
	registry := &NodeTokenRegistry{}
	registry.Replace(tokens)
	return registry
}

func (r *NodeTokenRegistry) Replace(tokens NodeTokenSet) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.replace(tokens)
}

func (r *NodeTokenRegistry) replace(tokens NodeTokenSet) {
	copySet := make(NodeTokenSet, len(tokens))
	for id, token := range tokens {
		copySet[id] = token
	}
	if len(copySet) == 0 {
		copySet = NodeTokenSet{}
	}
	r.value.Store(copySet)
}

// issueFile atomically adds a newly generated token to the owner-only server
// registry and runs commit while the registry lock is held. If commit fails,
// the file and in-memory registry are restored before the error is returned.
// The plaintext token is never logged or persisted outside the registry file.
func (r *NodeTokenRegistry) issueFile(path, nodeID string, commit func(string) error) (string, error) {
	if r == nil {
		return "", fmt.Errorf("%w: registry is not configured", ErrInvalidNodeTokenFile)
	}
	if !runtimeWorkerID.MatchString(nodeID) {
		return "", fmt.Errorf("%w: invalid node id", ErrInvalidNodeTokenFile)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	previous, err := ReadNodeTokenSetFile(path)
	if err != nil {
		return "", err
	}
	if _, exists := previous[nodeID]; exists {
		return "", repo.ErrNodeCredentialExists
	}
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("generate node credential: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(bytes)
	next := make(NodeTokenSet, len(previous)+1)
	for id, value := range previous {
		next[id] = value
	}
	next[nodeID] = token
	if err := writeNodeTokenSetFile(path, next); err != nil {
		return "", err
	}
	r.replace(next)
	if commit != nil {
		if err := commit(token); err != nil {
			if rollbackErr := writeNodeTokenSetFile(path, previous); rollbackErr != nil {
				return "", fmt.Errorf("commit node credential: %w; rollback registry: %v", err, rollbackErr)
			}
			r.replace(previous)
			return "", err
		}
	}
	return token, nil
}

// ReloadFile reads and swaps a complete owner-only registry under the same
// lock used by credential issuance, so SIGHUP cannot interleave with a
// failed issuance rollback.
func (r *NodeTokenRegistry) ReloadFile(path string) error {
	if r == nil {
		return fmt.Errorf("%w: registry is not configured", ErrInvalidNodeTokenFile)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	tokens, err := ReadNodeTokenSetFile(path)
	if err != nil {
		return err
	}
	r.replace(tokens)
	return nil
}

func writeNodeTokenSetFile(path string, tokens NodeTokenSet) error {
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("%w: path is required", ErrInvalidNodeTokenFile)
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("%w: file must be a regular owner-only file", ErrInvalidNodeTokenFile)
	}
	ids := make([]string, 0, len(tokens))
	for id, token := range tokens {
		if !runtimeWorkerID.MatchString(id) {
			return fmt.Errorf("%w: invalid node id", ErrInvalidNodeTokenFile)
		}
		if _, err := normalizeNodeToken([]byte(token)); err != nil {
			return fmt.Errorf("%w: invalid token for %s", ErrInvalidNodeTokenFile, id)
		}
		ids = append(ids, id)
	}
	if len(ids) == 0 {
		return fmt.Errorf("%w: empty registry", ErrInvalidNodeTokenFile)
	}
	sort.Strings(ids)
	var content strings.Builder
	for _, id := range ids {
		content.WriteString(id)
		content.WriteByte('=')
		content.WriteString(tokens[id])
		content.WriteByte('\n')
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".node-tokens-*")
	if err != nil {
		return fmt.Errorf("%w: create replacement", ErrInvalidNodeTokenFile)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0600); err == nil {
		_, err = tmp.WriteString(content.String())
	}
	if err == nil {
		err = tmp.Sync()
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return fmt.Errorf("%w: write replacement", ErrInvalidNodeTokenFile)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("%w: replace registry", ErrInvalidNodeTokenFile)
	}
	return nil
}

func (r *NodeTokenRegistry) snapshot() NodeTokenSet {
	if r == nil {
		return NodeTokenSet{}
	}
	value := r.value.Load()
	if value == nil {
		return NodeTokenSet{}
	}
	return value.(NodeTokenSet)
}

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
	return NodeAuthMiddlewareWithRegistry(next, NewNodeTokenRegistry(tokens))
}

// NodeAuthMiddlewareWithRegistry is the rotating form used by the Server.
// Human paths remain untouched; node paths read one immutable token snapshot
// for each request.
func NodeAuthMiddlewareWithRegistry(next http.Handler, registry *NodeTokenRegistry) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !IsNodeAPIPath(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		nodeID := r.Header.Get("X-Node-ID")
		copySet := registry.snapshot()
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

// NodeLifecycleMiddleware checks the Server-owned revocation tombstone after
// the file-backed token has established identity. Missing lifecycle metadata
// preserves explicitly configured legacy token files; heartbeats never enroll.
func NodeLifecycleMiddleware(next http.Handler, store interface {
	GetNodeLifecycle(context.Context, string) (repo.NodeLifecycle, bool, error)
}) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !IsNodeAPIPath(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		id := AuthenticatedNodeID(r)
		if id == "" {
			runtimeJSON(w, http.StatusUnauthorized, APIError{Error: "node_auth_required", Message: "节点认证失败"})
			return
		}
		item, exists, err := store.GetNodeLifecycle(r.Context(), id)
		if err != nil {
			runtimeJSON(w, http.StatusServiceUnavailable, APIError{Error: "node_registry_unavailable", Message: "节点状态不可用"})
			return
		}
		if exists && item.Status == "REVOKED" {
			runtimeJSON(w, http.StatusForbidden, APIError{Error: "node_revoked", Message: "节点已吊销"})
			return
		}
		if exists && (strings.HasPrefix(r.URL.Path, "/api/v1/worker/") && item.Kind != "worker" || strings.HasPrefix(r.URL.Path, "/api/v1/updater/") && item.Kind != "updater") {
			runtimeJSON(w, http.StatusForbidden, APIError{Error: "node_kind_mismatch", Message: "节点类型不匹配"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

// contextWithNodeIdentity is kept private so handlers cannot manufacture an
// authenticated identity; only the middleware can set it.
func contextWithNodeIdentity(ctx context.Context, nodeID string) context.Context {
	return context.WithValue(ctx, nodeIdentityContextKey{}, nodeID)
}
