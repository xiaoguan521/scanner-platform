package api

import (
	"context"
	"errors"
	"strings"

	"scanner-platform/internal/repo"
)

// NodeCredential is returned only to the authenticated administrator that
// explicitly requested issuance. The token is not stored in the database or
// included in audit detail and must be copied into an owner-only node file.
type NodeCredential struct {
	ID        string `json:"id"`
	Kind      string `json:"kind"`
	HostID    string `json:"hostId"`
	ServerURL string `json:"serverUrl,omitempty"`
	Token     string `json:"token"`
}

type NodeCredentialIssuer interface {
	IssueNodeCredential(context.Context, string, string) (NodeCredential, error)
	RotateNodeCredential(context.Context, string, string) (NodeCredential, error)
}

type fileNodeCredentialIssuer struct {
	store        repo.RuntimeBackend
	registry     *NodeTokenRegistry
	registryPath string
	serverURL    string
}

func NewFileNodeCredentialIssuer(store repo.RuntimeBackend, registry *NodeTokenRegistry, registryPath, serverURL string) NodeCredentialIssuer {
	if store == nil || registry == nil || strings.TrimSpace(registryPath) == "" {
		return nil
	}
	return &fileNodeCredentialIssuer{store: store, registry: registry, registryPath: registryPath, serverURL: strings.TrimRight(strings.TrimSpace(serverURL), "/")}
}

func (i *fileNodeCredentialIssuer) IssueNodeCredential(ctx context.Context, id, actor string) (NodeCredential, error) {
	if i == nil || i.store == nil || i.registry == nil {
		return NodeCredential{}, repo.ErrBackendCapability
	}
	if !runtimeWorkerID.MatchString(id) {
		return NodeCredential{}, repo.ErrInvalidNodeLifecycle
	}
	item, found, err := i.store.GetNodeLifecycle(ctx, id)
	if err != nil {
		return NodeCredential{}, err
	}
	if !found {
		return NodeCredential{}, repo.ErrNodeLifecycleNotFound
	}
	if item.Status == "REVOKED" {
		return NodeCredential{}, repo.ErrNodeRevoked
	}
	token, err := i.registry.issueFile(i.registryPath, id, func(string) error {
		return i.store.RecordNodeCredentialIssued(ctx, id, actor)
	})
	if err != nil {
		return NodeCredential{}, err
	}
	return NodeCredential{ID: item.ID, Kind: item.Kind, HostID: item.HostID, ServerURL: i.serverURL, Token: token}, nil
}

func (i *fileNodeCredentialIssuer) RotateNodeCredential(ctx context.Context, id, actor string) (NodeCredential, error) {
	if i == nil || i.store == nil || i.registry == nil {
		return NodeCredential{}, repo.ErrBackendCapability
	}
	if !runtimeWorkerID.MatchString(id) {
		return NodeCredential{}, repo.ErrInvalidNodeLifecycle
	}
	item, found, err := i.store.GetNodeLifecycle(ctx, id)
	if err != nil {
		return NodeCredential{}, err
	}
	if !found {
		return NodeCredential{}, repo.ErrNodeLifecycleNotFound
	}
	if item.Status == "REVOKED" {
		return NodeCredential{}, repo.ErrNodeRevoked
	}
	token, err := i.registry.rotateFile(i.registryPath, id, func(string) error {
		return i.store.RecordNodeCredentialRotated(ctx, id, actor)
	})
	if err != nil {
		return NodeCredential{}, err
	}
	return NodeCredential{ID: item.ID, Kind: item.Kind, HostID: item.HostID, ServerURL: i.serverURL, Token: token}, nil
}

func nodeCredentialError(err error) (int, string, bool) {
	switch {
	case errors.Is(err, repo.ErrNodeLifecycleNotFound):
		return 404, "node_not_registered", true
	case errors.Is(err, repo.ErrNodeRevoked):
		return 409, "node_revoked", true
	case errors.Is(err, repo.ErrNodeCredentialExists):
		return 409, "node_credential_exists", true
	case errors.Is(err, repo.ErrNodeCredentialNotFound):
		return 404, "node_credential_not_found", true
	case errors.Is(err, repo.ErrInvalidNodeLifecycle):
		return 400, "invalid_node_id", true
	case errors.Is(err, ErrInvalidNodeTokenFile):
		return 503, "node_issuance_unavailable", true
	default:
		return 0, "", false
	}
}
