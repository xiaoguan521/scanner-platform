# Deployment status and runtime contract

This directory does not yet contain production Dockerfiles or a production
Compose file. The Compose fragment in `docs/architecture-v3.2.md` remains a
design skeleton and must not be started as-is. The executable entry points and
the security boundaries they require are implemented; deployment orchestration
and its isolated-Linux acceptance are still pending.

## Supported local modes

Use the repository Make targets for the two supported local control-plane
modes:

```text
make dev

POSTGRES_DSN_FILE=/path/to/owner-only.dsn make migrate-postgres
POSTGRES_DSN_FILE=/path/to/owner-only.dsn make dev-postgres
```

`make dev` uses the portable SQLite control plane. `make dev-postgres` selects
PostgreSQL explicitly; it does not migrate or copy the SQLite database. The
PostgreSQL DSN and administrator password are read from owner-only files. The
PostgreSQL fixture under `lab/orbstack-target/` is for isolated verification,
not a production dependency.

## Multi-process node contract

The Server web/API listener stays on a numeric loopback address. A deployment
that runs Worker or Updater as separate processes must give them the dedicated
HTTPS node listener and owner-only node token files:

```text
sec-server \
  --listen 127.0.0.1:8080 \
  --node-listen 192.0.2.10:8443 \
  --node-tls-cert /run/secrets/node-cert.pem \
  --node-tls-key /run/secrets/node-key.pem \
  --node-tls-client-ca /run/secrets/node-client-ca.pem \
  --node-token-file /run/secrets/node-tokens
```

Worker and Updater point `--server` at that HTTPS numeric `IP:port` and read
their own token files. Tokens must not be passed in environment variables or
written to logs. The separate listener only serves node protocol paths; the
web UI remains on the loopback listener. See `docs/runtime.md` and
`docs/api/README.md` for the complete flag and rotation contract.

## Linux fenced Worker contract

The only supported production-shaped Worker execution path is the Linux
fenced mode described in `docs/worker-fence.md`:

```text
sec-worker \
  --server https://192.0.2.10:8443 \
  --node-token-file /run/secrets/worker-token \
  --fence --once --fence-parent-netns-fd 3 \
  --fence-cgroup-root /sys/fs/cgroup/sec-worker \
  --fence-infra tcp://192.0.2.53:53 \
  --bin-dir /opt/sec/bin --rules-dir /vuln-data \
  --runtime-dir /runtime/worker --inputs-dir /runtime/inputs
```

The trusted launcher must create a dedicated network namespace and pass the
parent namespace as fd 3. Worker containers must not use `hostNetwork` or
reuse the host namespace. The Worker rule directory is read-only; only the
private runtime and input directories are writable by uid 10001. `nft` and
`setpriv` paths are pinned, and the dropped engine process has no capabilities
and `no_new_privs`. Each namespace handles one task and is then destroyed.

Only the Server address and explicitly listed numeric `IP:port` infrastructure
permits may be reachable. The Server still fixes every scan target and port;
the Worker does not resolve names or expand networks.

## Remaining deployment gates

The following items are intentionally not represented by a fake Compose file:

- pinned Server/Updater/Worker images and reproducible image builds;
- secret, certificate, token, and parent-namespace launcher orchestration;
- isolated-Linux evidence for out-of-scope packet drops, uid/capabilities,
    `no_new_privs`, cgroup-v2 descendant cleanup, and forbidden `hostNetwork`;
- production PostgreSQL backup/restore, monitoring, and migration rollout;
- remote node deployment and automatic certificate issuance.

Until these gates are completed, use the local Make targets or the explicit
isolated lab procedures. Do not treat a local macOS Worker, the PostgreSQL
fixture, or the architecture Compose fragment as production deployment
evidence.
