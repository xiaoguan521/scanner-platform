# Deployment status and runtime contract

This directory contains the production image build targets and a deployment
Compose contract. The Compose file requires immutable image digests and
owner-managed secret files; it has no build directives and must not be used
with placeholder values from `production.env.example`. The executable entry
points and security boundaries are implemented, while real remote service
orchestration and isolated-Linux acceptance remain deployment-stage checks.

## Build immutable service images

Build and publish each target with BuildKit, then record the resulting digest
in an owner-managed environment file. The build downloads only the SHA-256
pinned Nuclei and Trivy distributions from `config/engines.lock.json`:

```text
docker buildx build --platform linux/amd64 --target server \
  --tag registry.example.invalid/scanner-platform-server:VERSION \
  --push -f deploy/Dockerfile .
docker buildx build --platform linux/amd64 --target worker \
  --tag registry.example.invalid/scanner-platform-worker:VERSION \
  --push -f deploy/Dockerfile .
docker buildx build --platform linux/amd64 --target updater \
  --tag registry.example.invalid/scanner-platform-updater:VERSION \
  --push -f deploy/Dockerfile .
```

Use the registry's returned `@sha256:...` references in a copied
`production.env.example`. Never put registry credentials, private keys, node
tokens or populated environment files in the repository.

## Prepare and validate the deployment

Create `deploy/secrets/` with owner-only files. The files must contain the
PostgreSQL DSN, database password, Server/node certificates and keys, the
role-scoped Worker/Updater credentials, and the Ed25519 rule public key. The
Server certificate must have the numeric SAN `172.30.1.10` used by the
Compose worker network. Before starting anything, run:

```text
set -a; . ./deploy/production.env; set +a
DEPLOY_COMPOSE_FILE=deploy/compose.production.yaml make verify-deploy
docker compose --env-file deploy/production.env \
  -f deploy/compose.production.yaml config --quiet
```

The static gate checks immutable images, explicit networks, secret references,
loopback-only web publishing, no host namespace or privileged mode, the
Worker capability allowlist, read-only rule data, and private writable
runtime. It does not replace the Linux namespace, cgroup, DROP-counter,
range-capture or service-manager acceptance tests.

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

After a trusted deployment channel copies a generated material directory to a
node, run the read-only preflight before restarting services:

```text
sec-node-provision --verify-dir /var/lib/scanner-platform/node-materials
```

The preflight does not need the CA private key and does not contact the
Server. It rejects unlisted files, non-owner-only secret material, malformed
token registries, mismatched keys, invalid certificate chains and a Server
certificate whose numeric IP SAN differs from the manifest. A successful
preflight is a material check, not evidence that remote service orchestration
or Linux fence acceptance is complete.

### Role-scoped material packages

Do not copy the complete provisioning directory to every node: it contains
the Server key and the other nodes' bearer tokens. Create a package for each
deployment role and verify that package after transfer:

```text
sec-node-provision \
  --split-from /var/lib/scanner-platform/node-materials \
  --split-output-dir /var/lib/scanner-platform/packages/worker-a \
  --package-role worker --node-id worker-a

sec-node-provision \
  --split-from /var/lib/scanner-platform/node-materials \
  --split-output-dir /var/lib/scanner-platform/packages/server \
  --package-role server

sec-node-provision --verify-dir /var/lib/scanner-platform/packages/worker-a
```

The Server package contains `ca-cert.pem`, the Server certificate/key and the
node token registry. A Worker or Updater package contains only its own client
certificate/key and token plus `ca-cert.pem`. Package manifests are role
scoped and the verifier rejects extra files, missing files, mismatched node
roles and owner-permission violations. This is still an offline packaging
step; remote copy, service restart and automatic enrollment remain deployment
system responsibilities.

### Explicit SSH deployment

`sec-node-deploy` turns a verified role package into a reviewable plan. It
requires a numeric target IP, an owner-only SSH identity file, a pinned
`known_hosts` file, an absolute remote directory and an allowlisted scanner
service name. It defaults to dry-run; only `--dry-run=false` executes the
fixed `ssh`/`scp` sequence:

```text
sec-node-deploy \
  --package-dir /var/lib/scanner-platform/packages/worker-a \
  --target-ip 192.0.2.20 --ssh-port 22 --user scanner \
  --identity-file /etc/scanner-platform/deploy-key \
  --known-hosts-file /etc/scanner-platform/known_hosts \
  --remote-dir /var/lib/scanner-platform/node-materials \
  --service sec-worker
```

The sequence creates a fresh remote staging directory, copies only the role
package, runs the remote read-only preflight, publishes the directory only if
the destination is absent, and restarts the fixed service. A pre-publish
failure removes the staging directory; a publish or restart failure is
reported without deleting the published material. The command never discovers
hosts, accepts hostnames/CIDRs, invokes a local shell or prints command
output.

Pass `--rotate-existing` only for an explicit material replacement. The
rotation plan moves the old directory to a unique rollback directory before
publishing, restarts the service, and removes the rollback copy only after a
successful restart. Publish or restart failures run a fixed restore and
restart sequence; a failed restore is reported and its rollback directory is
left for recovery. This is still an operator-triggered action: it does not
auto-register nodes, change tokens, or deploy the CA private key.

## Linux fenced Worker contract

The repository now includes `sec-fence-launcher` as the trusted Linux entry
point. It opens the parent namespace before forking, creates a private
network namespace for `sec-worker`, passes the parent namespace as fd 3, and
owns the `--fence --once --fence-parent-netns-fd=3` flags. Worker arguments
must appear after `--`; the launcher rejects attempts to override those
flags. A supervisor should restart the launcher for the next task after the
one-shot Worker exits.

Example (paths and addresses are deployment values, not repository defaults):

```text
sec-fence-launcher \
  --worker /opt/sec/bin/sec-worker -- \
  --server https://192.0.2.10:8443 \
  --node-token-file /run/secrets/worker-token \
  --fence-cgroup-root /sys/fs/cgroup/sec-worker \
  --fence-infra tcp://192.0.2.53:53 \
  --bin-dir /opt/sec/bin --rules-dir /vuln-data \
  --runtime-dir /runtime/worker --inputs-dir /runtime/inputs
```

The launcher is the trusted boundary; the Worker still enforces all task
scope and rule checks. The Linux fenced Worker execution path is described in
`docs/worker-fence.md`:

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

The launcher creates a dedicated network namespace and passes the parent
namespace as fd 3. Worker containers must not use `hostNetwork` or reuse the
host namespace. The Worker rule directory is read-only; only the
private runtime and input directories are writable by uid 10001. `nft` and
`setpriv` paths are pinned, and the dropped engine process has no capabilities
and `no_new_privs`. Each namespace handles one task and is then destroyed.

### One-shot Worker supervisor

`sec-worker-supervisor` is the external restart loop for the one-shot launcher.
It validates both executable paths as pinned, non-writable regular files,
passes Worker arguments only after `--`, and never invokes a shell. A clean
one-task exit uses the base delay; consecutive failures use bounded exponential
backoff. `--max-restarts` can be set for a finite deployment test, while the
default `0` keeps the node available for subsequent tasks. SIGTERM/SIGINT
cancels the current launcher and does not start another cycle.

```text
sec-worker-supervisor \
  --launcher /opt/sec/bin/sec-fence-launcher \
  --worker /opt/sec/bin/sec-worker \
  --restart-delay 2s --max-backoff 60s \
  -- \
  --server https://192.0.2.10:8443 \
  --node-token-file /run/secrets/worker-token \
  --fence-cgroup-root /sys/fs/cgroup/sec-worker \
  --fence-infra tcp://192.0.2.53:53 \
  --bin-dir /opt/sec/bin --rules-dir /vuln-data \
  --runtime-dir /runtime/worker --inputs-dir /runtime/inputs
```

The supervisor only manages process lifetime; the launcher remains responsible
for the network namespace, parent-namespace fd and forced `--fence --once`
arguments. It does not read database credentials, node tokens or scan results.

Only the Server address and explicitly listed numeric `IP:port` infrastructure
permits may be reachable. The Server still fixes every scan target and port;
the Worker does not resolve names or expand networks.

## Compose security gate

The repository intentionally does not provide a runnable production Compose
file. Before operating a deployment file, normalize it with Docker Compose and
run the static security gate:

```text
DEPLOY_COMPOSE_FILE=/path/to/compose.yaml make verify-deploy
```

`scripts/verify_compose_security.py` consumes only `docker compose config
--format json`; it never starts services. It fails closed when the deployment
is missing the `sec-server`, `sec-updater`, `postgres`, or `sec-worker-*`
roles, uses a host namespace or privileged container, publishes Worker/Updater/
PostgreSQL ports, places sensitive values directly in environment variables,
gives a Worker unsafe capabilities, mounts `/vuln-data` writable in a Worker,
or leaves the Worker runtime read-only. It also rejects unpinned image tags and
direct `build:` contexts; every service must name an approved `@sha256` image.
Server ports must bind loopback, the Updater must run non-root, and all secret
sources must be owner-managed files.
The check is a deployment gate, not proof that the resulting Linux namespace,
firewall, cgroup, or packet-drop behavior has been accepted; those isolated
runtime tests remain required.

## Remaining deployment gates

The following items are intentionally not represented by a fake Compose file:

- pinned Server/Updater/Worker images and reproducible image builds;
- remote transfer and service orchestration around the generated secret, certificate, and token files (local atomic rotation via `sec-node-provision --rotate-dir` is available);
- isolated-Linux evidence for out-of-scope packet drops, uid/capabilities,
    `no_new_privs`, cgroup-v2 descendant cleanup, and forbidden `hostNetwork`;
- production PostgreSQL backup/restore, monitoring, and migration rollout;
- remote node deployment and automatic certificate issuance.

Until these gates are completed, use the local Make targets or the explicit
isolated lab procedures. Do not treat a local macOS Worker, the PostgreSQL
fixture, or the architecture Compose fragment as production deployment
evidence.
