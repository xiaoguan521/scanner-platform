-- PostgreSQL baseline 0002: node registry, task queue and finding lifecycle.
-- Based on docs/architecture-v3.2.md §7, not on the temporary synthetic
-- runtime SQLite tables in internal/repo/runtime.go.
BEGIN;
SET LOCAL search_path TO public;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM schema_migrations WHERE version = '0001_core') THEN
        RAISE EXCEPTION 'Apply 0001_core.sql before 0002_scanning.sql';
    END IF;
END
$$;

-- Only the Server has DB credentials. Worker/updater tokens are stored hashed.
CREATE TABLE nodes (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL CHECK (kind IN ('worker', 'updater')),
    host_id TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    revoked_at TIMESTAMPTZ,
    last_heartbeat TIMESTAMPTZ
);
CREATE INDEX idx_nodes_host_kind ON nodes(host_id, kind);
CREATE INDEX idx_nodes_last_heartbeat ON nodes(last_heartbeat);

CREATE TABLE scan_tasks (
    id TEXT PRIMARY KEY,
    scope_id TEXT NOT NULL REFERENCES authorized_scopes(id),
    engines TEXT NOT NULL CHECK (length(btrim(engines)) > 0), -- JSON array as TEXT
    status TEXT NOT NULL DEFAULT 'PENDING'
        CHECK (status IN (
            'PENDING', 'WAITING_WINDOW', 'RUNNING', 'PAUSED_WINDOW',
            'COMPLETED', 'FAILED', 'CANCELED'
        )),
    hard_deadline TIMESTAMPTZ,
    created_by TEXT NOT NULL REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_scan_tasks_queue ON scan_tasks(status, created_at, id);
CREATE INDEX idx_scan_tasks_scope ON scan_tasks(scope_id, created_at DESC);
CREATE INDEX idx_scan_tasks_creator ON scan_tasks(created_by, created_at DESC);

-- Targets contain only Server-validated numeric IP:port pairs serialized as
-- JSON TEXT. No Worker-side discovery or CIDR expansion.
CREATE TABLE scan_task_chunks (
    id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL REFERENCES scan_tasks(id),
    targets TEXT NOT NULL CHECK (length(btrim(targets)) > 0),
    status TEXT NOT NULL DEFAULT 'PENDING',
    worker_node_id TEXT REFERENCES nodes(id),
    pinned_rule_version TEXT,
    lease_expires_at TIMESTAMPTZ,
    completed_fully BOOLEAN NOT NULL DEFAULT FALSE,
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ
);
CREATE INDEX idx_chunks_poll ON scan_task_chunks(status, lease_expires_at);
CREATE INDEX idx_chunks_task_status ON scan_task_chunks(task_id, status);
CREATE INDEX idx_chunks_worker_lease ON scan_task_chunks(worker_node_id, lease_expires_at);
CREATE INDEX idx_chunks_rule_version_status ON scan_task_chunks(pinned_rule_version, status);

-- Stable fingerprint is unique per asset; dynamic request/response material
-- belongs to evidence_json, never to fingerprint_hash.
CREATE TABLE security_findings (
    id TEXT PRIMARY KEY,
    asset_id TEXT NOT NULL REFERENCES assets(id),
    fingerprint_hash TEXT NOT NULL,
    engine_name TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    location TEXT NOT NULL,
    evidence_json TEXT NOT NULL,             -- JSON as TEXT for SQLite parity
    lifecycle_status TEXT NOT NULL DEFAULT 'OPEN'
        CHECK (lifecycle_status IN (
            'OPEN', 'REOPENED', 'IN_PROGRESS', 'FIXED',
            'FALSE_POSITIVE', 'ACCEPTED_RISK'
        )),
    accepted_until TIMESTAMPTZ,
    sla_deadline TIMESTAMPTZ,
    first_seen_task_id TEXT NOT NULL REFERENCES scan_tasks(id),
    last_seen_task_id TEXT NOT NULL REFERENCES scan_tasks(id),
    first_seen_at TIMESTAMPTZ,
    last_seen_at TIMESTAMPTZ,
    resolved_at TIMESTAMPTZ,
    CONSTRAINT uq_findings_asset_fingerprint UNIQUE (asset_id, fingerprint_hash)
);
CREATE INDEX idx_findings_severity_status ON security_findings(severity, lifecycle_status);
CREATE INDEX idx_findings_status_sla ON security_findings(lifecycle_status, sla_deadline);
CREATE INDEX idx_findings_last_seen_task ON security_findings(last_seen_task_id);

CREATE TABLE finding_events (
    id TEXT PRIMARY KEY,
    finding_id TEXT NOT NULL REFERENCES security_findings(id),
    from_status TEXT,
    to_status TEXT NOT NULL,
    actor TEXT,
    reason TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_finding_events_history ON finding_events(finding_id, created_at DESC);

-- PostgreSQL-specific leasing implementation is intentionally deferred:
-- the Server should use SELECT ... FOR UPDATE SKIP LOCKED in its own
-- transaction, with a pinned rule version and expiry checks.
INSERT INTO schema_migrations(version) VALUES ('0002_scanning');
COMMIT;
