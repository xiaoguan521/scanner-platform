-- PostgreSQL baseline 0001: accounts, assets, scope and human approval.
-- Source: docs/architecture-v3.2.md §7 + existing SQLite account/assets/approvals stores.
-- Apply only to a NEW, dedicated PostgreSQL database. Never run on a populated
-- SQLite-derived deployment without a reviewed data migration.
BEGIN;
SET LOCAL search_path TO public;

-- Administrative migration journal; not one of the 17 domain tables.
CREATE TABLE schema_migrations (
    version TEXT PRIMARY KEY,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE users (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    role TEXT NOT NULL CHECK (role IN ('admin', 'security_engineer', 'ops_approver', 'viewer')),
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    password_hash TEXT NOT NULL
);

-- expires_at stores Unix seconds, matching the current account Repository.
-- Only a SHA-256 digest of the opaque cookie is persisted, not its raw value.
CREATE TABLE user_sessions (
    token_hash TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at BIGINT NOT NULL CHECK (expires_at > 0)
);
CREATE INDEX idx_user_sessions_user_id ON user_sessions(user_id);
CREATE INDEX idx_user_sessions_expiry ON user_sessions(expires_at);

CREATE TABLE assets (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL CHECK (kind IN ('host', 'image_repo')),
    address TEXT NOT NULL,
    resolved_ip TEXT,
    business_group TEXT NOT NULL,
    owner TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_assets_kind_address UNIQUE (kind, address),
    CONSTRAINT ck_assets_group_not_blank CHECK (length(btrim(business_group)) > 0),
    CONSTRAINT ck_assets_owner_not_blank CHECK (length(btrim(owner)) > 0)
);
CREATE INDEX idx_assets_business_group ON assets(business_group);
CREATE INDEX idx_assets_owner ON assets(owner);
CREATE INDEX idx_assets_created ON assets(created_at DESC);

-- Registering a desired port is NOT a scan grant.
CREATE TABLE asset_port_requests (
    asset_id TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    port INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
    PRIMARY KEY (asset_id, port)
);

CREATE TABLE asset_port_request_authors (
    asset_id TEXT NOT NULL,
    port INTEGER NOT NULL,
    requested_by TEXT NOT NULL REFERENCES users(id),
    PRIMARY KEY (asset_id, port),
    CONSTRAINT fk_request_author_request
        FOREIGN KEY (asset_id, port)
        REFERENCES asset_port_requests(asset_id, port) ON DELETE CASCADE
);
CREATE INDEX idx_port_request_authors_user ON asset_port_request_authors(requested_by);

-- Explicitly approved/registered ports. Worker authorization still requires
-- Server-side scope, time window, quarantine, lease and network checks.
CREATE TABLE asset_ports (
    asset_id TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    port INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
    kind TEXT NOT NULL CHECK (kind IN ('WEB', 'NON_WEB', 'EXCLUDED_PROXY')),
    source TEXT NOT NULL,
    PRIMARY KEY (asset_id, port)
);

CREATE TABLE port_quarantine (
    asset_id TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    port INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
    reason TEXT NOT NULL,
    detected_at TIMESTAMPTZ NOT NULL,
    status TEXT NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'RELEASED')),
    reviewed_by TEXT,
    reviewed_at TIMESTAMPTZ,
    PRIMARY KEY (asset_id, port)
);
CREATE INDEX idx_port_quarantine_active
    ON port_quarantine(asset_id, port) WHERE status = 'ACTIVE';

CREATE TABLE asset_port_reviews (
    asset_id TEXT NOT NULL,
    port INTEGER NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('APPROVED', 'REJECTED')),
    reviewed_by TEXT NOT NULL REFERENCES users(id),
    approval_ticket TEXT NOT NULL CHECK (length(btrim(approval_ticket)) >= 3),
    reviewed_at TIMESTAMPTZ NOT NULL,
    review_note TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (asset_id, port),
    CONSTRAINT fk_port_review_request
        FOREIGN KEY (asset_id, port)
        REFERENCES asset_port_requests(asset_id, port) ON DELETE CASCADE
);
CREATE INDEX idx_asset_port_reviews_reviewer ON asset_port_reviews(reviewed_by);

-- New applications are always PENDING; applicants may not self-approve.
-- isActive in the UI is derived from status and expires_at (not a DB column).
CREATE TABLE authorized_scopes (
    id TEXT PRIMARY KEY,
    asset_id TEXT NOT NULL REFERENCES assets(id),
    cidr_or_host TEXT NOT NULL,
    max_targets INTEGER NOT NULL DEFAULT 1 CHECK (max_targets > 0),
    time_windows TEXT NOT NULL CHECK (length(btrim(time_windows)) > 0),
    requested_by TEXT NOT NULL REFERENCES users(id),
    approved_by TEXT NOT NULL DEFAULT '',
    approval_ticket TEXT NOT NULL DEFAULT '',
    expires_at TIMESTAMPTZ NOT NULL,
    status TEXT NOT NULL DEFAULT 'PENDING'
        CHECK (status IN ('PENDING', 'APPROVED', 'REJECTED', 'REVOKED')),
    review_note TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT ck_scope_approval_fields CHECK (
        (status = 'PENDING' AND approved_by = '' AND approval_ticket = '')
        OR
        (status <> 'PENDING' AND approved_by <> '' AND approval_ticket <> '')
    ),
    CONSTRAINT ck_scope_independent_reviewer CHECK (
        approved_by = '' OR approved_by <> requested_by
    )
);
CREATE INDEX idx_scopes_asset ON authorized_scopes(asset_id);
CREATE INDEX idx_scopes_status_expiry ON authorized_scopes(status, expires_at);
CREATE INDEX idx_scopes_requested_by ON authorized_scopes(requested_by);

-- Actors may also be system/service identities; preserve logs independently
-- from user lifecycle by not imposing an actor -> users FK.
CREATE TABLE audit_logs (
    id TEXT PRIMARY KEY,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    object_type TEXT,
    object_id TEXT,
    detail TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_audit_actor_time ON audit_logs(actor, created_at DESC);
CREATE INDEX idx_audit_object_time ON audit_logs(object_type, object_id, created_at DESC);

INSERT INTO schema_migrations(version) VALUES ('0001_core');
COMMIT;
