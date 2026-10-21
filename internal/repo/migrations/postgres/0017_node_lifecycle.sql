BEGIN;
SET LOCAL search_path TO public;

CREATE TABLE node_lifecycle (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL CHECK (kind IN ('worker', 'updater')),
    host_id TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('REGISTERED', 'ONLINE', 'OFFLINE', 'REVOKED')),
    registered_at TEXT NOT NULL,
    last_heartbeat TEXT,
    revoked_at TEXT,
    offline_generation INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE node_lifecycle_events (
    id TEXT PRIMARY KEY,
    node_id TEXT NOT NULL REFERENCES node_lifecycle(id),
    kind TEXT NOT NULL,
    generation INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(node_id, kind, generation)
);
CREATE INDEX idx_node_lifecycle_events_node ON node_lifecycle_events(node_id, created_at);

INSERT INTO schema_migrations(version) VALUES ('0017_node_lifecycle');
COMMIT;
