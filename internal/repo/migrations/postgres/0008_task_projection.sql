-- PostgreSQL migration 0008: task UI projection and advisory progress.
-- Queue status, leases and target chunks remain authoritative in 0002. This
-- projection stores the Server-owned task fields that are not part of the
-- normalized queue schema, so the API can expose the same safe task shape as
-- the SQLite runtime without putting raw engine output in the queue tables.
BEGIN;
SET LOCAL search_path TO public;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM schema_migrations WHERE version = '0007_asset_catalog') THEN
        RAISE EXCEPTION 'Apply 0007_asset_catalog.sql before 0008_task_projection.sql';
    END IF;
END
$$;

CREATE TABLE scan_task_projections (
    task_id TEXT PRIMARY KEY REFERENCES scan_tasks(id) ON DELETE CASCADE,
    data TEXT NOT NULL CHECK (length(btrim(data)) > 0),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE scan_task_progress (
    task_id TEXT PRIMARY KEY REFERENCES scan_tasks(id) ON DELETE CASCADE,
    worker_id TEXT NOT NULL,
    phase TEXT NOT NULL,
    completed INTEGER NOT NULL CHECK (completed >= 0),
    total INTEGER NOT NULL CHECK (total >= completed),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_scan_task_progress_updated
    ON scan_task_progress(updated_at DESC, task_id);

INSERT INTO schema_migrations(version) VALUES ('0008_task_projection');
COMMIT;
