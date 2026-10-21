-- PostgreSQL migration 0007: asset catalog support resources.
-- These records contain administrative summaries only; CSV source rows and
-- scan evidence remain outside this migration.
BEGIN;
SET LOCAL search_path TO public;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM schema_migrations WHERE version = '0006_task_pause') THEN
        RAISE EXCEPTION 'Apply 0006_task_pause.sql before 0007_asset_catalog.sql';
    END IF;
END
$$;

CREATE TABLE asset_business_groups (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_asset_business_groups_name ON asset_business_groups(name);

CREATE TABLE asset_import_previews (
    id TEXT PRIMARY KEY,
    actor TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    rows_json TEXT NOT NULL,
    expires_at BIGINT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('PENDING','CONFIRMED'))
);

CREATE TABLE asset_import_history (
    id TEXT PRIMARY KEY,
    actor TEXT NOT NULL,
    imported INTEGER NOT NULL CHECK (imported > 0),
    total INTEGER NOT NULL CHECK (total >= imported),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_asset_import_history_created_at ON asset_import_history(created_at DESC, id DESC);

INSERT INTO schema_migrations(version) VALUES ('0007_asset_catalog');
COMMIT;
