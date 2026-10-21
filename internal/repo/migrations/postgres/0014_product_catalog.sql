-- PostgreSQL product catalog and administration projections.
BEGIN;
SET LOCAL search_path TO public;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM schema_migrations WHERE version = '0013_notifications') THEN
        RAISE EXCEPTION 'Apply 0013_notifications.sql before 0014_product_catalog.sql';
    END IF;
END
$$;

CREATE TABLE custom_rules (
    id TEXT PRIMARY KEY,
    data TEXT NOT NULL CHECK (length(btrim(data)) > 0),
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX idx_custom_rules_updated ON custom_rules(updated_at DESC, id DESC);

CREATE TABLE scan_plans (
    id TEXT PRIMARY KEY,
    data TEXT NOT NULL CHECK (length(btrim(data)) > 0),
    created_by TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX idx_scan_plans_updated ON scan_plans(updated_at DESC, id DESC);

INSERT INTO schema_migrations(version) VALUES ('0014_product_catalog');
COMMIT;
