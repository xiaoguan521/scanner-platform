-- PostgreSQL migration 0010: rule catalog projection for the explicit runtime.
-- The Updater owns the signed files and CURRENT pointer; PostgreSQL stores
-- only the verified catalog metadata needed for task readiness and UI reads.
BEGIN;
SET LOCAL search_path TO public;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM schema_migrations WHERE version = '0009_finding_projection') THEN
        RAISE EXCEPTION 'Apply 0009_finding_projection.sql before 0010_rule_catalog_projection.sql';
    END IF;
END
$$;

ALTER TABLE rule_bundles
    ADD COLUMN engines TEXT NOT NULL DEFAULT '[]',
    ADD COLUMN is_current BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN is_backup BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN in_use_by_tasks INTEGER NOT NULL DEFAULT 0 CHECK (in_use_by_tasks >= 0),
    ADD COLUMN integrity_verified BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN signature_verified BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN engine_validated BOOLEAN NOT NULL DEFAULT FALSE;

INSERT INTO schema_migrations(version) VALUES ('0010_rule_catalog_projection');
COMMIT;
