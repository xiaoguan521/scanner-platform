-- PostgreSQL migration 0016: distinguish newly frozen task thresholds from
-- projections created before the lifecycle threshold was persisted.
BEGIN;
SET LOCAL search_path TO public;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM schema_migrations WHERE version = '0015_finding_work') THEN
        RAISE EXCEPTION 'Apply 0015_finding_work.sql before 0016_freeze_threshold_marker.sql';
    END IF;
END
$$;

-- Existing projections are intentionally left unfrozen. Their historical
-- policy threshold is unavailable, so completed reports must not converge a
-- missing finding to FIXED. New task creation marks the selected threshold.
ALTER TABLE scan_task_projections
    ADD COLUMN fixed_threshold_frozen BOOLEAN NOT NULL DEFAULT FALSE;

INSERT INTO schema_migrations(version) VALUES ('0016_freeze_threshold_marker');
COMMIT;

