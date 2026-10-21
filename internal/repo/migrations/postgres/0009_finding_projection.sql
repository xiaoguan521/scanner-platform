-- PostgreSQL migration 0009: full finding projection for the Server API.
-- Stable lifecycle fields remain normalized in security_findings. The JSON
-- projection carries the portable detail shape used by the existing API.
BEGIN;
SET LOCAL search_path TO public;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM schema_migrations WHERE version = '0008_task_projection') THEN
        RAISE EXCEPTION 'Apply 0008_task_projection.sql before 0009_finding_projection.sql';
    END IF;
END
$$;

CREATE TABLE finding_projections (
    finding_id TEXT PRIMARY KEY REFERENCES security_findings(id) ON DELETE CASCADE,
    task_id TEXT NOT NULL REFERENCES scan_tasks(id),
    data TEXT NOT NULL CHECK (length(btrim(data)) > 0),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_finding_projections_task ON finding_projections(task_id, finding_id);

INSERT INTO schema_migrations(version) VALUES ('0009_finding_projection');
COMMIT;
