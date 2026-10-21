-- PostgreSQL rule import/fetch/activation queue.
BEGIN;
SET LOCAL search_path TO public;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM schema_migrations WHERE version = '0010_rule_catalog_projection') THEN
        RAISE EXCEPTION 'Apply 0010_rule_catalog_projection.sql before 0011_rule_jobs.sql';
    END IF;
END
$$;

CREATE TABLE rule_jobs (
    id TEXT PRIMARY KEY,
    status TEXT NOT NULL CHECK (status IN ('PENDING', 'RUNNING', 'COMPLETED', 'FAILED')),
    data TEXT NOT NULL,
    bundle BYTEA,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_rule_jobs_queue ON rule_jobs(status, created_at, id);

INSERT INTO schema_migrations(version) VALUES ('0011_rule_jobs');
COMMIT;
