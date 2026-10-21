-- PostgreSQL migration 0015: human finding work and frozen lifecycle threshold.
BEGIN;
SET LOCAL search_path TO public;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM schema_migrations WHERE version = '0014_product_catalog') THEN
        RAISE EXCEPTION 'Apply 0014_product_catalog.sql before 0015_finding_work.sql';
    END IF;
END
$$;

-- Task JSON deliberately omits this Server-only field. Keep the value selected
-- at task creation so later policy changes cannot alter lifecycle decisions.
ALTER TABLE scan_task_projections
    ADD COLUMN fixed_threshold INTEGER NOT NULL DEFAULT 1
    CHECK (fixed_threshold BETWEEN 1 AND 3);

CREATE TABLE finding_notes (
    id TEXT PRIMARY KEY,
    finding_id TEXT NOT NULL REFERENCES security_findings(id) ON DELETE CASCADE,
    actor TEXT NOT NULL,
    actor_name TEXT NOT NULL,
    body TEXT NOT NULL CHECK (octet_length(body) BETWEEN 1 AND 2000),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_finding_notes_history
    ON finding_notes(finding_id, created_at, id);

CREATE TABLE finding_assignment_events (
    id TEXT PRIMARY KEY,
    finding_id TEXT NOT NULL REFERENCES security_findings(id) ON DELETE CASCADE,
    from_assignee TEXT NOT NULL DEFAULT '',
    to_assignee TEXT NOT NULL DEFAULT '',
    actor TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_finding_assignment_events_history
    ON finding_assignment_events(finding_id, created_at, id);

-- A relation records which existing task was started for one finding. The
-- target and engine remain in the frozen task projection, not in this table.
CREATE TABLE finding_retests (
    id TEXT PRIMARY KEY,
    finding_id TEXT NOT NULL REFERENCES security_findings(id) ON DELETE CASCADE,
    task_id TEXT NOT NULL UNIQUE REFERENCES scan_tasks(id) ON DELETE CASCADE,
    actor TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_finding_retests_history
    ON finding_retests(finding_id, created_at, id);

INSERT INTO schema_migrations(version) VALUES ('0015_finding_work');
COMMIT;
