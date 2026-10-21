-- PostgreSQL scheduled scan definitions and safe run history.
BEGIN;
SET LOCAL search_path TO public;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM schema_migrations WHERE version = '0011_rule_jobs') THEN
        RAISE EXCEPTION 'Apply 0011_rule_jobs.sql before 0012_schedules.sql';
    END IF;
END
$$;

CREATE TABLE task_schedules (
    id TEXT PRIMARY KEY,
    data TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_task_schedules_due ON task_schedules(updated_at, id);

-- Deliberately no foreign keys: schedule history remains readable after the
-- schedule or generated task is removed, matching the SQLite projection.
CREATE TABLE schedule_runs (
    id TEXT PRIMARY KEY,
    schedule_id TEXT NOT NULL,
    task_id TEXT NOT NULL DEFAULT '',
    triggered_at TIMESTAMPTZ NOT NULL,
    error TEXT NOT NULL DEFAULT ''
);
CREATE INDEX idx_schedule_runs_history ON schedule_runs(schedule_id, triggered_at DESC, id DESC);

INSERT INTO schema_migrations(version) VALUES ('0012_schedules');
COMMIT;
