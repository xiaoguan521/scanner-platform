-- PostgreSQL migration 0006: explicit manual task pause state.
BEGIN;
SET LOCAL search_path TO public;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM schema_migrations WHERE version = '0005_task_archive') THEN
        RAISE EXCEPTION 'Apply 0005_task_archive.sql before 0006_task_pause.sql';
    END IF;
END
$$;

-- 0002 is an applied migration. Replace its status check in a new migration
-- so existing databases can accept user-paused tasks without rewriting history.
ALTER TABLE scan_tasks DROP CONSTRAINT IF EXISTS scan_tasks_status_check;
ALTER TABLE scan_tasks ADD CONSTRAINT scan_tasks_status_check CHECK (status IN (
    'PENDING', 'WAITING_WINDOW', 'RUNNING', 'PAUSED_WINDOW', 'PAUSED',
    'COMPLETED', 'FAILED', 'CANCELED'
));

INSERT INTO schema_migrations(version) VALUES ('0006_task_pause');
COMMIT;
