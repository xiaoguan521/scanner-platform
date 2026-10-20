-- Archived tasks stay stored and recoverable; only the default task list hides them.
BEGIN;
SET LOCAL search_path TO public;
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM schema_migrations WHERE version = '0004_report_inventory') THEN
        RAISE EXCEPTION 'Apply 0004_report_inventory.sql before 0005_task_archive.sql';
    END IF;
END
$$;
ALTER TABLE scan_tasks ADD COLUMN archived_at TIMESTAMPTZ;
CREATE INDEX idx_scan_tasks_archive_created ON scan_tasks(archived_at, created_at DESC);
INSERT INTO schema_migrations(version) VALUES ('0005_task_archive');
COMMIT;
