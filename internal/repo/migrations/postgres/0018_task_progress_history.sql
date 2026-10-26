BEGIN;
SET LOCAL search_path TO public;

-- Final counts of finished phases and the ports found so far (JSON text, empty
-- when none); lets the UI show phase n/m and live results while a task runs.
ALTER TABLE scan_task_progress ADD COLUMN history TEXT NOT NULL DEFAULT '';

INSERT INTO schema_migrations(version) VALUES ('0018_task_progress_history');
COMMIT;
