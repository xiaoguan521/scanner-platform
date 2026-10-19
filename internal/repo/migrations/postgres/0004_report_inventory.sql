-- Report/inventory additions. JSON remains TEXT for SQLite parity.
-- This baseline does not implement a PostgreSQL RuntimeStore adapter.
BEGIN;
SET LOCAL search_path TO public;
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM schema_migrations WHERE version = '0003_rules_sbom') THEN
        RAISE EXCEPTION 'Apply 0003_rules_sbom.sql before 0004_report_inventory.sql';
    END IF;
END
$$;
CREATE TABLE asset_profiles (
    asset_id TEXT PRIMARY KEY REFERENCES assets(id) ON DELETE CASCADE,
    data TEXT NOT NULL
);
CREATE TABLE asset_services (
    asset_id TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    port INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
    data TEXT NOT NULL,
    PRIMARY KEY (asset_id, port)
);
CREATE TABLE asset_login_entries (
    asset_id TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    entry_key TEXT NOT NULL,
    data TEXT NOT NULL,
    PRIMARY KEY (asset_id, entry_key)
);
CREATE TABLE asset_reachability (
    asset_id TEXT PRIMARY KEY REFERENCES assets(id) ON DELETE CASCADE,
    status TEXT NOT NULL CHECK (status IN ('REACHABLE','NO_RESPONSE','CHECK_FAILED')),
    checked_at TEXT NOT NULL
);
CREATE TABLE product_settings (id TEXT PRIMARY KEY, data TEXT NOT NULL);
CREATE TABLE vulnerability_knowledge (id TEXT PRIMARY KEY, data TEXT NOT NULL);
-- Per-task immutable observations are distinct from the current lifecycle row.
CREATE TABLE task_finding_observations (
    task_id TEXT NOT NULL REFERENCES scan_tasks(id),
    finding_id TEXT NOT NULL,
    data TEXT NOT NULL,
    PRIMARY KEY (task_id, finding_id)
);
CREATE TABLE report_templates (id TEXT PRIMARY KEY, data TEXT NOT NULL);
CREATE TABLE report_snapshots (
    id TEXT PRIMARY KEY,
    schema_version INTEGER NOT NULL,
    data TEXT NOT NULL
);
CREATE TABLE report_jobs (
    id TEXT PRIMARY KEY,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    snapshot_id TEXT NOT NULL REFERENCES report_snapshots(id),
    data TEXT NOT NULL,
    file_path TEXT NOT NULL DEFAULT ''
);
CREATE INDEX report_job_queue ON report_jobs(status, created_at, id);
-- Finding detection method, confidence, CVSS and knowledge metadata are portable
-- serialized content; the baseline uses evidence_json, not RuntimeStore's data.
-- No target, result, credential or third-party knowledge is seeded.
INSERT INTO schema_migrations(version) VALUES ('0004_report_inventory');
COMMIT;
