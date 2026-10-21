#!/usr/bin/env bash
# Read-only post-initialization PostgreSQL schema inventory.
# Intended for the next validation session; not run during code drafting.
set -euo pipefail

if [[ -z "${PGHOST:-}" || -z "${PGDATABASE:-}" || -z "${PGUSER:-}" ]]; then
  echo 'Set PGHOST, PGDATABASE and PGUSER explicitly.' >&2
  exit 2
fi
if ! command -v psql >/dev/null 2>&1; then
  echo 'psql is required.' >&2
  exit 2
fi

psql -X -v ON_ERROR_STOP=1 <<'SQL'
DO $$
DECLARE missing TEXT[];
BEGIN
    SELECT array_agg(name ORDER BY name)
      INTO missing
      FROM (VALUES
        ('schema_migrations'),
        ('users'), ('user_sessions'), ('assets'),
        ('asset_port_requests'), ('asset_port_request_authors'),
        ('asset_ports'), ('port_quarantine'), ('asset_port_reviews'),
        ('authorized_scopes'), ('audit_logs'),
        ('nodes'), ('scan_tasks'), ('scan_task_chunks'),
        ('security_findings'), ('finding_events'),
        ('rule_bundles'), ('artifact_sboms'),
        ('asset_profiles'), ('asset_services'), ('asset_login_entries'), ('asset_reachability'),
        ('product_settings'), ('vulnerability_knowledge'), ('task_finding_observations'),
        ('report_templates'), ('report_snapshots'), ('report_jobs'),
        ('asset_business_groups'), ('asset_import_previews'), ('asset_import_history'),
        ('scan_task_projections'), ('scan_task_progress')
      ) AS expected(name)
     WHERE to_regclass(format('public.%I', name)) IS NULL;

    IF missing IS NOT NULL THEN
        RAISE EXCEPTION 'Missing PostgreSQL tables: %', array_to_string(missing, ', ');
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
         WHERE table_schema = 'public' AND table_name = 'scan_tasks' AND column_name = 'archived_at'
    ) THEN
        RAISE EXCEPTION 'Missing scan_tasks.archived_at';
    END IF;
    IF (SELECT count(*) FROM public.schema_migrations
         WHERE version IN ('0001_core','0002_scanning','0003_rules_sbom','0004_report_inventory','0005_task_archive','0006_task_pause','0007_asset_catalog','0008_task_projection')) <> 8 THEN
        RAISE EXCEPTION 'Not all eight migrations have been recorded';
    END IF;
END
$$;

SELECT 'Verified table count' AS item, count(*)::text AS value
  FROM pg_catalog.pg_tables
 WHERE schemaname = 'public'
   AND tablename IN (
     'schema_migrations','users','user_sessions','assets',
     'asset_port_requests','asset_port_request_authors',
     'asset_ports','port_quarantine','asset_port_reviews',
     'authorized_scopes','audit_logs','nodes','scan_tasks',
     'scan_task_chunks','security_findings','finding_events',
     'rule_bundles','artifact_sboms',
     'asset_profiles','asset_services','asset_login_entries','asset_reachability',
     'product_settings','vulnerability_knowledge','task_finding_observations',
     'report_templates','report_snapshots','report_jobs',
     'asset_business_groups','asset_import_previews','asset_import_history',
     'scan_task_projections','scan_task_progress'
   );

SELECT version, applied_at FROM public.schema_migrations ORDER BY version;
SQL
