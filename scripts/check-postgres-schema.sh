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
        ('rule_bundles'), ('artifact_sboms')
      ) AS expected(name)
     WHERE to_regclass(format('public.%I', name)) IS NULL;

    IF missing IS NOT NULL THEN
        RAISE EXCEPTION 'Missing PostgreSQL tables: %', array_to_string(missing, ', ');
    END IF;
    IF (SELECT count(*) FROM public.schema_migrations
         WHERE version IN ('0001_core','0002_scanning','0003_rules_sbom')) <> 3 THEN
        RAISE EXCEPTION 'Not all three initial migrations have been recorded';
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
     'rule_bundles','artifact_sboms'
   );

SELECT version, applied_at FROM public.schema_migrations ORDER BY version;
SQL
