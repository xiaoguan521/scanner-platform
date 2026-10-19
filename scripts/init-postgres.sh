#!/usr/bin/env bash
# PostgreSQL migration runner for a NEW, explicitly selected database.
# Passwords belong in ~/.pgpass / credential store, never in Git or CLI args.
set -euo pipefail

if [[ -z "${PGHOST:-}" || -z "${PGDATABASE:-}" || -z "${PGUSER:-}" ]]; then
  echo 'Please set PGHOST, PGDATABASE, and PGUSER explicitly.' >&2
  exit 2
fi
case "$PGDATABASE" in
  postgres|template0|template1)
    echo 'Refusing to modify PostgreSQL system databases.' >&2
    exit 2 ;;
esac
if ! command -v psql >/dev/null 2>&1; then
  echo 'psql must be installed before applying PostgreSQL migrations.' >&2
  exit 2
fi

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
directory="$root/internal/repo/migrations/postgres"
versions=(0001_core 0002_scanning 0003_rules_sbom 0004_report_inventory)

echo "Target PostgreSQL: host=$PGHOST database=$PGDATABASE user=$PGUSER"
journal="$(psql -X -qAt -v ON_ERROR_STOP=1 -c "SELECT to_regclass('public.schema_migrations') IS NOT NULL")"
if [[ "$journal" != t ]]; then
  # Refuse to initialize another application's existing, untracked schema.
  existing="$(psql -X -qAt -v ON_ERROR_STOP=1 \
    -c "SELECT count(*) FROM pg_catalog.pg_tables WHERE schemaname = 'public'")"
  if [[ "$existing" != 0 ]]; then
    echo 'Refusing migration: public schema is non-empty and has no migration journal.' >&2
    exit 2
  fi
fi

for version in "${versions[@]}"; do
  script="$directory/$version.sql"
  if [[ ! -r "$script" ]]; then
    echo "Missing SQL migration: $script" >&2
    exit 2
  fi
  if [[ "$journal" == t ]]; then
    # $version is a constant declared above, never user input.
    applied="$(psql -X -qAt -v ON_ERROR_STOP=1 -c "SELECT EXISTS (SELECT 1 FROM public.schema_migrations WHERE version = '$version')")"
    if [[ "$applied" == t ]]; then
      echo "Already applied: $version"
      continue
    fi
  fi
  echo "Applying migration: $version"
  psql -X -v ON_ERROR_STOP=1 -f "$script"
  journal=t
done
echo 'PostgreSQL migrations complete.'
