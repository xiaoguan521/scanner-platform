# PostgreSQL database migrations

These files implement the schema in [architecture-v3.2.md §7](../../../docs/architecture-v3.2.md), expanded to cover the already-written SQLite account, asset and approval modules. They target the **central Server**, not the portable SQLite build.

## Migration inventory

| File | Tables | Count |
| --- | --- | ---: |
| `postgres/0001_core.sql` | users, user_sessions, assets, asset_port_requests, asset_port_request_authors, asset_ports, port_quarantine, asset_port_reviews, authorized_scopes, audit_logs | 10 |
| `postgres/0002_scanning.sql` | nodes, scan_tasks, scan_task_chunks, security_findings, finding_events | 5 |
| `postgres/0003_rules_sbom.sql` | rule_bundles, artifact_sboms | 2 |

There are **17 business tables** plus the internal `schema_migrations` journal. All SQL scripts use a transaction, include constraints/indexes and record their version. No users, tokens, rules, targets or example data are seeded.

## How to initialize a NEW dedicated database (after review)

Install `psql`, create an empty database and give the migration owner permission to create tables in `public`. Explicitly select the target (the script refuses system databases):

```bash
export PGHOST=localhost
export PGPORT=5432
export PGDATABASE=scanner_platform_dev
export PGUSER=scanner_migrator
# Provide credentials via ~/.pgpass or another secure credential provider.
bash scripts/init-postgres.sh
```

The runner refuses a non-empty public schema with no migration journal, applies versions in order, skips already-recorded versions and aborts on the first SQL error. It does **not** create the PostgreSQL database itself. To run manually, use `psql -X -v ON_ERROR_STOP=1 -f internal/repo/migrations/postgres/0001_core.sql`, then 0002 and 0003. Run one migrator at a time. Never edit an applied migration: add a higher-numbered file. After applying, use the read-only inventory script `bash scripts/check-postgres-schema.sh` to check all 18 tables and the three recorded migrations. This verification is planned for tomorrow, not performed today.

## Important schema differences and boundaries

- These are **PostgreSQL-only** DDL scripts; the Go application **still connects to SQLite**. PostgreSQL `pgx` adapters, migrations-on-startup and production connection settings are not implemented here.
- IDs and serialized JSON remain `TEXT` for compatibility with the architecture's SQLite model. PostgreSQL event timestamps use `TIMESTAMPTZ`, while SQLite currently writes RFC3339 text. **Session expiry is an exception**: `user_sessions.expires_at` uses Unix seconds (`BIGINT`), matching the Go account store.
- The initial authorization flow accepts only a registered **numeric host IP**, not unrestricted CIDRs. Approved scopes/ports are administrative records, *not* Worker leases, firewall exceptions or authority to scan.
- `authorized_scopes.isActive` is calculated from `status` and `expires_at`; it is not stored. `approved_by` uses an empty string while PENDING to match the current application.
- The synthetic/uncommitted `internal/repo/runtime.go` defines simplified, **incompatible** `assets`, `scan_tasks` and `security_findings` SQLite tables. Its structure was intentionally **not** copied into the PostgreSQL schema. It must be reconciled before real PostgreSQL task integration.
- Rule pinning and SBOM historical version fields have no cascading rule-version foreign key because GC and retention are explicit Server/Updater decisions.

**Verification is deferred:** These drafts have not been executed against PostgreSQL, and their indexes, foreign keys, migration re-runs and PostgreSQL Repository compatibility have not been tested. Review on a disposable database before enabling in any environment; never apply them blindly to an existing populated database.
