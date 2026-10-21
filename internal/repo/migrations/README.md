# PostgreSQL database migrations

These files implement the schema in [architecture-v3.2.md §7](../../../docs/architecture-v3.2.md), expanded to cover the already-written SQLite account, asset and approval modules. They target the **central Server**, not the portable SQLite build. The Go Server now embeds and can run these migrations from a protected DSN file; the product runtime still uses SQLite until the full PostgreSQL Repository and startup selection are completed.

## Migration inventory

| File | Tables | Count |
| --- | --- | ---: |
| `postgres/0001_core.sql` | users, user_sessions, assets, asset_port_requests, asset_port_request_authors, asset_ports, port_quarantine, asset_port_reviews, authorized_scopes, audit_logs | 10 |
| `postgres/0002_scanning.sql` | nodes, scan_tasks, scan_task_chunks, security_findings, finding_events | 5 |
| `postgres/0003_rules_sbom.sql` | rule_bundles, artifact_sboms | 2 |
| `postgres/0004_report_inventory.sql` | asset_profiles, asset_services, asset_login_entries, asset_reachability, product_settings, vulnerability_knowledge, task_finding_observations, report_templates, report_snapshots, report_jobs | 10 |
| `postgres/0005_task_archive.sql` | `scan_tasks.archived_at` plus task archive listing index | 0 new tables |
| `postgres/0006_task_pause.sql` | `scan_tasks.status` manual `PAUSED` state constraint | 0 new tables |
| `postgres/0007_asset_catalog.sql` | asset business groups, import previews and import history | 3 |
| `postgres/0008_task_projection.sql` | task UI projection and Worker progress | 2 |

There are **32 business tables** plus the internal `schema_migrations` journal. All SQL scripts use a transaction, include constraints/indexes and record their version. No users, tokens, rules, targets or example data are seeded.

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

The same migration set can be applied through the built Server without relying
on the checkout directory:

```bash
chmod 600 /path/to/scanner-platform-postgres.dsn
POSTGRES_DSN_FILE=/path/to/scanner-platform-postgres.dsn make migrate-postgres
```

The command opens the DSN only from an owner-only regular file, acquires a
PostgreSQL advisory lock, refuses a non-empty untracked public schema, rejects
unknown or gapped journal entries, and prints only the applied version names.
It does not create a database, seed users/assets/rules, or switch the running
SQLite Server to PostgreSQL.

The runner refuses a non-empty public schema with no migration journal, applies versions in order, skips already-recorded versions and aborts on the first SQL error. It does **not** create the PostgreSQL database itself. To run manually, apply migrations `0001_core.sql` through `0008_task_projection.sql` in order. Run one migrator at a time. Never edit an applied migration: add a higher-numbered file. After applying, use the read-only inventory script `bash scripts/check-postgres-schema.sh` to check all 33 tables including the journal, the eight recorded migrations, and the task archive/projection columns. The eight migrations were executed and journal-checked against the isolated PostgreSQL fixture on 2026-10-21; this still does not mean that the product runtime has switched from SQLite or that the full PostgreSQL Repository is complete. The Server-side `PostgresTaskStore` now exercises the core queue contract (create, `FOR UPDATE SKIP LOCKED` claim, lease renewal, completion and running-version count), and `PostgresTaskProjection` persists the safe task fields and advisory progress; both remain isolated adapters and do not switch the web runtime.

## Important schema differences and boundaries

- These are **PostgreSQL-only** DDL scripts. The Go application now has the
  protected connection and migration foundation (`internal/repo/postgres.go`)
  plus the initial Server-side queue and task projection adapters
  (`internal/repo/postgres_queue.go`, `internal/repo/postgres_task_projection.go`),
  but the product runtime still connects to SQLite; account, asset, approval,
  finding/report adapters and dual-backend startup selection are not
  implemented here.
- IDs and serialized JSON remain `TEXT` for compatibility with the architecture's SQLite model. PostgreSQL event timestamps use `TIMESTAMPTZ`, while SQLite currently writes RFC3339 text. **Session expiry is an exception**: `user_sessions.expires_at` uses Unix seconds (`BIGINT`), matching the Go account store.
- The runtime accepts explicitly selected **numeric host IPs**, not CIDRs or domain expansion. The selected port strategy authorizes bounded read-only discovery/checks on that target; per-port approval is no longer a gate. Legacy scope/port approvals remain administrative records, not Worker leases or firewall exceptions.
- `authorized_scopes.isActive` is calculated from `status` and `expires_at`; it is not stored. `approved_by` uses an empty string while PENDING to match the current application.
- The local SQLite runtime now shares the account/asset schema; an earlier synthetic assets table is preserved as `assets_legacy_runtime` during upgrade. Its synthetic task/finding tables and local schedules/rule queues are still different from this PostgreSQL baseline. The initial PostgreSQL queue adapter is implemented, but the remaining Repository adapters and runtime migration plan are still incomplete.
- Inventory, service, login, policy, knowledge and report records in 0004 use TEXT JSON. Report snapshots are versioned; task observations are separate from current finding lifecycle rows. Existing PostgreSQL finding JSON is `evidence_json`, while RuntimeStore uses a `data` column: the baseline is not a drop-in runtime adapter. The SQLite RuntimeStore stores archive state in task details JSON; the PostgreSQL schema uses `scan_tasks.archived_at`. Migration 0008 stores the remaining task UI fields as a bounded JSON projection and progress as a separate advisory row; queue state and leases remain authoritative in normalized tables.
- Rule pinning and SBOM historical version fields have no cascading rule-version foreign key because GC and retention are explicit Server/Updater decisions.

The embedded runner and protected-file checks have unit coverage, and the eight
 migrations were executed against an isolated PostgreSQL instance on
 2026-10-21. The queue adapter's `lab` regression covers its transaction and
 lease behavior there. Account/asset/approval/finding/report compatibility,
 cross-backend parity and startup selection still require isolated verification;
 never apply these migrations blindly to an existing populated database.
