# PostgreSQL database migrations

These files implement the schema in [architecture-v3.2.md §7](../../../docs/architecture-v3.2.md), expanded to cover the already-written SQLite account, asset and approval modules. They target the **central Server**, not the portable SQLite build. The Go Server embeds these migrations, and its runtime can explicitly select PostgreSQL with a protected DSN file; SQLite remains the default portable backend.

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
| `postgres/0009_finding_projection.sql` | finding UI projection | 1 |
| `postgres/0010_rule_catalog_projection.sql` | rule catalog metadata projection | 0 new tables |
| `postgres/0011_rule_jobs.sql` | rule import/fetch/activation queue | 1 |
| `postgres/0012_schedules.sql` | scheduled scan definitions and run history | 2 |
| `postgres/0013_notifications.sql` | in-product notifications and safe webhook outbox | 2 |
| `postgres/0014_product_catalog.sql` | custom rules and scan plan catalog | 2 |

There are **40 business tables** plus the internal `schema_migrations` journal. All SQL scripts use a transaction, include constraints/indexes and record their version. No users, tokens, rules, targets or example data are seeded.

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

The runner refuses a non-empty public schema with no migration journal, applies versions in order, skips already-recorded versions and aborts on the first SQL error. It does **not** create the PostgreSQL database itself. To run manually, apply migrations `0001_core.sql` through `0014_product_catalog.sql` in order. Run one migrator at a time. Never edit an applied migration: add a higher-numbered file. After applying, use the read-only inventory script `bash scripts/check-postgres-schema.sh` to check all 41 tables including the journal, the fourteen recorded migrations, and the task archive/projection columns. The fourteen migrations were executed and journal-checked against the isolated PostgreSQL fixture on 2026-10-21. The Server-side runtime now wires the account, asset, approval, task queue/projection, finding, report, rule-catalog, rule-job, schedule, notification and product-catalog adapters when explicitly selected; only remaining non-core system administration endpoints are capability-gated.

## Important schema differences and boundaries

- These are **PostgreSQL-only** DDL scripts. The Go application now has the
  protected connection and migration foundation (`internal/repo/postgres.go`)
  plus the Server-side queue, task projection, finding, report, schedule,
  notification and product-catalog adapters (`internal/repo/postgres_queue.go`,
  `internal/repo/postgres_task_projection.go`,
  `internal/repo/postgres_findings.go`, `internal/repo/postgres_reports.go`,
  `internal/repo/postgres_schedules.go`, `internal/repo/postgres_notifications.go`,
  `internal/repo/postgres_product.go`). `sec-server --storage postgres
  --postgres-dsn-file <file>` selects these adapters without a SQLite fallback;
  some rule/system administration endpoints remain explicitly unavailable.
- IDs and serialized JSON remain `TEXT` for compatibility with the architecture's SQLite model. PostgreSQL event timestamps use `TIMESTAMPTZ`, while SQLite currently writes RFC3339 text. **Session expiry is an exception**: `user_sessions.expires_at` uses Unix seconds (`BIGINT`), matching the Go account store.
- The runtime accepts explicitly selected **numeric host IPs**, not CIDRs or domain expansion. The selected port strategy authorizes bounded read-only discovery/checks on that target; per-port approval is no longer a gate. Legacy scope/port approvals remain administrative records, not Worker leases or firewall exceptions.
- `authorized_scopes.isActive` is calculated from `status` and `expires_at`; it is not stored. `approved_by` uses an empty string while PENDING to match the current application.
- The local SQLite runtime now shares the account/asset schema; an earlier synthetic assets table is preserved as `assets_legacy_runtime` during upgrade. Its synthetic task/finding tables and local schedules/rule queues are still different from this PostgreSQL baseline. PostgreSQL intentionally returns a capability-unavailable response for runtime features that do not yet have a PostgreSQL table/adapter instead of reading SQLite.
- Inventory, service, login, policy, knowledge and report records in 0004 use TEXT JSON. Report snapshots are versioned; task observations are separate from current finding lifecycle rows. Migration 0009 stores the complete finding UI/lifecycle projection while `security_findings` remains authoritative for stable identity and status; `task_finding_observations` remains the immutable per-task view. The SQLite RuntimeStore stores archive state in task details JSON; the PostgreSQL schema uses `scan_tasks.archived_at`. Migration 0008 stores the remaining task UI fields as a bounded JSON projection and progress as a separate advisory row; queue state and leases remain authoritative in normalized tables.
- Rule pinning and SBOM historical version fields have no cascading rule-version foreign key because GC and retention are explicit Server/Updater decisions.

The embedded runner and protected-file checks have unit coverage, and all
fourteen migrations were executed against an isolated PostgreSQL instance on
2026-10-21. The queue, task projection, finding, report, schedule, notification
and product-catalog adapters' `lab` regressions cover their transaction,
lifecycle, snapshot and worker behavior there. Account/asset/approval
compatibility, cross-backend parity and the full browser journey still require
isolated verification; never apply these migrations blindly to an existing
populated database.
