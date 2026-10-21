package repo

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

// The PostgreSQL DDL is kept beside the architecture document and embedded in
// the Server binary so migrations do not depend on the process working
// directory or a mutable checkout at runtime.
//
//go:embed migrations/postgres/*.sql
var postgresMigrationFiles embed.FS

var (
	ErrPostgresDSNRequired      = errors.New("postgres dsn is required")
	ErrPostgresDSNFile          = errors.New("invalid postgres dsn file")
	ErrPostgresDirtySchema      = errors.New("postgres public schema is non-empty without a migration journal")
	ErrPostgresInvalidJournal   = errors.New("postgres migration journal is invalid")
	ErrPostgresUnknownMigration = errors.New("postgres migration journal contains an unknown version")
)

const postgresMigrationLock int64 = 712459870123456789

var postgresMigrationName = regexp.MustCompile(`^([0-9]{4}_[a-z0-9][a-z0-9_]*)\.sql$`)

// PostgresConfig contains connection-pool settings for the Server migration
// and future PostgreSQL repository. The DSN is intentionally never included
// in an error returned to callers or in structured logs.
type PostgresConfig struct {
	DSN             string
	MaxOpenConns    int
	MaxIdleConns    int
	ConnMaxLifetime time.Duration
}

func (c PostgresConfig) validate() error {
	if strings.TrimSpace(c.DSN) == "" {
		return ErrPostgresDSNRequired
	}
	if c.MaxOpenConns < 0 || c.MaxIdleConns < 0 || c.ConnMaxLifetime < 0 {
		return fmt.Errorf("invalid postgres pool settings")
	}
	return nil
}

// OpenPostgres opens and pings a PostgreSQL connection owned by sec-server.
// Credentials must come from a protected file or another secure provider; the
// caller owns the returned pool and must close it.
func OpenPostgres(ctx context.Context, config PostgresConfig) (*sql.DB, error) {
	if err := config.validate(); err != nil {
		return nil, err
	}
	db, err := sql.Open("pgx", config.DSN)
	if err != nil {
		return nil, errors.New("open postgres connection failed")
	}
	maxOpen := config.MaxOpenConns
	if maxOpen == 0 {
		maxOpen = 8
	}
	maxIdle := config.MaxIdleConns
	if maxIdle == 0 {
		maxIdle = maxOpen / 2
		if maxIdle < 1 {
			maxIdle = 1
		}
	}
	db.SetMaxOpenConns(maxOpen)
	db.SetMaxIdleConns(maxIdle)
	if config.ConnMaxLifetime > 0 {
		db.SetConnMaxLifetime(config.ConnMaxLifetime)
	}
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, errors.New("ping postgres failed")
	}
	return db, nil
}

// ReadPostgresDSNFile reads a short owner-only connection string. It refuses
// symlinks, group/world-readable files, embedded newlines and oversized input
// so a deployment cannot accidentally load a second line or a shared secret.
func ReadPostgresDSNFile(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", ErrPostgresDSNFile
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 {
		return "", ErrPostgresDSNFile
	}
	file, err := os.Open(path)
	if err != nil {
		return "", ErrPostgresDSNFile
	}
	defer file.Close()
	data, err := ioReadAllLimit(file, 4096)
	if err != nil {
		return "", ErrPostgresDSNFile
	}
	value := strings.TrimSpace(string(data))
	if value == "" || strings.ContainsAny(value, "\r\n\x00") {
		return "", ErrPostgresDSNFile
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return "", ErrPostgresDSNFile
		}
	}
	return value, nil
}

// ioReadAllLimit avoids importing a second reader helper into callers that
// only need a small protected configuration file.
func ioReadAllLimit(file *os.File, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(data)) > limit {
		return nil, ErrPostgresDSNFile
	}
	return data, nil
}

// PostgresMigration is a validated embedded migration script.
type PostgresMigration struct {
	Version string
	SQL     []byte
}

// PostgresMigrations returns a defensive copy in dependency order. It is
// exported for diagnostics and tests; callers must not mutate embedded data.
func PostgresMigrations() ([]PostgresMigration, error) {
	entries, err := fs.Glob(postgresMigrationFiles, "migrations/postgres/*.sql")
	if err != nil {
		return nil, fmt.Errorf("list embedded postgres migrations: %w", err)
	}
	sort.Strings(entries)
	migrations := make([]PostgresMigration, 0, len(entries))
	seen := map[string]bool{}
	for _, entry := range entries {
		name := path.Base(entry)
		match := postgresMigrationName.FindStringSubmatch(name)
		if match == nil || seen[match[1]] {
			return nil, fmt.Errorf("invalid embedded postgres migration name")
		}
		data, err := postgresMigrationFiles.ReadFile(entry)
		if err != nil {
			return nil, fmt.Errorf("read embedded postgres migration: %w", err)
		}
		if len(data) == 0 {
			return nil, fmt.Errorf("empty embedded postgres migration")
		}
		seen[match[1]] = true
		migrations = append(migrations, PostgresMigration{Version: match[1], SQL: append([]byte(nil), data...)})
	}
	if len(migrations) == 0 {
		return nil, fmt.Errorf("no embedded postgres migrations")
	}
	return migrations, nil
}

type PostgresMigrationReport struct {
	Applied        []string `json:"applied"`
	AlreadyApplied []string `json:"alreadyApplied"`
}

// MigratePostgres applies the embedded DDL to a dedicated PostgreSQL public
// schema. It serializes migrators with an advisory lock, refuses an existing
// untracked schema, rejects unknown journal entries and preserves each SQL
// file's transaction boundary. It does not create a database or seed data.
func MigratePostgres(ctx context.Context, db *sql.DB) (PostgresMigrationReport, error) {
	if db == nil {
		return PostgresMigrationReport{}, ErrPostgresDSNRequired
	}
	migrations, err := PostgresMigrations()
	if err != nil {
		return PostgresMigrationReport{}, err
	}
	conn, err := db.Conn(ctx)
	if err != nil {
		return PostgresMigrationReport{}, fmt.Errorf("reserve postgres migration connection: %w", err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, `SELECT pg_advisory_lock($1)`, postgresMigrationLock); err != nil {
		return PostgresMigrationReport{}, fmt.Errorf("lock postgres migrations: %w", err)
	}
	defer func() {
		_, _ = conn.ExecContext(context.Background(), `SELECT pg_advisory_unlock($1)`, postgresMigrationLock)
	}()

	var journal sql.NullString
	if err := conn.QueryRowContext(ctx, `SELECT to_regclass('public.schema_migrations')`).Scan(&journal); err != nil {
		return PostgresMigrationReport{}, fmt.Errorf("inspect postgres migration journal: %w", err)
	}
	applied := map[string]bool{}
	if !journal.Valid || journal.String == "" {
		var tables int
		if err := conn.QueryRowContext(ctx, `SELECT count(*) FROM pg_catalog.pg_tables WHERE schemaname = 'public'`).Scan(&tables); err != nil {
			return PostgresMigrationReport{}, fmt.Errorf("inspect postgres public schema: %w", err)
		}
		if tables != 0 {
			return PostgresMigrationReport{}, ErrPostgresDirtySchema
		}
	} else {
		rows, err := conn.QueryContext(ctx, `SELECT version FROM public.schema_migrations`)
		if err != nil {
			return PostgresMigrationReport{}, fmt.Errorf("read postgres migration journal: %w", err)
		}
		for rows.Next() {
			var version string
			if err := rows.Scan(&version); err != nil {
				rows.Close()
				return PostgresMigrationReport{}, fmt.Errorf("scan postgres migration journal: %w", err)
			}
			applied[version] = true
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return PostgresMigrationReport{}, fmt.Errorf("iterate postgres migration journal: %w", err)
		}
		rows.Close()
		known := make(map[string]bool, len(migrations))
		for _, migration := range migrations {
			known[migration.Version] = true
		}
		for version := range applied {
			if !known[version] {
				return PostgresMigrationReport{}, fmt.Errorf("%w: %s", ErrPostgresUnknownMigration, version)
			}
		}
		if len(applied) == 0 {
			return PostgresMigrationReport{}, ErrPostgresInvalidJournal
		}
	}

	report := PostgresMigrationReport{Applied: []string{}, AlreadyApplied: []string{}}
	seenMissing := false
	for _, migration := range migrations {
		if applied[migration.Version] {
			if seenMissing {
				return PostgresMigrationReport{}, fmt.Errorf("postgres migration journal has a gap before %s", migration.Version)
			}
			report.AlreadyApplied = append(report.AlreadyApplied, migration.Version)
			continue
		}
		seenMissing = true
		if _, err := conn.ExecContext(ctx, string(migration.SQL)); err != nil {
			return PostgresMigrationReport{}, fmt.Errorf("apply postgres migration %s: %w", migration.Version, err)
		}
		var recorded bool
		if err := conn.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM public.schema_migrations WHERE version = $1)`, migration.Version).Scan(&recorded); err != nil {
			return PostgresMigrationReport{}, fmt.Errorf("verify postgres migration %s: %w", migration.Version, err)
		}
		if !recorded {
			return PostgresMigrationReport{}, fmt.Errorf("postgres migration %s did not record itself", migration.Version)
		}
		report.Applied = append(report.Applied, migration.Version)
	}
	return report, nil
}
