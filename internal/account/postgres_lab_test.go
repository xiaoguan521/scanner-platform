//go:build lab

package account

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"scanner-platform/internal/repo"
)

func TestPostgresAccountRepositoryLab(t *testing.T) {
	dsnFile := os.Getenv("POSTGRES_DSN_FILE")
	if dsnFile == "" {
		t.Skip("set POSTGRES_DSN_FILE to an isolated PostgreSQL fixture")
	}
	dsn, err := repo.ReadPostgresDSNFile(filepath.Clean(dsnFile))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	db, err := repo.OpenPostgres(ctx, repo.PostgresConfig{DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := repo.MigratePostgres(ctx, db); err != nil {
		t.Fatal(err)
	}
	const adminName = "pgacctadmin"
	const userName = "pgacctuser"
	cleanup := func() {
		_, _ = db.ExecContext(ctx, `DELETE FROM audit_logs WHERE actor IN
			(SELECT id FROM users WHERE username IN ($1,$2)) OR object_id IN
			(SELECT id FROM users WHERE username IN ($1,$2))`, adminName, userName)
		_, _ = db.ExecContext(ctx, `DELETE FROM users WHERE username IN ($1,$2)`, adminName, userName)
	}
	cleanup()
	defer cleanup()

	store, err := NewPostgres(db)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.InitAdmin(ctx, adminName, "Admin-Password-123"); err != nil {
		t.Fatal(err)
	}
	admin, token, err := store.Authenticate(ctx, adminName, "Admin-Password-123")
	if err != nil {
		t.Fatal(err)
	}
	if admin.Role != "admin" || token == "" {
		t.Fatalf("admin=%+v token empty=%v", admin, token == "")
	}
	if session, err := store.Session(ctx, token); err != nil || session.ID != admin.ID {
		t.Fatalf("session=%+v err=%v", session, err)
	}
	if err := store.Logout(ctx, token); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Session(ctx, token); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("logged out session err=%v, want unauthorized", err)
	}

	created, err := store.Create(ctx, admin, userName, "User-Password-123", "viewer")
	if err != nil {
		t.Fatal(err)
	}
	if created.Username != userName || !created.IsActive {
		t.Fatalf("created=%+v", created)
	}
	user, userToken, err := store.Authenticate(ctx, userName, "User-Password-123")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Update(ctx, admin, user.ID, "security_engineer", false); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Session(ctx, userToken); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("disabled session err=%v, want unauthorized", err)
	}
	if _, err := store.Update(ctx, admin, user.ID, "security_engineer", true); err != nil {
		t.Fatal(err)
	}
	updated, err := store.ResetPassword(ctx, admin, user.ID, "Reset-Password-123")
	if err != nil {
		t.Fatal(err)
	}
	if updated.Role != "security_engineer" || !updated.IsActive {
		t.Fatalf("reset returned=%+v", updated)
	}
	if _, _, err := store.Authenticate(ctx, userName, "User-Password-123"); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("old password err=%v, want unauthorized", err)
	}
	if _, _, err := store.Authenticate(ctx, userName, "Reset-Password-123"); err != nil {
		t.Fatalf("new password err=%v", err)
	}
	users, err := store.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	matched := 0
	for _, listed := range users {
		if listed.Username == adminName || listed.Username == userName {
			matched++
		}
	}
	if matched != 2 {
		t.Fatalf("matching users=%d err=%v, want 2", matched, err)
	}
}
