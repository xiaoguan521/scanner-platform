package account

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
)

func TestSQLiteAccountLifecycle(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "accounts.sqlite")
	store, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.InitAdmin(ctx, "admin_user", "Strong-Demo-Password-21"); err != nil {
		t.Fatal(err)
	}
	if err := store.InitAdmin(ctx, "admin_next", "Strong-Demo-Password-22"); !errors.Is(err, ErrExists) {
		t.Fatalf("second bootstrap: %v", err)
	}
	if _, _, err := store.Authenticate(ctx, "admin_user", "invalid password"); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("accepted invalid login: %v", err)
	}
	admin, token, err := store.Authenticate(ctx, "admin_user", "Strong-Demo-Password-21")
	if err != nil {
		t.Fatal(err)
	}
	if admin.Role != "admin" || token == "" {
		t.Fatal("invalid admin login")
	}
	if _, err := store.Session(ctx, token); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Update(ctx, admin, admin.ID, "viewer", false); !errors.Is(err, ErrForbidden) {
		t.Fatalf("admin self-demotion allowed: %v", err)
	}
	if _, err := store.Create(ctx, admin, "bad", "weak", "viewer"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("short password allowed: %v", err)
	}
	user, err := store.Create(ctx, admin, "reader_user", "Another-Demo-Password-31", "viewer")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Create(ctx, admin, "reader_user", "Another-Demo-Password-31", "viewer"); !errors.Is(err, ErrExists) {
		t.Fatalf("duplicate username allowed: %v", err)
	}
	viewer, viewerToken, err := store.Authenticate(ctx, "reader_user", "Another-Demo-Password-31")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Create(ctx, viewer, "newreader", "Another-Demo-Password-32", "viewer"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("viewer created user: %v", err)
	}
	if _, err := store.Update(ctx, viewer, admin.ID, "viewer", false); !errors.Is(err, ErrForbidden) {
		t.Fatalf("viewer changed admin: %v", err)
	}
	list, err := store.List(ctx)
	if err != nil || len(list) != 2 {
		t.Fatalf("list: %v, %v", list, err)
	}
	updated, err := store.Update(ctx, admin, user.ID, "ops_approver", false)
	if err != nil || updated.IsActive {
		t.Fatalf("deactivate: %v, %v", updated, err)
	}
	if _, err := store.Session(ctx, viewerToken); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("disabled user still authenticated: %v", err)
	}
	if err := store.Logout(ctx, token); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Session(ctx, token); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("logout session accepted: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	list, err = reopened.List(ctx)
	if err != nil || len(list) != 2 {
		t.Fatalf("SQLite lost users: %v %v", list, err)
	}
}
func TestInvalidDatabasePath(t *testing.T) {
	if _, err := New("relative.sqlite"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("relative DB path: %v", err)
	}
}
