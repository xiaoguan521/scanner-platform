package account

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

type User struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Role     string `json:"role"`
	IsActive bool   `json:"isActive"`
}

// Repository keeps HTTP authorization logic independent of SQLite so the
// production Server can later use a PostgreSQL implementation.
type Repository interface {
	Authenticate(context.Context, string, string) (User, string, error)
	Session(context.Context, string) (User, error)
	Logout(context.Context, string) error
	List(context.Context) ([]User, error)
	Create(context.Context, User, string, string, string) (User, error)
	Update(context.Context, User, string, string, bool) (User, error)
	ResetPassword(context.Context, User, string, string) (User, error)
}
type Store struct{ db *sql.DB }

var (
	ErrInvalid      = errors.New("invalid account input")
	ErrExists       = errors.New("account already exists")
	ErrUnauthorized = errors.New("invalid credentials")
	ErrForbidden    = errors.New("operation forbidden")
	ErrMissing      = errors.New("account not found")
)
var usernamePattern = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_.-]{2,39}$`)
var roles = map[string]bool{"admin": true, "security_engineer": true, "ops_approver": true, "viewer": true}

const sessionDuration = 8 * time.Hour

// DefaultSessionDuration is used when the product settings row has not been
// created yet (for example while the account database is being bootstrapped).
func DefaultSessionDuration() time.Duration { return sessionDuration }

// SessionDuration reads the Server-owned product setting without importing the
// repository package. The account store is also used by the setup-only API,
// where product_settings may not exist yet, so a missing table/row uses the
// documented eight-hour default.
func (s *Store) SessionDuration(ctx context.Context) (time.Duration, error) {
	var raw string
	err := s.db.QueryRowContext(ctx, "SELECT data FROM product_settings WHERE id=?", "system-settings").Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) || (err != nil && strings.Contains(strings.ToLower(err.Error()), "no such table")) {
		return sessionDuration, nil
	}
	if err != nil {
		return 0, fmt.Errorf("read session settings: %w", err)
	}
	var settings struct {
		SessionDurationMinutes int `json:"sessionDurationMinutes"`
	}
	if err := json.Unmarshal([]byte(raw), &settings); err != nil {
		return 0, fmt.Errorf("decode session settings: %w", err)
	}
	if settings.SessionDurationMinutes < 30 || settings.SessionDurationMinutes > 1440 {
		return 0, fmt.Errorf("invalid session duration: %d minutes", settings.SessionDurationMinutes)
	}
	return time.Duration(settings.SessionDurationMinutes) * time.Minute, nil
}

func validate(username, password, role string) error {
	if !usernamePattern.MatchString(username) || !roles[role] || len(password) < 12 || len(password) > 72 {
		return fmt.Errorf("%w: username, role or password (12–72 bytes)", ErrInvalid)
	}
	return nil
}
func New(path string) (*Store, error) {
	if path == "" || !filepath.IsAbs(path) {
		return nil, fmt.Errorf("%w: database path must be absolute", ErrInvalid)
	}
	parent := filepath.Dir(path)
	if err := os.MkdirAll(parent, 0700); err != nil {
		return nil, fmt.Errorf("create DB directory: %w", err)
	}
	// Per-connection pragmas belong in the DSN so a replaced connection keeps
	// waiting on a busy database instead of failing instantly.
	db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)")
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	db.SetMaxOpenConns(1) // simple serialized local writes; WAL read scale later
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, stmt := range []string{
		"PRAGMA foreign_keys=ON",
		"PRAGMA busy_timeout=5000",
		"CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, username TEXT NOT NULL UNIQUE, role TEXT NOT NULL CHECK(role IN ('admin','security_engineer','ops_approver','viewer')), is_active INTEGER NOT NULL DEFAULT 1 CHECK(is_active IN (0,1)), password_hash TEXT NOT NULL)",
		"CREATE TABLE IF NOT EXISTS user_sessions (token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, expires_at INTEGER NOT NULL)",
		"CREATE TABLE IF NOT EXISTS audit_logs (id TEXT PRIMARY KEY, actor TEXT NOT NULL, action TEXT NOT NULL, object_type TEXT, object_id TEXT, detail TEXT, created_at TEXT NOT NULL)",
	} {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			db.Close()
			return nil, fmt.Errorf("initialize database: %w", err)
		}
	}
	if err := os.Chmod(path, 0600); err != nil {
		db.Close()
		return nil, fmt.Errorf("secure sqlite file permissions: %w", err)
	}
	return &Store{db: db}, nil
}

// SQLDB exposes the single Server-owned SQLite connection to Repository adapters.
func (s *Store) SQLDB() *sql.DB { return s.db }
func (s *Store) Close() error   { return s.db.Close() }
func randomID() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}
func digest(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}
func (s *Store) InitAdmin(ctx context.Context, username, password string) error {
	if err := validate(username, password, "admin"); err != nil {
		return err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	id, err := randomID()
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var count int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM users").Scan(&count); err != nil {
		return err
	}
	if count != 0 {
		return ErrExists
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO users (id,username,role,is_active,password_hash) VALUES (?, ?, 'admin',1,?)", id, username, string(hash)); err != nil {
		return err
	}
	key, err := randomID()
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO audit_logs(id,actor,action,object_type,object_id,detail,created_at) VALUES (?, ?, 'bootstrap_admin', 'user', ?, '', ?)", key, id, id, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		return err
	}
	return tx.Commit()
}
func (s *Store) Authenticate(ctx context.Context, username, password string) (User, string, error) {
	var u User
	var active int
	var hash string
	err := s.db.QueryRowContext(ctx, "SELECT id,username,role,is_active,password_hash FROM users WHERE username=?", username).Scan(&u.ID, &u.Username, &u.Role, &active, &hash)
	if err != nil {
		// Use bcrypt even for unknown users to reduce username enumeration.
		_ = bcrypt.CompareHashAndPassword([]byte("$2a$10$N9qo8uLOickgx2ZMRZoMye1viPFs0bsMUAfz.gXS6fFqNJHxpHhFy"), []byte(password))
		if errors.Is(err, sql.ErrNoRows) {
			return User{}, "", ErrUnauthorized
		}
		return User{}, "", fmt.Errorf("lookup account: %w", err)
	}
	if active != 1 || bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) != nil {
		return User{}, "", ErrUnauthorized
	}
	u.IsActive = true
	token, err := randomID()
	if err != nil {
		return User{}, "", err
	}
	duration, err := s.SessionDuration(ctx)
	if err != nil {
		return User{}, "", err
	}
	_, err = s.db.ExecContext(ctx, "INSERT INTO user_sessions(token_hash,user_id,expires_at) VALUES (?,?,?)", digest(token), u.ID, time.Now().Add(duration).Unix())
	if err != nil {
		return User{}, "", fmt.Errorf("create session: %w", err)
	}
	return u, token, nil
}
func (s *Store) Session(ctx context.Context, token string) (User, error) {
	if len(token) < 32 || len(token) > 128 {
		return User{}, ErrUnauthorized
	}
	var u User
	var active int
	err := s.db.QueryRowContext(ctx, "SELECT u.id,u.username,u.role,u.is_active FROM user_sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>?", digest(token), time.Now().Unix()).Scan(&u.ID, &u.Username, &u.Role, &active)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return User{}, ErrUnauthorized
		}
		return User{}, err
	}
	if active != 1 {
		return User{}, ErrUnauthorized
	}
	u.IsActive = true
	return u, nil
}
func (s *Store) Logout(ctx context.Context, token string) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM user_sessions WHERE token_hash=?", digest(token))
	return err
}
func (s *Store) List(ctx context.Context) ([]User, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT id,username,role,is_active FROM users ORDER BY username")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	users := make([]User, 0)
	for rows.Next() {
		var u User
		var active int
		if err := rows.Scan(&u.ID, &u.Username, &u.Role, &active); err != nil {
			return nil, err
		}
		u.IsActive = active == 1
		users = append(users, u)
	}
	return users, rows.Err()
}
func (s *Store) Create(ctx context.Context, actor User, username, password, role string) (User, error) {
	if actor.Role != "admin" {
		return User{}, ErrForbidden
	}
	if err := validate(username, password, role); err != nil {
		return User{}, err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return User{}, err
	}
	id, err := randomID()
	if err != nil {
		return User{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return User{}, err
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, "INSERT INTO users(id,username,role,is_active,password_hash) VALUES (?,?,?,1,?)", id, username, role, string(hash))
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return User{}, ErrExists
		}
		return User{}, fmt.Errorf("create user: %w", err)
	}
	key, err := randomID()
	if err != nil {
		return User{}, err
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO audit_logs(id,actor,action,object_type,object_id,detail,created_at) VALUES (?,?,?,'user',?,'',?)", key, actor.ID, "create_user", id, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		return User{}, fmt.Errorf("audit user creation: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return User{}, err
	}

	return User{ID: id, Username: username, Role: role, IsActive: true}, nil
}
func (s *Store) Update(ctx context.Context, actor User, id, role string, active bool) (User, error) {
	if actor.Role != "admin" {
		return User{}, ErrForbidden
	}
	if !roles[role] {
		return User{}, ErrInvalid
	}
	if id == actor.ID && (role != "admin" || !active) {
		return User{}, ErrForbidden
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return User{}, err
	}
	defer tx.Rollback()
	var u User
	var oldRole string
	var oldActive int
	err = tx.QueryRowContext(ctx, "SELECT id,username,role,is_active FROM users WHERE id=?", id).Scan(&u.ID, &u.Username, &oldRole, &oldActive)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return User{}, ErrMissing
		}
		return User{}, err
	}
	if oldRole == "admin" && oldActive == 1 && (role != "admin" || !active) {
		var admins int
		if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM users WHERE role='admin' AND is_active=1").Scan(&admins); err != nil {
			return User{}, err
		}
		if admins <= 1 {
			return User{}, ErrForbidden
		}
	}
	flag := 0
	if active {
		flag = 1
	}
	if _, err := tx.ExecContext(ctx, "UPDATE users SET role=?,is_active=? WHERE id=?", role, flag, id); err != nil {
		return User{}, err
	}
	if !active {
		if _, err := tx.ExecContext(ctx, "DELETE FROM user_sessions WHERE user_id=?", id); err != nil {
			return User{}, err
		}
	}
	key, err := randomID()
	if err != nil {
		return User{}, err
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO audit_logs(id,actor,action,object_type,object_id,detail,created_at) VALUES (?,?,?,'user',?,'',?)", key, actor.ID, "update_user", id, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		return User{}, err
	}
	if err := tx.Commit(); err != nil {
		return User{}, err
	}
	u.Role = role
	u.IsActive = active
	return u, nil
}

// ResetPassword replaces an administrator-managed password and invalidates all
// existing sessions for the target account. The password is never written to
// an audit record or returned to the caller.
func (s *Store) ResetPassword(ctx context.Context, actor User, id, password string) (User, error) {
	if actor.Role != "admin" {
		return User{}, ErrForbidden
	}
	if len(password) < 12 || len(password) > 72 {
		return User{}, ErrInvalid
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return User{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return User{}, err
	}
	defer tx.Rollback()
	var user User
	var active int
	if err := tx.QueryRowContext(ctx, "SELECT id,username,role,is_active FROM users WHERE id=?", id).Scan(&user.ID, &user.Username, &user.Role, &active); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return User{}, ErrMissing
		}
		return User{}, err
	}
	if _, err := tx.ExecContext(ctx, "UPDATE users SET password_hash=? WHERE id=?", string(hash), id); err != nil {
		return User{}, err
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM user_sessions WHERE user_id=?", id); err != nil {
		return User{}, err
	}
	key, err := randomID()
	if err != nil {
		return User{}, err
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO audit_logs(id,actor,action,object_type,object_id,detail,created_at) VALUES (?,?,?,'user',?,'',?)", key, actor.ID, "reset_user_password", id, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		return User{}, err
	}
	if err := tx.Commit(); err != nil {
		return User{}, err
	}
	user.IsActive = active == 1
	return user, nil
}
