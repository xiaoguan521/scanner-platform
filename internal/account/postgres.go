package account

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// PostgresStore implements the account Repository against the Server-owned
// PostgreSQL pool. The constructor never migrates or creates a database; the
// caller must run the repository migration gate before enabling this store.
type PostgresStore struct {
	db     *sql.DB
	ownsDB bool
}

var _ Repository = (*PostgresStore)(nil)

func NewPostgres(db *sql.DB) (*PostgresStore, error) {
	if db == nil {
		return nil, fmt.Errorf("%w: missing postgres database", ErrInvalid)
	}
	return &PostgresStore{db: db}, nil
}

// SQLDB exposes the Server-owned PostgreSQL pool for other Server adapters.
// Worker and Updater never receive this value.
func (s *PostgresStore) SQLDB() *sql.DB { return s.db }

func (s *PostgresStore) Close() error {
	if s != nil && s.ownsDB && s.db != nil {
		return s.db.Close()
	}
	return nil
}

func (s *PostgresStore) SessionDuration(ctx context.Context) (time.Duration, error) {
	if s == nil || s.db == nil {
		return 0, fmt.Errorf("read session settings: missing database")
	}
	var raw string
	err := s.db.QueryRowContext(ctx, "SELECT data FROM product_settings WHERE id=$1", "system-settings").Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) || isPostgresMissingRelation(err) {
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

func isPostgresMissingRelation(err error) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), "relation") && strings.Contains(strings.ToLower(err.Error()), "does not exist")
}

func (s *PostgresStore) InitAdmin(ctx context.Context, username, password string) error {
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
	if _, err := tx.ExecContext(ctx, `INSERT INTO users
		(id,username,role,is_active,password_hash)
		VALUES ($1,$2,'admin',TRUE,$3)`, id, username, string(hash)); err != nil {
		return fmt.Errorf("create postgres administrator: %w", err)
	}
	key, err := randomID()
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO audit_logs
		(id,actor,action,object_type,object_id,detail,created_at)
		VALUES ($1,$2,'bootstrap_admin','user',$2,'',CURRENT_TIMESTAMP)`, key, id); err != nil {
		return fmt.Errorf("audit postgres administrator: %w", err)
	}
	return tx.Commit()
}

func (s *PostgresStore) Authenticate(ctx context.Context, username, password string) (User, string, error) {
	var u User
	var active bool
	var hash string
	err := s.db.QueryRowContext(ctx, `SELECT id,username,role,is_active,password_hash
		FROM users WHERE username=$1`, username).Scan(&u.ID, &u.Username, &u.Role, &active, &hash)
	if err != nil {
		_ = bcrypt.CompareHashAndPassword([]byte("$2a$10$N9qo8uLOickgx2ZMRZoMye1viPFs0bsMUAfz.gXS6fFqNJHxpHhFy"), []byte(password))
		if errors.Is(err, sql.ErrNoRows) {
			return User{}, "", ErrUnauthorized
		}
		return User{}, "", fmt.Errorf("lookup postgres account: %w", err)
	}
	if !active || bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) != nil {
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
	if _, err := s.db.ExecContext(ctx, `INSERT INTO user_sessions(token_hash,user_id,expires_at)
		VALUES ($1,$2,$3)`, digest(token), u.ID, time.Now().Add(duration).Unix()); err != nil {
		return User{}, "", fmt.Errorf("create postgres session: %w", err)
	}
	return u, token, nil
}

func (s *PostgresStore) Session(ctx context.Context, token string) (User, error) {
	if len(token) < 32 || len(token) > 128 {
		return User{}, ErrUnauthorized
	}
	var u User
	var active bool
	err := s.db.QueryRowContext(ctx, `SELECT u.id,u.username,u.role,u.is_active
		FROM user_sessions s JOIN users u ON u.id=s.user_id
		WHERE s.token_hash=$1 AND s.expires_at>$2`, digest(token), time.Now().Unix()).Scan(&u.ID, &u.Username, &u.Role, &active)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return User{}, ErrUnauthorized
		}
		return User{}, err
	}
	if !active {
		return User{}, ErrUnauthorized
	}
	u.IsActive = true
	return u, nil
}

func (s *PostgresStore) Logout(ctx context.Context, token string) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM user_sessions WHERE token_hash=$1", digest(token))
	return err
}

func (s *PostgresStore) List(ctx context.Context) ([]User, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT id,username,role,is_active FROM users ORDER BY username")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	users := make([]User, 0)
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.Username, &u.Role, &u.IsActive); err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, rows.Err()
}

func (s *PostgresStore) Create(ctx context.Context, actor User, username, password, role string) (User, error) {
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
	if _, err := tx.ExecContext(ctx, `INSERT INTO users
		(id,username,role,is_active,password_hash)
		VALUES ($1,$2,$3,TRUE,$4)`, id, username, role, string(hash)); err != nil {
		if isPostgresUniqueViolation(err) {
			return User{}, ErrExists
		}
		return User{}, fmt.Errorf("create postgres user: %w", err)
	}
	if err := postgresAudit(ctx, tx, actor.ID, "create_user", id); err != nil {
		return User{}, err
	}
	if err := tx.Commit(); err != nil {
		return User{}, err
	}
	return User{ID: id, Username: username, Role: role, IsActive: true}, nil
}

func isPostgresUniqueViolation(err error) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), "duplicate key")
}

func postgresAudit(ctx context.Context, tx *sql.Tx, actor, action, objectID string) error {
	key, err := randomID()
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO audit_logs
		(id,actor,action,object_type,object_id,detail,created_at)
		VALUES ($1,$2,$3,'user',$4,'',CURRENT_TIMESTAMP)`, key, actor, action, objectID); err != nil {
		return fmt.Errorf("audit postgres user change: %w", err)
	}
	return nil
}

func (s *PostgresStore) Update(ctx context.Context, actor User, id, role string, active bool) (User, error) {
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
	var oldActive bool
	if err := tx.QueryRowContext(ctx, `SELECT id,username,role,is_active
		FROM users WHERE id=$1`, id).Scan(&u.ID, &u.Username, &oldRole, &oldActive); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return User{}, ErrMissing
		}
		return User{}, err
	}
	if oldRole == "admin" && oldActive && (role != "admin" || !active) {
		var admins int
		if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM users WHERE role='admin' AND is_active=TRUE").Scan(&admins); err != nil {
			return User{}, err
		}
		if admins <= 1 {
			return User{}, ErrForbidden
		}
	}
	if _, err := tx.ExecContext(ctx, "UPDATE users SET role=$1,is_active=$2 WHERE id=$3", role, active, id); err != nil {
		return User{}, err
	}
	if !active {
		if _, err := tx.ExecContext(ctx, "DELETE FROM user_sessions WHERE user_id=$1", id); err != nil {
			return User{}, err
		}
	}
	if err := postgresAudit(ctx, tx, actor.ID, "update_user", id); err != nil {
		return User{}, err
	}
	if err := tx.Commit(); err != nil {
		return User{}, err
	}
	u.Role = role
	u.IsActive = active
	return u, nil
}

func (s *PostgresStore) ResetPassword(ctx context.Context, actor User, id, password string) (User, error) {
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
	if err := tx.QueryRowContext(ctx, "SELECT id,username,role,is_active FROM users WHERE id=$1", id).Scan(&user.ID, &user.Username, &user.Role, &user.IsActive); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return User{}, ErrMissing
		}
		return User{}, err
	}
	if _, err := tx.ExecContext(ctx, "UPDATE users SET password_hash=$1 WHERE id=$2", string(hash), id); err != nil {
		return User{}, err
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM user_sessions WHERE user_id=$1", id); err != nil {
		return User{}, err
	}
	if err := postgresAudit(ctx, tx, actor.ID, "reset_user_password", id); err != nil {
		return User{}, err
	}
	if err := tx.Commit(); err != nil {
		return User{}, err
	}
	return user, nil
}
