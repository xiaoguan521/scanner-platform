package approvals

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// RenewScopes turns every selected approved scope into a new pending request.
// The operation is all-or-nothing: a missing, revoked, rejected or already
// pending scope aborts the whole batch and leaves every row unchanged.
func (s *Store) RenewScopes(ctx context.Context, actor string, input ScopeRenewalInput) ([]Scope, error) {
	if strings.TrimSpace(actor) == "" {
		return nil, ErrInvalid
	}
	in, expiresAt, err := normalizeScopeRenewalInput(input)
	if err != nil {
		return nil, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	items := make([]Scope, 0, len(in.IDs))
	for _, id := range in.IDs {
		item, err := readScope(tx.QueryRowContext(ctx, "SELECT "+scopeFields+" FROM authorized_scopes WHERE id=?", id))
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrMissing
		}
		if err != nil {
			return nil, err
		}
		if item.Status != "APPROVED" {
			return nil, ErrConflict
		}
		if _, err := tx.ExecContext(ctx, `UPDATE authorized_scopes SET
			expires_at=?,status='PENDING',approved_by='',approval_ticket='',review_note=''
			WHERE id=? AND status='APPROVED'`, in.ExpiresAt, id); err != nil {
			return nil, err
		}
		if err := audit(ctx, tx, actor, "renew_scope_reset_approval", "scope", id); err != nil {
			return nil, err
		}
		item.ExpiresAt = expiresAt.Format(time.RFC3339)
		item.Status = "PENDING"
		item.ApprovedBy = ""
		item.ApprovalTicket = ""
		item.ReviewNote = ""
		item.ExpiryState = "NOT_APPLICABLE"
		item.IsActive = false
		items = append(items, item)
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return items, nil
}

func (s *PostgresStore) RenewScopes(ctx context.Context, actor string, input ScopeRenewalInput) ([]Scope, error) {
	if strings.TrimSpace(actor) == "" {
		return nil, ErrInvalid
	}
	in, expiresAt, err := normalizeScopeRenewalInput(input)
	if err != nil {
		return nil, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	items := make([]Scope, 0, len(in.IDs))
	for _, id := range in.IDs {
		item, err := readPostgresScope(tx.QueryRowContext(ctx, "SELECT "+scopeFields+" FROM authorized_scopes WHERE id=$1 FOR UPDATE", id))
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrMissing
		}
		if err != nil {
			return nil, err
		}
		if item.Status != "APPROVED" {
			return nil, ErrConflict
		}
		if _, err := tx.ExecContext(ctx, `UPDATE authorized_scopes SET
			expires_at=$1,status='PENDING',approved_by='',approval_ticket='',review_note=''
			WHERE id=$2 AND status='APPROVED'`, expiresAt, id); err != nil {
			return nil, err
		}
		if err := postgresAudit(ctx, tx, actor, "renew_scope_reset_approval", "scope", id); err != nil {
			return nil, err
		}
		item.ExpiresAt = expiresAt.Format(time.RFC3339)
		item.Status = "PENDING"
		item.ApprovedBy = ""
		item.ApprovalTicket = ""
		item.ReviewNote = ""
		item.ExpiryState = "NOT_APPLICABLE"
		item.IsActive = false
		items = append(items, item)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit postgres scope renewal: %w", err)
	}
	return items, nil
}
