package approvals

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

func readPort(row interface{ Scan(...any) error }) (PortRequest, error) {
	var p PortRequest
	err := row.Scan(&p.AssetID, &p.Address, &p.Port, &p.Status,
		&p.RequestedBy, &p.ReviewedBy, &p.ApprovalTicket, &p.ReviewedAt, &p.ReviewNote, &p.Kind)
	return p, err
}

const portListQuery = `SELECT r.asset_id,a.address,r.port,
 COALESCE(v.status,'PENDING'),COALESCE(author.requested_by,''),COALESCE(v.reviewed_by,''),
 COALESCE(v.approval_ticket,''),COALESCE(v.reviewed_at,''),
 COALESCE(v.review_note,''),COALESCE(ap.kind,'')
 FROM asset_port_requests r JOIN assets a ON a.id=r.asset_id
 LEFT JOIN asset_port_reviews v ON v.asset_id=r.asset_id AND v.port=r.port
 LEFT JOIN asset_port_request_authors author ON author.asset_id=r.asset_id AND author.port=r.port
 LEFT JOIN asset_ports ap ON ap.asset_id=r.asset_id AND ap.port=r.port`

func (s *Store) ListPortRequests(ctx context.Context) ([]PortRequest, error) {
	rows, err := s.db.QueryContext(ctx, portListQuery+" ORDER BY a.address,r.port")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []PortRequest{}
	for rows.Next() {
		p, err := readPort(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}
func (s *Store) ReviewPort(ctx context.Context, actor, assetID string, port int, d Decision) (PortRequest, error) {
	if assetID == "" || port < 1 || port > 65535 || !validDecision(d) {
		return PortRequest{}, ErrInvalid
	}
	if d.Decision == "APPROVE" && d.Kind != "WEB" && d.Kind != "NON_WEB" {
		return PortRequest{}, ErrInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return PortRequest{}, err
	}
	defer tx.Rollback()
	var address, kind, requester string
	err = tx.QueryRowContext(ctx, `SELECT a.address,a.kind,author.requested_by FROM asset_port_requests r
   JOIN assets a ON a.id=r.asset_id
   JOIN asset_port_request_authors author ON author.asset_id=r.asset_id AND author.port=r.port
   WHERE r.asset_id=? AND r.port=?`, assetID, port).Scan(&address, &kind, &requester)
	if errors.Is(err, sql.ErrNoRows) {
		return PortRequest{}, ErrMissing
	}
	if err != nil {
		return PortRequest{}, err
	}
	if kind != "host" {
		return PortRequest{}, ErrInvalid
	}
	if actor == requester {
		return PortRequest{}, ErrForbidden
	}
	var reviewed int
	err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM asset_port_reviews
   WHERE asset_id=? AND port=?`, assetID, port).Scan(&reviewed)
	if err != nil {
		return PortRequest{}, err
	}
	if reviewed != 0 {
		return PortRequest{}, ErrConflict
	}
	// Quarantined ports must never be approved. Quarantine takes precedence
	// even when a later operator tries to approve the same port.
	var quarantined int
	err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM port_quarantine
   WHERE asset_id=? AND port=? AND status='ACTIVE'`, assetID, port).Scan(&quarantined)
	if err != nil {
		return PortRequest{}, err
	}
	if quarantined > 0 && d.Decision == "APPROVE" {
		return PortRequest{}, ErrConflict
	}
	status := "REJECTED"
	if d.Decision == "APPROVE" {
		status = "APPROVED"
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err = tx.ExecContext(ctx, `INSERT INTO asset_port_reviews
  (asset_id,port,status,reviewed_by,approval_ticket,reviewed_at,review_note)
  VALUES (?,?,?,?,?,?,?)`, assetID, port, status, actor, strings.TrimSpace(d.ApprovalTicket), now, d.Note)
	if err != nil {
		return PortRequest{}, fmt.Errorf("save port review: %w", err)
	}
	if status == "APPROVED" {
		_, err = tx.ExecContext(ctx, `INSERT INTO asset_ports(asset_id,port,kind,source)
    VALUES (?,?,?,'manual_approval')`, assetID, port, d.Kind)
		if err != nil {
			return PortRequest{}, err
		}
	}
	if err := audit(ctx, tx, actor, "review_port_"+strings.ToLower(d.Decision), "asset_port", fmt.Sprintf("%s:%d", assetID, port)); err != nil {
		return PortRequest{}, err
	}
	if err := tx.Commit(); err != nil {
		return PortRequest{}, err
	}
	return PortRequest{AssetID: assetID, Address: address, Port: port, RequestedBy: requester, Kind: d.Kind, Status: status,
		ReviewedBy: actor, ApprovalTicket: strings.TrimSpace(d.ApprovalTicket),
		ReviewedAt: now, ReviewNote: d.Note}, nil
}
