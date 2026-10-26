package repo

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"scanner-platform/internal/inventory"
)

// ReleaseAllQuarantines releases every active quarantine of one asset in a single
// transaction with one audit entry. It exists because earlier scans could
// quarantine hundreds of ports, which is impractical to release one by one.
func (s *RuntimeStore) ReleaseAllQuarantines(ctx context.Context, assetID, reason, actor string) (int, error) {
	reason = strings.TrimSpace(reason)
	if strings.TrimSpace(assetID) == "" || reason == "" || len(reason) > 1000 || strings.TrimSpace(actor) == "" {
		return 0, fmt.Errorf("%w: 批量解除隔离需要资产和复核原因", ErrInvalidTask)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, "SELECT port FROM port_quarantine WHERE asset_id=? AND status='ACTIVE'", assetID)
	if err != nil {
		return 0, err
	}
	var ports []int
	for rows.Next() {
		var port int
		if err := rows.Scan(&port); err != nil {
			rows.Close()
			return 0, err
		}
		ports = append(ports, port)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, err
	}
	if err := rows.Close(); err != nil {
		return 0, err
	}
	if len(ports) == 0 {
		return 0, nil
	}
	if _, err := tx.ExecContext(ctx, "UPDATE port_quarantine SET status='RELEASED',reviewed_by=?,reviewed_at=? WHERE asset_id=? AND status='ACTIVE'", actor, time.Now().UTC().Format(time.RFC3339Nano), assetID); err != nil {
		return 0, err
	}
	for _, port := range ports {
		var raw string
		if err := tx.QueryRowContext(ctx, "SELECT data FROM asset_services WHERE asset_id=? AND port=?", assetID, port).Scan(&raw); err != nil {
			continue // No inventory row for this port: nothing else to update.
		}
		var service inventory.Service
		if err := json.Unmarshal([]byte(raw), &service); err != nil {
			return 0, err
		}
		service.Quarantined, service.QuarantineReason = false, ""
		data, err := json.Marshal(service)
		if err != nil {
			return 0, err
		}
		if _, err := tx.ExecContext(ctx, "UPDATE asset_services SET data=? WHERE asset_id=? AND port=?", string(data), assetID, port); err != nil {
			return 0, err
		}
	}
	if err := logLocal(ctx, tx, actor, "release_all_quarantines", "asset", assetID, fmt.Sprintf("count=%d; reason=%s", len(ports), reason)); err != nil {
		return 0, err
	}
	return len(ports), tx.Commit()
}
