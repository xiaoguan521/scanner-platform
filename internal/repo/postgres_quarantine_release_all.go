package repo

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"scanner-platform/internal/inventory"
)

// ReleaseAllQuarantines is the PostgreSQL form of RuntimeStore.ReleaseAllQuarantines.
func (s *PostgresRuntimeStore) ReleaseAllQuarantines(ctx context.Context, assetID, reason, actor string) (int, error) {
	reason = strings.TrimSpace(reason)
	if strings.TrimSpace(assetID) == "" || reason == "" || len(reason) > 1000 || strings.TrimSpace(actor) == "" {
		return 0, fmt.Errorf("%w: 批量解除隔离需要资产和复核原因", ErrInvalidTask)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin postgres quarantine release: %w", err)
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, "SELECT port FROM port_quarantine WHERE asset_id=$1 AND status='ACTIVE'", assetID)
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
	if _, err := tx.ExecContext(ctx, "UPDATE port_quarantine SET status='RELEASED',reviewed_by=$1,reviewed_at=$2 WHERE asset_id=$3 AND status='ACTIVE'", actor, time.Now().UTC(), assetID); err != nil {
		return 0, err
	}
	for _, port := range ports {
		var raw string
		if err := tx.QueryRowContext(ctx, "SELECT data FROM asset_services WHERE asset_id=$1 AND port=$2", assetID, port).Scan(&raw); err != nil {
			continue
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
		if _, err := tx.ExecContext(ctx, "UPDATE asset_services SET data=$1 WHERE asset_id=$2 AND port=$3", string(data), assetID, port); err != nil {
			return 0, err
		}
	}
	if err := s.postgresAuditTx(ctx, tx, actor, "release_all_quarantines", "asset", assetID, fmt.Sprintf("count=%d; reason=%s", len(ports), reason)); err != nil {
		return 0, err
	}
	return len(ports), tx.Commit()
}
