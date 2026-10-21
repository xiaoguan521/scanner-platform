package assets

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"unicode/utf8"

	"scanner-platform/internal/inventory"
)

type profileData struct {
	Name            string                     `json:"name,omitempty"`
	IsCore          bool                       `json:"isCore"`
	Department      string                     `json:"department,omitempty"`
	Phone           string                     `json:"phone,omitempty"`
	MAC             string                     `json:"mac,omitempty"`
	OSName          string                     `json:"osName,omitempty"`
	OSFamily        string                     `json:"osFamily,omitempty"`
	DeviceType      string                     `json:"deviceType,omitempty"`
	DeviceSubtype   string                     `json:"deviceSubtype,omitempty"`
	Vendor          string                     `json:"vendor,omitempty"`
	Model           string                     `json:"model,omitempty"`
	RuntimeServices []inventory.RuntimeService `json:"runtimeServices,omitempty"`
}

func profileBytes(value any) ([]byte, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	var profile profileData
	if err = json.Unmarshal(data, &profile); err != nil {
		return nil, err
	}
	return json.Marshal(profile)
}
func validProfile(value any) bool {
	data, err := profileBytes(value)
	if err != nil {
		return false
	}
	var fields map[string]any
	if json.Unmarshal(data, &fields) != nil {
		return false
	}
	for _, v := range fields {
		if text, ok := v.(string); ok && (len(text) > 500 || !utf8.ValidString(text) || strings.ContainsRune(text, 0)) {
			return false
		}
	}
	var profile inventory.Profile
	if err := json.Unmarshal(data, &profile); err != nil || !inventory.ValidateRuntimeServices(profile.RuntimeServices) {
		return false
	}
	return true
}
func saveProfile(ctx context.Context, tx *sql.Tx, id string, value any) error {
	data, err := profileBytes(value)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO asset_profiles(asset_id,data) VALUES(?,?) ON CONFLICT(asset_id) DO UPDATE SET data=excluded.data`, id, string(data))
	return err
}
func applyProfile(a *Asset, value any) {
	data, err := profileBytes(value)
	if err == nil {
		_ = json.Unmarshal(data, a)
	}
}
func loadProfiles(ctx context.Context, q SnapshotQuerier, items []Asset) error {
	indices := map[string]int{}
	for i := range items {
		indices[items[i].ID] = i
		items[i].Services = []inventory.Service{}
		items[i].LoginEntries = []inventory.LoginEntry{}
	}
	for _, table := range []string{"asset_profiles", "asset_services", "asset_login_entries"} {
		rows, err := q.QueryContext(ctx, "SELECT asset_id,data FROM "+table+" ORDER BY asset_id")
		if err != nil {
			return err
		}
		for rows.Next() {
			var id, data string
			if err = rows.Scan(&id, &data); err != nil {
				rows.Close()
				return err
			}
			i, ok := indices[id]
			if !ok {
				continue
			}
			switch table {
			case "asset_profiles":
				err = json.Unmarshal([]byte(data), &items[i])
			case "asset_services":
				var service inventory.Service
				err = json.Unmarshal([]byte(data), &service)
				if err == nil {
					for _, p := range items[i].SkippedPorts {
						service.Excluded = service.Excluded || p == service.Port
					}
					for _, p := range items[i].QuarantinedPorts {
						service.Quarantined = service.Quarantined || p == service.Port
					}
					items[i].Services = append(items[i].Services, service)
				}
			case "asset_login_entries":
				var entry inventory.LoginEntry
				err = json.Unmarshal([]byte(data), &entry)
				if err == nil {
					items[i].LoginEntries = append(items[i].LoginEntries, entry)
				}
			}
			if err != nil {
				rows.Close()
				return fmt.Errorf("decode asset profile: %w", err)
			}
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
	}
	return nil
}
