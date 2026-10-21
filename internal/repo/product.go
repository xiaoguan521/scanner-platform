package repo

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"scanner-platform/internal/findings"
	"scanner-platform/internal/inventory"
	"scanner-platform/internal/portprobe"
	"scanner-platform/internal/taskflow"
)

type ScanPolicy struct {
	CommonPorts         []int             `json:"commonPorts"`
	Exclusions          []portprobe.Range `json:"exclusions"`
	QuarantineThreshold int               `json:"quarantineThreshold"`
	DiscoveryAttempts   int               `json:"discoveryAttempts"`
	FixedThreshold      int               `json:"fixedThreshold"`
}

// SystemSettings contains the small set of control-plane preferences that are
// persisted by the local Server. External notification delivery has its own
// explicitly disabled-by-default settings type in notification_delivery.go.
type SystemSettings struct {
	TimeZone               string `json:"timeZone"`
	SessionDurationMinutes int    `json:"sessionDurationMinutes"`
}

const systemSettingsID = "system-settings"

func defaultSystemSettings() SystemSettings {
	return SystemSettings{TimeZone: "Asia/Shanghai", SessionDurationMinutes: 480}
}

func validateSystemSettings(settings SystemSettings) (SystemSettings, error) {
	settings.TimeZone = strings.TrimSpace(settings.TimeZone)
	if settings.TimeZone != "UTC" && settings.TimeZone != "Asia/Shanghai" && settings.TimeZone != "America/New_York" {
		return settings, fmt.Errorf("%w: 时区必须为 UTC、Asia/Shanghai 或 America/New_York", ErrInvalidTask)
	}
	if settings.SessionDurationMinutes < 30 || settings.SessionDurationMinutes > 1440 {
		return settings, fmt.Errorf("%w: 会话时长必须为 30–1440 分钟", ErrInvalidTask)
	}
	return settings, nil
}

func systemSettingsIn(ctx context.Context, q productQueryer) (SystemSettings, error) {
	settings := defaultSystemSettings()
	var raw string
	err := q.QueryRowContext(ctx, "SELECT data FROM product_settings WHERE id=?", systemSettingsID).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return settings, nil
	}
	if err != nil {
		return settings, err
	}
	if err := json.Unmarshal([]byte(raw), &settings); err != nil {
		return defaultSystemSettings(), fmt.Errorf("decode system settings: %w", err)
	}
	return validateSystemSettings(settings)
}

func (s *RuntimeStore) GetSystemSettings(ctx context.Context) (SystemSettings, error) {
	return systemSettingsIn(ctx, s.db)
}

func (s *RuntimeStore) SaveSystemSettings(ctx context.Context, settings SystemSettings, actor string) (SystemSettings, error) {
	settings, err := validateSystemSettings(settings)
	if err != nil {
		return settings, err
	}
	data, err := json.Marshal(settings)
	if err != nil {
		return settings, fmt.Errorf("encode system settings: %w", err)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return settings, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `INSERT INTO product_settings(id,data) VALUES(?,?) ON CONFLICT(id) DO UPDATE SET data=excluded.data`, systemSettingsID, string(data)); err != nil {
		return settings, err
	}
	if err = logLocal(ctx, tx, actor, "update_system_settings", "settings", systemSettingsID, string(data)); err != nil {
		return settings, err
	}
	if err = tx.Commit(); err != nil {
		return settings, err
	}
	return settings, nil
}

func defaultPolicy() ScanPolicy {
	return ScanPolicy{CommonPorts: portprobe.CommonPorts(), Exclusions: []portprobe.Range{}, QuarantineThreshold: 2, DiscoveryAttempts: 3, FixedThreshold: 1}
}
func (s *RuntimeStore) initProduct(ctx context.Context) error {
	for _, q := range []string{
		`CREATE TABLE IF NOT EXISTS product_settings(id TEXT PRIMARY KEY,data TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS notifications(
			id TEXT PRIMARY KEY,kind TEXT NOT NULL,severity TEXT NOT NULL,
			title TEXT NOT NULL,message TEXT NOT NULL,object_type TEXT NOT NULL,
			object_id TEXT NOT NULL,created_at TEXT NOT NULL,read_at TEXT)`,
		`CREATE INDEX IF NOT EXISTS notifications_read_created ON notifications(read_at,created_at DESC,id DESC)`,
		`CREATE TABLE IF NOT EXISTS notification_deliveries(
			id TEXT PRIMARY KEY,notification_id TEXT NOT NULL UNIQUE REFERENCES notifications(id) ON DELETE CASCADE,
			state TEXT NOT NULL CHECK(state IN ('PENDING','SENDING','FAILED','DELIVERED','DEAD')),
			attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts >= 0),next_attempt_at TEXT NOT NULL,
			last_error TEXT NOT NULL DEFAULT '',delivered_at TEXT,created_at TEXT NOT NULL)`,
		`CREATE INDEX IF NOT EXISTS notification_deliveries_queue ON notification_deliveries(state,next_attempt_at,created_at,id)`,
		`INSERT INTO notification_deliveries(id,notification_id,state,next_attempt_at,created_at)
			SELECT 'delivery-'||n.id,n.id,'PENDING',n.created_at,n.created_at FROM notifications n
			WHERE NOT EXISTS (SELECT 1 FROM notification_deliveries d WHERE d.notification_id=n.id)`,
		`CREATE TABLE IF NOT EXISTS vulnerability_knowledge(id TEXT PRIMARY KEY,data TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS scan_plans(id TEXT PRIMARY KEY,data TEXT NOT NULL,created_by TEXT NOT NULL DEFAULT '',created_at TEXT NOT NULL,updated_at TEXT NOT NULL)`,
		`CREATE INDEX IF NOT EXISTS scan_plans_updated ON scan_plans(updated_at DESC,id DESC)`,
		`CREATE TABLE IF NOT EXISTS task_finding_observations(task_id TEXT NOT NULL REFERENCES scan_tasks(id),finding_id TEXT NOT NULL,data TEXT NOT NULL,PRIMARY KEY(task_id,finding_id))`,
		`INSERT INTO task_finding_observations(task_id,finding_id,data) SELECT task_id,id,data FROM security_findings WHERE 1 ON CONFLICT(task_id,finding_id) DO NOTHING`,
	} {
		if _, err := s.db.ExecContext(ctx, q); err != nil {
			return fmt.Errorf("initialize product model: %w", err)
		}
	}
	return nil
}

type productQueryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func policyIn(ctx context.Context, q productQueryer) (ScanPolicy, error) {
	p := defaultPolicy()
	var raw string
	err := q.QueryRowContext(ctx, "SELECT data FROM product_settings WHERE id='scan-policy'").Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return p, nil
	}
	if err != nil {
		return p, err
	}
	err = json.Unmarshal([]byte(raw), &p)
	if err == nil && p.FixedThreshold == 0 {
		// Catalogs written before the lifecycle setting was introduced inherit
		// the safe one-scan default without changing other frozen policy values.
		p.FixedThreshold = defaultPolicy().FixedThreshold
	}
	return p, err
}
func (s *RuntimeStore) GetScanPolicy(ctx context.Context) (ScanPolicy, error) {
	return policyIn(ctx, s.db)
}
func (s *RuntimeStore) SaveScanPolicy(ctx context.Context, p ScanPolicy, actor string) (ScanPolicy, error) {
	if p.FixedThreshold == 0 {
		// Keep older UI clients wire-compatible while never allowing a zero
		// threshold to make every missing finding immediately fixed.
		p.FixedThreshold = defaultPolicy().FixedThreshold
	}
	if len(p.CommonPorts) < 1 || len(p.CommonPorts) > 65535 || len(p.Exclusions) > 128 || p.DiscoveryAttempts < 1 || p.DiscoveryAttempts > 3 || p.QuarantineThreshold < 1 || p.QuarantineThreshold > 3 || p.FixedThreshold < 1 || p.FixedThreshold > 3 {
		return p, fmt.Errorf("%w: 无效端口策略", ErrInvalidTask)
	}
	seen := map[int]bool{}
	for _, v := range p.CommonPorts {
		if v < 1 || v > 65535 || seen[v] {
			return p, fmt.Errorf("%w: 常见端口必须为不重复的1–65535整数", ErrInvalidTask)
		}
		seen[v] = true
	}
	sort.Ints(p.CommonPorts)
	for _, r := range p.Exclusions {
		if r.Start < 1 || r.End > 65535 || r.Start > r.End {
			return p, fmt.Errorf("%w: 无效排除端口范围", ErrInvalidTask)
		}
	}
	data, _ := json.Marshal(p)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return p, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `INSERT INTO product_settings(id,data) VALUES('scan-policy',?) ON CONFLICT(id) DO UPDATE SET data=excluded.data`, string(data)); err != nil {
		return p, err
	}
	if err = logLocal(ctx, tx, actor, "update_scan_policy", "settings", "scan-policy", string(data)); err != nil {
		return p, err
	}
	return p, tx.Commit()
}
func (s *RuntimeStore) ListKnowledge(ctx context.Context) ([]findings.KnowledgeEntry, error) {
	return listKnowledge(ctx, s.db)
}

type productRows interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

func listKnowledge(ctx context.Context, q productRows) ([]findings.KnowledgeEntry, error) {
	rows, err := q.QueryContext(ctx, "SELECT data FROM vulnerability_knowledge ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []findings.KnowledgeEntry{}
	for rows.Next() {
		var raw string
		var k findings.KnowledgeEntry
		if err = rows.Scan(&raw); err != nil {
			return nil, err
		}
		if err = json.Unmarshal([]byte(raw), &k); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}
func (s *RuntimeStore) SaveKnowledge(ctx context.Context, k findings.KnowledgeEntry, actor string) (findings.KnowledgeEntry, error) {
	k = findings.PrepareKnowledge(k)
	if err := findings.ValidateKnowledge(k); err != nil {
		return k, fmt.Errorf("%w: %v", ErrInvalidTask, err)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return k, err
	}
	defer tx.Rollback()
	data, _ := json.Marshal(k)
	if _, err = tx.ExecContext(ctx, `INSERT INTO vulnerability_knowledge(id,data) VALUES(?,?) ON CONFLICT(id) DO UPDATE SET data=excluded.data`, k.ID, string(data)); err != nil {
		return k, err
	}
	if err = logLocal(ctx, tx, actor, "save_knowledge", "knowledge", k.ID, ""); err != nil {
		return k, err
	}
	return k, tx.Commit()
}
func (s *RuntimeStore) ImportKnowledge(ctx context.Context, items []findings.KnowledgeEntry, actor string) error {
	if len(items) < 1 || len(items) > 5000 {
		return fmt.Errorf("%w: 一次导入1–5000条知识", ErrInvalidTask)
	}
	for i := range items {
		items[i] = findings.PrepareKnowledge(items[i])
		if err := findings.ValidateKnowledge(items[i]); err != nil {
			return fmt.Errorf("%w: %s: %v", ErrInvalidTask, items[i].ID, err)
		}
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, k := range items {
		data, _ := json.Marshal(k)
		if _, err = tx.ExecContext(ctx, `INSERT INTO vulnerability_knowledge(id,data) VALUES(?,?) ON CONFLICT(id) DO UPDATE SET data=excluded.data`, k.ID, string(data)); err != nil {
			return err
		}
	}
	if err = logLocal(ctx, tx, actor, "import_knowledge", "knowledge", "", fmt.Sprint(len(items))); err != nil {
		return err
	}
	return tx.Commit()
}
func (s *RuntimeStore) DeleteKnowledge(ctx context.Context, id, actor string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, "DELETE FROM vulnerability_knowledge WHERE id=?", id); err != nil {
		return err
	}
	if err = logLocal(ctx, tx, actor, "delete_knowledge", "knowledge", id, ""); err != nil {
		return err
	}
	return tx.Commit()
}
func (s *RuntimeStore) ListTaskFindings(ctx context.Context, id string) ([]taskflow.Finding, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT data FROM task_finding_observations WHERE task_id=? ORDER BY finding_id", id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []taskflow.Finding{}
	for rows.Next() {
		var raw string
		var f taskflow.Finding
		if err = rows.Scan(&raw); err != nil {
			return nil, err
		}
		if err = json.Unmarshal([]byte(raw), &f); err != nil {
			return nil, err
		}
		out = append(out, findings.Upgrade(f))
	}
	return out, rows.Err()
}
func (s *RuntimeStore) ReleaseQuarantine(ctx context.Context, assetID string, port int, reason, actor string) error {
	reason = strings.TrimSpace(reason)
	if assetID == "" || port < 1 || port > 65535 || reason == "" || len(reason) > 1000 {
		return fmt.Errorf("%w: 解除隔离需要资产、端口和复核原因", ErrInvalidTask)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, "UPDATE port_quarantine SET status='RELEASED',reviewed_by=?,reviewed_at=? WHERE asset_id=? AND port=? AND status='ACTIVE'", actor, time.Now().UTC().Format(time.RFC3339Nano), assetID, port)
	if err != nil {
		return err
	}
	n, _ := result.RowsAffected()
	if n != 1 {
		return fmt.Errorf("%w: 未找到有效隔离记录", ErrInvalidTask)
	}
	var raw string
	if err = tx.QueryRowContext(ctx, "SELECT data FROM asset_services WHERE asset_id=? AND port=?", assetID, port).Scan(&raw); err == nil {
		var service inventory.Service
		if err = json.Unmarshal([]byte(raw), &service); err != nil {
			return err
		}
		service.Quarantined = false
		service.QuarantineReason = ""
		data, _ := json.Marshal(service)
		if _, err = tx.ExecContext(ctx, "UPDATE asset_services SET data=? WHERE asset_id=? AND port=?", string(data), assetID, port); err != nil {
			return err
		}
	} else if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if err = logLocal(ctx, tx, actor, "release_quarantine", "asset", assetID, fmt.Sprintf("port=%d; reason=%s", port, reason)); err != nil {
		return err
	}
	return tx.Commit()
}
func resolveOwner(ctx context.Context, tx *sql.Tx, target string) (string, targetOwner, error) {
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		host = target
	}
	var id string
	var owner targetOwner
	err = tx.QueryRowContext(ctx, "SELECT id,business_group,owner FROM assets WHERE kind='host' AND (address=? OR resolved_ip=?)", host, host).Scan(&id, &owner.Group, &owner.Owner)
	if errors.Is(err, sql.ErrNoRows) {
		return "", owner, nil
	}
	return id, owner, err
}
func observation(ctx context.Context, tx *sql.Tx, f taskflow.Finding) error {
	data, err := json.Marshal(f)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO task_finding_observations(task_id,finding_id,data) VALUES(?,?,?) ON CONFLICT(task_id,finding_id) DO UPDATE SET data=excluded.data`, f.TaskID, f.ID, string(data))
	return err
}
func compactPortRanges(ports map[int]bool) []portprobe.Range {
	values := make([]int, 0, len(ports))
	for p := range ports {
		values = append(values, p)
	}
	sort.Ints(values)
	out := []portprobe.Range{}
	for _, p := range values {
		if len(out) > 0 && out[len(out)-1].End+1 == p {
			out[len(out)-1].End = p
		} else {
			out = append(out, portprobe.Range{Start: p, End: p})
		}
	}
	return out
}
func recordInventory(ctx context.Context, tx *sql.Tx, task taskflow.Task, report taskflow.Report) error {
	if task.AssetID == "" {
		return nil
	}
	now := time.Now().UTC()
	services := report.ServiceResults
	if len(services) == 0 {
		for _, p := range report.PortProbeResults {
			services = append(services, inventory.Service{Port: p.Port, Kind: "OTHER", Protocol: "tcp", State: "open"})
		}
	}
	for _, service := range services {
		service.FirstSeen, service.LastSeen = now, now
		var raw string
		if err := tx.QueryRowContext(ctx, "SELECT data FROM asset_services WHERE asset_id=? AND port=?", task.AssetID, service.Port).Scan(&raw); err == nil {
			var old inventory.Service
			if json.Unmarshal([]byte(raw), &old) == nil && !old.FirstSeen.IsZero() {
				service.FirstSeen = old.FirstSeen
			}
		}
		if service.Protocol == "" {
			service.Protocol = "tcp"
		}
		if service.State == "" {
			service.State = "open"
		}
		data, _ := json.Marshal(service)
		if _, err := tx.ExecContext(ctx, `INSERT INTO asset_services(asset_id,port,data) VALUES(?,?,?) ON CONFLICT(asset_id,port) DO UPDATE SET data=excluded.data`, task.AssetID, service.Port, string(data)); err != nil {
			return err
		}
		if service.Quarantined {
			reason := service.QuarantineReason
			if reason == "" {
				reason = "受限服务识别出现疑似转发特征，等待人工复核"
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO port_quarantine(asset_id,port,reason,detected_at,status) VALUES(?,?,?,?,'ACTIVE') ON CONFLICT(asset_id,port) DO UPDATE SET reason=excluded.reason,detected_at=excluded.detected_at,status='ACTIVE',reviewed_by=NULL,reviewed_at=NULL`, task.AssetID, service.Port, reason, now.Format(time.RFC3339Nano)); err != nil {
				return err
			}
			if err := logLocal(ctx, tx, report.WorkerID, "quarantine_port", "asset", task.AssetID, fmt.Sprintf("port=%d; %s", service.Port, reason)); err != nil {
				return err
			}
		}
		if _, err := tx.ExecContext(ctx, "DELETE FROM asset_login_entries WHERE asset_id=? AND json_extract(data,'$.port')=?", task.AssetID, service.Port); err != nil {
			return err
		}
		for _, entry := range service.LoginEntries {
			data, _ := json.Marshal(entry)
			key := entry.Type + ":" + strconv.Itoa(entry.Port) + ":" + entry.URL
			if _, err := tx.ExecContext(ctx, `INSERT INTO asset_login_entries(asset_id,entry_key,data) VALUES(?,?,?) ON CONFLICT(asset_id,entry_key) DO UPDATE SET data=excluded.data`, task.AssetID, key, string(data)); err != nil {
				return err
			}
		}
	}

	// Close only previously observed services which were actually probed in this run.
	// Excluded and quarantined ports are absent from this fixed list and stay untouched.
	probed := map[int]bool{}
	opened := map[int]bool{}
	for _, p := range task.PortProbePorts {
		probed[p] = true
	}
	for _, p := range report.PortProbeResults {
		opened[p.Port] = true
	}
	rows, err := tx.QueryContext(ctx, "SELECT port,data FROM asset_services WHERE asset_id=?", task.AssetID)
	if err != nil {
		return err
	}
	closed := []inventory.Service{}
	for rows.Next() {
		var p int
		var raw string
		if err = rows.Scan(&p, &raw); err != nil {
			rows.Close()
			return err
		}
		if probed[p] && !opened[p] {
			var service inventory.Service
			if err = json.Unmarshal([]byte(raw), &service); err != nil {
				rows.Close()
				return err
			}
			service.State = "closed"
			service.LastSeen = now
			service.LoginEntries = nil
			closed = append(closed, service)
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, service := range closed {
		data, _ := json.Marshal(service)
		if _, err = tx.ExecContext(ctx, "UPDATE asset_services SET data=? WHERE asset_id=? AND port=?", string(data), task.AssetID, service.Port); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, "DELETE FROM asset_login_entries WHERE asset_id=? AND json_extract(data,'$.port')=?", task.AssetID, service.Port); err != nil {
			return err
		}
	}
	profile := report.AssetProfile
	var raw string
	if err := tx.QueryRowContext(ctx, "SELECT data FROM asset_profiles WHERE asset_id=?", task.AssetID).Scan(&raw); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	fields := map[string]any{}
	if raw != "" {
		if err := json.Unmarshal([]byte(raw), &fields); err != nil {
			return err
		}
	}
	data, _ := json.Marshal(profile)
	updates := map[string]any{}
	_ = json.Unmarshal(data, &updates)
	for k, v := range updates {
		if text, ok := v.(string); ok && text != "" {
			fields[k] = text
		}
	}
	data, _ = json.Marshal(fields)
	if _, err := tx.ExecContext(ctx, `INSERT INTO asset_profiles(asset_id,data) VALUES(?,?) ON CONFLICT(asset_id) DO UPDATE SET data=excluded.data`, task.AssetID, string(data)); err != nil {
		return err
	}
	if len(report.PortProbeResults) > 0 {
		if _, err := tx.ExecContext(ctx, `INSERT INTO asset_reachability(asset_id,status,checked_at) VALUES(?,'REACHABLE',?) ON CONFLICT(asset_id) DO UPDATE SET status='REACHABLE',checked_at=excluded.checked_at`, task.AssetID, now.Format(time.RFC3339Nano)); err != nil {
			return err
		}
	}
	return nil
}

func countUniqueExclusions(ranges []portprobe.Range) int {
	ports := map[int]bool{}
	for _, r := range ranges {
		if r.Start < 1 || r.End > 65535 || r.Start > r.End {
			continue
		}
		for p := r.Start; p <= r.End; p++ {
			ports[p] = true
		}
	}
	return len(ports)
}
