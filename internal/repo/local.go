package repo

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"scanner-platform/internal/inventory"
	"scanner-platform/internal/portprobe"
	"scanner-platform/internal/scheduler"
	"scanner-platform/internal/taskflow"
)

var ErrInvalidTask = errors.New("invalid task input")

func randomLocalID() string { return rand.Text() }

type targetOwner struct {
	Group string `json:"group"`
	Owner string `json:"owner"`
}
type taskDetails struct {
	EffectiveExclusions []portprobe.Range            `json:"effectiveExclusions,omitempty"`
	AssetProfile        inventory.Profile            `json:"assetProfile,omitempty"`
	Input               taskflow.TaskInput           `json:"input"`
	Archived            bool                         `json:"archived,omitempty"`
	Skipped             []string                     `json:"skipped"`
	Owners              map[string]targetOwner       `json:"owners"`
	ProbePorts          []int                        `json:"probePorts,omitempty"`
	ProbeResults        []taskflow.PortProbeResult   `json:"probeResults,omitempty"`
	VulnPorts           []int                        `json:"vulnerabilityPorts,omitempty"`
	CustomRules         [][]byte                     `json:"customRules,omitempty"`
	Services            []taskflow.ServiceResult     `json:"services,omitempty"`
	SystemStatus        string                       `json:"systemScanStatus,omitempty"`
	ApplicationStatus   string                       `json:"applicationScanStatus,omitempty"`
	ApplicationResults  []taskflow.ApplicationResult `json:"applicationResults,omitempty"`
	FixedThreshold      int                          `json:"fixedThreshold"`
	Deadline            string                       `json:"deadline"`
	RuleVersion         string                       `json:"ruleVersion"`
	Error               string                       `json:"error,omitempty"`
}

func (s *RuntimeStore) initLocal(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx, "PRAGMA table_info(scan_tasks)")
	if err != nil {
		return err
	}
	foundDetails, foundPinned, foundLease := false, false, false
	for rows.Next() {
		var cid, nn, pk int
		var name, kind string
		var def any
		if err := rows.Scan(&cid, &name, &kind, &nn, &def, &pk); err != nil {
			rows.Close()
			return err
		}
		foundDetails = foundDetails || name == "details"
		foundPinned = foundPinned || name == "pinned_rule_version"
		foundLease = foundLease || name == "lease_expires_at"
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	if !foundDetails {
		if _, err := s.db.ExecContext(ctx, `ALTER TABLE scan_tasks ADD COLUMN details TEXT NOT NULL DEFAULT '{}'`); err != nil {
			return err
		}
	}
	if !foundPinned {
		if _, err := s.db.ExecContext(ctx, `ALTER TABLE scan_tasks ADD COLUMN pinned_rule_version TEXT NOT NULL DEFAULT ''`); err != nil {
			return err
		}
	}
	if !foundLease {
		if _, err := s.db.ExecContext(ctx, `ALTER TABLE scan_tasks ADD COLUMN lease_expires_at TEXT`); err != nil {
			return err
		}
	}
	for _, q := range []string{
		`CREATE TABLE IF NOT EXISTS audit_logs(id TEXT PRIMARY KEY,actor TEXT NOT NULL,action TEXT NOT NULL,object_type TEXT,object_id TEXT,detail TEXT,created_at TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS task_schedules(id TEXT PRIMARY KEY,data TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS local_nodes(id TEXT PRIMARY KEY,data TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS scan_task_progress(
			task_id TEXT PRIMARY KEY REFERENCES scan_tasks(id) ON DELETE CASCADE,
			worker_id TEXT NOT NULL, phase TEXT NOT NULL, completed INTEGER NOT NULL,
			total INTEGER NOT NULL, updated_at TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS local_rule_bundles(version TEXT PRIMARY KEY,data TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS rule_jobs(id TEXT PRIMARY KEY,status TEXT NOT NULL,data TEXT NOT NULL,bundle BLOB,created_at TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS custom_rules(id TEXT PRIMARY KEY,data TEXT NOT NULL,enabled INTEGER NOT NULL DEFAULT 1,created_at TEXT NOT NULL,updated_at TEXT NOT NULL)`,
	} {
		if _, err := s.db.ExecContext(ctx, q); err != nil {
			return err
		}
	}
	return nil
}

func canonicalTarget(raw string) (string, int, string, error) {
	host, p, err := net.SplitHostPort(strings.TrimSpace(raw))
	if err != nil {
		return "", 0, "", ErrInvalidTask
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || ip.Zone() != "" || ip.IsUnspecified() || ip.IsMulticast() {
		return "", 0, "", ErrInvalidTask
	}
	port, err := strconv.Atoi(p)
	if err != nil || port < 1 || port > 65535 {
		return "", 0, "", ErrInvalidTask
	}
	address := ip.Unmap().String()
	return address, port, net.JoinHostPort(address, strconv.Itoa(port)), nil
}

func resolveTargets(ctx context.Context, tx *sql.Tx, in taskflow.TaskInput) ([]string, taskDetails, error) {
	if in.TimeWindows == nil {
		in.TimeWindows = []scheduler.Window{}
	}
	detail := taskDetails{Input: in, Skipped: []string{}, Owners: map[string]targetOwner{}}
	if scheduler.ValidateWindows(in.TimeWindows) != nil {
		return nil, detail, ErrInvalidTask
	}
	if in.Synthetic {
		if in.Engine != "" && in.Engine != "synthetic" || in.InputPath != "" || in.InputKind != "" || in.Scheme != "" || in.AssetID != "" || !emptyPortProbeConfig(in.PortProbe) {
			return nil, detail, ErrInvalidTask
		}
	} else if in.Engine == "trivy" {
		if len(in.Targets) != 0 || in.Scheme != "" || in.AssetID != "" || !emptyPortProbeConfig(in.PortProbe) || !filepath.IsLocal(in.InputPath) || strings.ContainsAny(in.InputPath, "\\:\x00") || len(in.InputPath) > 240 || (in.InputKind != "filesystem" && in.InputKind != "image-archive" && in.InputKind != "rootfs" && in.InputKind != "artifact") {
			return nil, detail, fmt.Errorf("%w: Trivy requires a relative Worker input path and filesystem/artifact/image-archive/rootfs kind", ErrInvalidTask)
		}
		return []string{in.InputPath}, detail, nil
	} else if in.Engine == "port-probe" {
		return resolvePortProbe(ctx, tx, in, detail)
	} else if in.Engine == "auto" {
		return resolveAutoScan(ctx, tx, in, detail)
	} else if (in.Engine != "nuclei" && in.Engine != "zap") || (in.Scheme != "http" && in.Scheme != "https") || in.InputPath != "" || in.InputKind != "" {
		return nil, detail, ErrInvalidTask
	}
	if in.AssetID != "" || !emptyPortProbeConfig(in.PortProbe) {
		return nil, detail, ErrInvalidTask
	}
	if len(in.Targets) == 0 || len(in.Targets) > 100 {
		return nil, detail, ErrInvalidTask
	}
	policy, err := policyIn(ctx, tx)
	if err != nil {
		return nil, detail, err
	}
	targets := []string{}
	canonical := []string{}
	seen := map[string]bool{}
	for _, raw := range in.Targets {
		address, port, target, err := canonicalTarget(raw)
		if err != nil || seen[target] {
			return nil, detail, ErrInvalidTask
		}
		seen[target] = true
		var id string
		var owner targetOwner
		err = tx.QueryRowContext(ctx, `SELECT a.id,a.business_group,a.owner FROM assets a JOIN asset_port_requests p ON p.asset_id=a.id
   WHERE a.kind='host' AND a.address=? AND p.port=?`, address, port).Scan(&id, &owner.Group, &owner.Owner)
		if errors.Is(err, sql.ErrNoRows) {
			return nil, detail, fmt.Errorf("%w: target must be explicitly registered", ErrInvalidTask)
		}
		if err != nil {
			return nil, detail, err
		}
		var skip int
		err = tx.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM asset_ports WHERE asset_id=? AND port=? AND kind='EXCLUDED_PROXY')+
   (SELECT count(*) FROM port_quarantine WHERE asset_id=? AND port=? AND status='ACTIVE')`, id, port, id, port).Scan(&skip)
		if err != nil {
			return nil, detail, err
		}
		for _, r := range policy.Exclusions {
			if port >= r.Start && port <= r.End {
				skip++
			}
		}
		canonical = append(canonical, target)
		if skip > 0 {
			detail.Skipped = append(detail.Skipped, target)
		} else {
			if !in.Synthetic {
				var approved int
				if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM asset_port_reviews r JOIN asset_ports p
   ON p.asset_id=r.asset_id AND p.port=r.port WHERE r.asset_id=? AND r.port=? AND r.status='APPROVED'
   AND p.kind IN ('WEB','NON_WEB')`, id, port).Scan(&approved); err != nil {
					return nil, detail, err
				}
				if approved != 1 {
					return nil, detail, fmt.Errorf("%w: target port must be approved before vulnerability scanning", ErrInvalidTask)
				}
			}
			targets = append(targets, target)
			detail.Owners[target] = owner
		}
	}
	if len(targets) == 0 {
		return nil, detail, fmt.Errorf("%w: all ports are skipped", ErrInvalidTask)
	}
	detail.Input.Targets = canonical
	return targets, detail, nil
}

func emptyPortProbeConfig(config portprobe.Config) bool {
	return config.Preset == "" && len(config.Ranges) == 0 && len(config.Exclusions) == 0 && !config.OpsApproved && config.Intensity == "" && !config.FullConfirmed && len(config.CommonPorts) == 0 && len(config.RegisteredPorts) == 0
}

func resolvePortProbe(ctx context.Context, tx *sql.Tx, in taskflow.TaskInput, detail taskDetails) ([]string, taskDetails, error) {
	if in.AssetID == "" || in.Scheme != "" || in.InputPath != "" || in.InputKind != "" || !in.PortProbe.OpsApproved || (len(in.Targets) != 0 && len(in.Targets) != 1) {
		return nil, detail, ErrInvalidTask
	}
	if in.PortProbe.Preset == "" {
		in.PortProbe.Preset = portprobe.PresetCommon
	}
	policy, err := policyIn(ctx, tx)
	if err != nil {
		return nil, detail, err
	}
	requestedConfig := in.PortProbe
	in.PortProbe.CommonPorts = policy.CommonPorts
	in.PortProbe.IdentificationMaxAttempts = policy.DiscoveryAttempts
	in.PortProbe.QuarantineThreshold = policy.QuarantineThreshold
	in.PortProbe.RegisteredPorts = nil
	registered, err := tx.QueryContext(ctx, "SELECT port FROM asset_ports WHERE asset_id=? AND kind!='EXCLUDED_PROXY' UNION SELECT port FROM asset_services WHERE asset_id=?", in.AssetID, in.AssetID)
	if err != nil {
		return nil, detail, err
	}
	for registered.Next() {
		var port int
		if err = registered.Scan(&port); err != nil {
			registered.Close()
			return nil, detail, err
		}
		in.PortProbe.RegisteredPorts = append(in.PortProbe.RegisteredPorts, port)
	}
	err = registered.Err()
	registered.Close()
	if err != nil {
		return nil, detail, err
	}
	ports, err := portprobe.SelectPorts(in.PortProbe)
	if in.PortProbe.Intensity == "" && (in.PortProbe.Preset == portprobe.PresetFull || len(ports)+countUniqueExclusions(in.PortProbe.Exclusions) == 65535) {
		in.PortProbe.Intensity = portprobe.IntensityGentle
	}
	if err != nil {
		return nil, detail, fmt.Errorf("%w: %v", ErrInvalidTask, err)
	}
	var address string
	var kind string
	if err := tx.QueryRowContext(ctx, "SELECT address,kind FROM assets WHERE id=?", in.AssetID).Scan(&address, &kind); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, detail, fmt.Errorf("%w: port probe requires a registered asset", ErrInvalidTask)
		}
		return nil, detail, err
	}
	ip, err := netip.ParseAddr(address)
	if err != nil || kind != "host" || ip.Zone() != "" || ip.IsUnspecified() || ip.IsMulticast() {
		return nil, detail, ErrInvalidTask
	}
	address = ip.Unmap().String()
	if len(in.Targets) == 1 && in.Targets[0] != address {
		return nil, detail, ErrInvalidTask
	}
	rows, err := tx.QueryContext(ctx, `SELECT port FROM asset_ports WHERE asset_id=? AND kind='EXCLUDED_PROXY'
UNION SELECT port FROM port_quarantine WHERE asset_id=? AND status='ACTIVE'`, in.AssetID, in.AssetID)
	if err != nil {
		return nil, detail, err
	}
	selected := make(map[int]bool, len(ports))
	for _, port := range ports {
		selected[port] = true
	}
	automaticExclusions := make(map[int]bool)
	for _, r := range policy.Exclusions {
		for p := r.Start; p <= r.End; p++ {
			if selected[p] {
				automaticExclusions[p] = true
			}
		}
	}
	for rows.Next() {
		var port int
		if err := rows.Scan(&port); err != nil {
			rows.Close()
			return nil, detail, err
		}
		if selected[port] {
			automaticExclusions[port] = true

		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, detail, err
	}
	if err := rows.Close(); err != nil {
		return nil, detail, err
	}
	for p := range automaticExclusions {
		detail.Skipped = append(detail.Skipped, net.JoinHostPort(address, strconv.Itoa(p)))
	}
	effectivePorts := make([]int, 0, len(ports)-len(automaticExclusions))
	for _, port := range ports {
		if !automaticExclusions[port] {
			effectivePorts = append(effectivePorts, port)
		}
	}
	if len(effectivePorts) == 0 {
		return nil, detail, fmt.Errorf("%w: all ports are excluded", ErrInvalidTask)
	}
	// Keep the requested plan for display and persist the exact resolved list
	// separately so the Worker cannot expand or reinterpret the configured ranges.
	allExcluded := make(map[int]bool, len(automaticExclusions))
	for p := range automaticExclusions {
		allExcluded[p] = true
	}
	for _, r := range requestedConfig.Exclusions {
		for p := r.Start; p <= r.End; p++ {
			allExcluded[p] = true
		}
	}
	detail.EffectiveExclusions = compactPortRanges(allExcluded)
	detail.ProbePorts = effectivePorts
	in.Targets = []string{address}
	detail.Input = in
	return []string{address}, detail, nil
}

func resolveAutoScan(ctx context.Context, tx *sql.Tx, in taskflow.TaskInput, detail taskDetails) ([]string, taskDetails, error) {
	if in.AssetID == "" || in.InputPath != "" || in.InputKind != "" || in.Scheme != "" || len(in.Targets) > 1 || len(in.CustomRuleIDs) > 20 {
		return nil, detail, ErrInvalidTask
	}
	targets, resolved, err := resolvePortProbe(ctx, tx, in, detail)
	if err != nil {
		return nil, resolved, err
	}
	// The caller explicitly confirmed authorization for this single registered
	// IP and the selected bounded TCP range. Only open ports from this exact list
	// can proceed to the safe HTTP check.
	resolved.VulnPorts = append([]int{}, resolved.ProbePorts...)
	return targets, resolved, nil
}

func logLocal(ctx context.Context, tx *sql.Tx, actor, action, kind, id, detail string) error {
	// Keep compatibility with stores created before runtime audit initialization.
	var exists int
	if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='audit_logs'").Scan(&exists); err != nil {
		return err
	}
	if exists == 0 {
		return nil
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO audit_logs(id,actor,action,object_type,object_id,detail,created_at) VALUES(?,?,?,?,?,?,?)`,
		"audit-"+randomLocalID(), actor, action, kind, id, detail, time.Now().UTC().Format(time.RFC3339Nano))
	return err
}

func createLocalTask(ctx context.Context, tx *sql.Tx, in taskflow.TaskInput, actor, id string, now time.Time) (taskflow.Task, error) {
	targets, detail, err := resolveTargets(ctx, tx, in)
	if err != nil {
		return taskflow.Task{}, err
	}
	detail.CustomRules, err = customTemplates(ctx, tx, detail.Input)
	if err != nil {
		return taskflow.Task{}, fmt.Errorf("load custom scan rules: %w", err)
	}
	policy, err := policyIn(ctx, tx)
	if err != nil {
		return taskflow.Task{}, err
	}
	detail.FixedThreshold = policy.FixedThreshold
	if detail.FixedThreshold < 1 {
		detail.FixedThreshold = defaultPolicy().FixedThreshold
	}
	status := "PENDING"
	_, allowed, err := scheduler.AllowedUntil(in.TimeWindows, now)
	if err != nil {
		return taskflow.Task{}, err
	}
	if !allowed {
		status = "WAITING_WINDOW"
	}
	// The catalog is a copy reported by Updater; no rule directory is written by Server.
	var current string
	err = tx.QueryRowContext(ctx, `SELECT version FROM local_rule_bundles WHERE json_extract(data,'$.isCurrent')=1 LIMIT 1`).Scan(&current)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return taskflow.Task{}, err
	}
	detail.RuleVersion = current
	if in.Engine == "zap" {
		detail.RuleVersion = ""
	} // ZAP passive rules ship with the pinned binary.
	if !in.Synthetic && in.Engine != "zap" && in.Engine != "port-probe" {
		if current == "" {
			return taskflow.Task{}, fmt.Errorf("%w: 请先导入并激活包含所选引擎的规则包", ErrInvalidTask)
		}
		var catalog string
		if err := tx.QueryRowContext(ctx, "SELECT data FROM local_rule_bundles WHERE version=?", current).Scan(&catalog); err != nil {
			return taskflow.Task{}, err
		}
		var bundle struct {
			Engines   []string `json:"engines"`
			Integrity bool     `json:"integrityVerified"`
		}
		if json.Unmarshal([]byte(catalog), &bundle) != nil || !bundle.Integrity {
			return taskflow.Task{}, ErrInvalidTask
		}
		requiredEngines := []string{in.Engine}
		if in.Engine == "auto" {
			requiredEngines = []string{"nuclei", "trivy"}
		}
		supported := make(map[string]bool, len(bundle.Engines))
		for _, engine := range bundle.Engines {
			supported[engine] = true
		}
		for _, requiredEngine := range requiredEngines {
			if !supported[requiredEngine] {
				return taskflow.Task{}, fmt.Errorf("%w: 当前规则包缺少自动综合扫描所需的 %s 引擎或漏洞库", ErrInvalidTask, requiredEngine)
			}
		}
	}
	data, _ := json.Marshal(detail)
	encoded, _ := json.Marshal(targets)
	_, err = tx.ExecContext(ctx, `INSERT INTO scan_tasks(id,status,created_at,targets,details) VALUES(?,?,?,?,?)`, id, status, now.UTC().Format(time.RFC3339Nano), string(encoded), string(data))
	if err != nil {
		return taskflow.Task{}, err
	}
	if err := logLocal(ctx, tx, actor, "create_task", "task", id, string(data)); err != nil {
		return taskflow.Task{}, err
	}
	return readRuntimeTask(tx.QueryRowContext(ctx, `SELECT `+taskColumns+` FROM scan_tasks WHERE id=?`, id))
}

func (s *RuntimeStore) CreateLocalTask(ctx context.Context, in taskflow.TaskInput, actor string) (taskflow.Task, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return taskflow.Task{}, err
	}
	defer tx.Rollback()
	task, err := createLocalTask(ctx, tx, in, actor, "task-"+randomLocalID(), time.Now())
	if err != nil {
		return taskflow.Task{}, err
	}
	if err := tx.Commit(); err != nil {
		return taskflow.Task{}, err
	}
	return task, nil
}

func (s *RuntimeStore) CancelTask(ctx context.Context, id, actor string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE scan_tasks SET status='CANCELED',finished_at=? WHERE id=? AND status IN ('PENDING','WAITING_WINDOW','PAUSED_WINDOW','RUNNING')`, time.Now().UTC().Format(time.RFC3339Nano), id)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrTaskConflict
	}
	if err := logLocal(ctx, tx, actor, "cancel_task", "task", id, ""); err != nil {
		return err
	}
	return tx.Commit()
}

func terminalTaskStatus(status string) bool {
	return status == "COMPLETED" || status == "FAILED" || status == "CANCELED"
}

func (s *RuntimeStore) SetTaskArchived(ctx context.Context, id, actor string, archived bool) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var status, raw string
	if err := tx.QueryRowContext(ctx, `SELECT status,details FROM scan_tasks WHERE id=?`, id).Scan(&status, &raw); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrTaskNotFound
		}
		return err
	}
	if !terminalTaskStatus(status) {
		return ErrTaskNotTerminal
	}
	var detail taskDetails
	if err := json.Unmarshal([]byte(raw), &detail); err != nil {
		return fmt.Errorf("decode task details: %w", err)
	}
	if detail.Archived == archived {
		return tx.Commit()
	}
	detail.Archived = archived
	encoded, err := json.Marshal(detail)
	if err != nil {
		return fmt.Errorf("encode task details: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE scan_tasks SET details=? WHERE id=?`, string(encoded), id); err != nil {
		return err
	}
	action, description := "archive_task", "扫描任务已归档"
	if !archived {
		action, description = "restore_task", "扫描任务已从归档恢复"
	}
	if err := logLocal(ctx, tx, actor, action, "task", id, description); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *RuntimeStore) DeleteRuntimeTask(ctx context.Context, id, actor string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var status string
	if err := tx.QueryRowContext(ctx, `SELECT status FROM scan_tasks WHERE id=?`, id).Scan(&status); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrTaskNotFound
		}
		return err
	}
	if !terminalTaskStatus(status) {
		return ErrTaskNotTerminal
	}
	var findingCount int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM (
		SELECT task_id,finding_id FROM task_finding_observations WHERE task_id=?
		UNION
		SELECT task_id,id FROM security_findings WHERE task_id=?
	)`, id, id).Scan(&findingCount); err != nil {
		return err
	}
	if findingCount > 0 {
		return ErrTaskHasFindings
	}
	if err := clearDeletedTaskScheduleReference(ctx, tx, id); err != nil {
		return err
	}
	if err := logLocal(ctx, tx, actor, "delete_task", "task", id, "终态任务无关联发现项，已彻底删除任务记录"); err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `DELETE FROM scan_tasks WHERE id=? AND status IN ('COMPLETED','FAILED','CANCELED')`, id)
	if err != nil {
		return err
	}
	if count, err := result.RowsAffected(); err != nil {
		return err
	} else if count != 1 {
		return ErrTaskConflict
	}
	return tx.Commit()
}

func clearDeletedTaskScheduleReference(ctx context.Context, tx *sql.Tx, taskID string) error {
	rows, err := tx.QueryContext(ctx, `SELECT id,data FROM task_schedules`)
	if err != nil {
		return err
	}
	type scheduleRow struct{ id, data string }
	items := []scheduleRow{}
	for rows.Next() {
		var item scheduleRow
		if err := rows.Scan(&item.id, &item.data); err != nil {
			rows.Close()
			return err
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, item := range items {
		var schedule taskflow.Schedule
		if err := json.Unmarshal([]byte(item.data), &schedule); err != nil {
			return fmt.Errorf("decode schedule %s: %w", item.id, err)
		}
		if schedule.LastTaskID != taskID {
			continue
		}
		schedule.LastTaskID = ""
		encoded, err := json.Marshal(schedule)
		if err != nil {
			return fmt.Errorf("encode schedule %s: %w", item.id, err)
		}
		if _, err := tx.ExecContext(ctx, `UPDATE task_schedules SET data=? WHERE id=?`, string(encoded), item.id); err != nil {
			return err
		}
	}
	return nil
}

func (s *RuntimeStore) UpdateFinding(ctx context.Context, id, status, actor string) (taskflow.Finding, error) {
	if status != "IN_PROGRESS" && status != "FALSE_POSITIVE" && status != "OPEN" {
		return taskflow.Finding{}, ErrInvalidTask
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return taskflow.Finding{}, err
	}
	defer tx.Rollback()
	var data string
	var finding taskflow.Finding
	if err := tx.QueryRowContext(ctx, "SELECT data FROM security_findings WHERE id=?", id).Scan(&data); err != nil {
		return finding, ErrTaskConflict
	}
	if err := json.Unmarshal([]byte(data), &finding); err != nil {
		return finding, err
	}
	finding.Status = status
	encoded, _ := json.Marshal(finding)
	if _, err := tx.ExecContext(ctx, "UPDATE security_findings SET data=? WHERE id=?", string(encoded), id); err != nil {
		return finding, err
	}
	if err := logLocal(ctx, tx, actor, "update_finding", "finding", id, status); err != nil {
		return finding, err
	}
	if err := tx.Commit(); err != nil {
		return finding, err
	}
	return finding, nil
}

func (s *RuntimeStore) SaveSchedule(ctx context.Context, in taskflow.Schedule, actor string) (taskflow.Schedule, error) {
	if in.Engine == "port-probe" {
		return in, ErrInvalidTask
	}
	due, err := time.Parse(time.RFC3339, in.NextRun)
	if err != nil || !due.After(time.Now()) || due.After(time.Now().Add(366*24*time.Hour)) || len(strings.TrimSpace(in.Name)) == 0 || len(in.Name) > 100 || in.IntervalMinutes < 0 || in.IntervalMinutes > 525600 {
		return in, ErrInvalidTask
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return in, err
	}
	defer tx.Rollback()
	_, detail, err := resolveTargets(ctx, tx, in.TaskInput)
	if err != nil {
		return in, err
	}
	in.TaskInput = detail.Input
	in.ID = "schedule-" + randomLocalID()
	in.Enabled = true
	in.CreatedBy = actor
	in.LastError = ""
	in.LastTaskID = ""
	in.NextRun = due.UTC().Format(time.RFC3339Nano)
	data, _ := json.Marshal(in)
	if _, err := tx.ExecContext(ctx, "INSERT INTO task_schedules(id,data) VALUES(?,?)", in.ID, string(data)); err != nil {
		return in, err
	}
	if err := logLocal(ctx, tx, actor, "create_schedule", "schedule", in.ID, ""); err != nil {
		return in, err
	}
	return in, tx.Commit()
}

func (s *RuntimeStore) UpdateSchedule(ctx context.Context, id string, in taskflow.Schedule, actor string) (taskflow.Schedule, error) {
	if id == "" || in.Engine == "port-probe" {
		return in, ErrInvalidTask
	}
	due, err := time.Parse(time.RFC3339, in.NextRun)
	if err != nil || !due.After(time.Now()) || due.After(time.Now().Add(366*24*time.Hour)) || len(strings.TrimSpace(in.Name)) == 0 || len(in.Name) > 100 || in.IntervalMinutes < 0 || in.IntervalMinutes > 525600 {
		return in, ErrInvalidTask
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return in, err
	}
	defer tx.Rollback()
	var raw string
	var current taskflow.Schedule
	if err := tx.QueryRowContext(ctx, "SELECT data FROM task_schedules WHERE id=?", id).Scan(&raw); errors.Is(err, sql.ErrNoRows) {
		return in, ErrTaskConflict
	} else if err != nil {
		return in, err
	}
	if err := json.Unmarshal([]byte(raw), &current); err != nil {
		return in, err
	}
	_, detail, err := resolveTargets(ctx, tx, in.TaskInput)
	if err != nil {
		return in, err
	}
	in.TaskInput = detail.Input
	in.ID = id
	in.Enabled = current.Enabled
	in.CreatedBy = current.CreatedBy
	in.LastTaskID = current.LastTaskID
	in.LastError = ""
	in.NextRun = due.UTC().Format(time.RFC3339Nano)
	data, err := json.Marshal(in)
	if err != nil {
		return in, err
	}
	if _, err := tx.ExecContext(ctx, "UPDATE task_schedules SET data=? WHERE id=?", string(data), id); err != nil {
		return in, err
	}
	if err := logLocal(ctx, tx, actor, "update_schedule", "schedule", id, ""); err != nil {
		return in, err
	}
	if err := tx.Commit(); err != nil {
		return in, err
	}
	return in, nil
}

func (s *RuntimeStore) DeleteSchedule(ctx context.Context, id, actor string) error {
	if strings.TrimSpace(id) == "" {
		return ErrInvalidTask
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var exists int
	if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM task_schedules WHERE id=?", id).Scan(&exists); err != nil {
		return err
	}
	if exists == 0 {
		return ErrTaskConflict
	}
	if err := logLocal(ctx, tx, actor, "delete_schedule", "schedule", id, ""); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM task_schedules WHERE id=?", id); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *RuntimeStore) ListSchedules(ctx context.Context) ([]taskflow.Schedule, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT data FROM task_schedules ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []taskflow.Schedule{}
	for rows.Next() {
		var data string
		var item taskflow.Schedule
		if err := rows.Scan(&data); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(data), &item); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *RuntimeStore) ToggleSchedule(ctx context.Context, id, actor string, enabled bool) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var data string
	var item taskflow.Schedule
	if err := tx.QueryRowContext(ctx, "SELECT data FROM task_schedules WHERE id=?", id).Scan(&data); err != nil {
		return ErrTaskConflict
	}
	if err := json.Unmarshal([]byte(data), &item); err != nil {
		return err
	}
	item.Enabled = enabled
	item.LastError = ""
	if enabled {
		due, err := time.Parse(time.RFC3339Nano, item.NextRun)
		if err != nil {
			return err
		}
		if due.Before(time.Now()) {
			item.NextRun = time.Now().Add(time.Second).UTC().Format(time.RFC3339Nano)
		}
	}
	encoded, _ := json.Marshal(item)
	if _, err := tx.ExecContext(ctx, "UPDATE task_schedules SET data=? WHERE id=?", string(encoded), id); err != nil {
		return err
	}
	if err := logLocal(ctx, tx, actor, "toggle_schedule", "schedule", id, strconv.FormatBool(enabled)); err != nil {
		return err
	}
	return tx.Commit()
}

// Tick advances persisted schedules and resumes tasks only within their windows.
func (s *RuntimeStore) Tick(ctx context.Context, now time.Time) error {
	if err := s.expireRuntimeLeases(ctx, now); err != nil {
		return err
	}
	schedules, err := s.ListSchedules(ctx)
	if err != nil {
		return err
	}
	for _, item := range schedules {
		due, err := time.Parse(time.RFC3339Nano, item.NextRun)
		if err != nil {
			return err
		}
		if !item.Enabled || due.After(now) {
			continue
		}
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		var original string
		if err := tx.QueryRowContext(ctx, "SELECT data FROM task_schedules WHERE id=?", item.ID).Scan(&original); err != nil {
			tx.Rollback()
			if errors.Is(err, sql.ErrNoRows) {
				continue
			}
			return err
		}
		var latest taskflow.Schedule
		if err := json.Unmarshal([]byte(original), &latest); err != nil {
			tx.Rollback()
			return err
		}
		// Compare against the snapshot to prevent duplicate ticks or stale toggles.
		if !latest.Enabled || latest.NextRun != item.NextRun {
			tx.Rollback()
			continue
		}
		id := "task-" + randomLocalID()
		_, createErr := createLocalTask(ctx, tx, item.TaskInput, item.CreatedBy, id, now)
		if createErr != nil {
			tx.Rollback()
			if !errors.Is(createErr, ErrInvalidTask) {
				return createErr
			}
			item.Enabled = false
			item.LastError = createErr.Error()
		} else {
			item.LastTaskID = id
			item.LastError = ""
			if item.IntervalMinutes == 0 {
				item.Enabled = false
			} else {
				item.NextRun = now.Add(time.Duration(item.IntervalMinutes) * time.Minute).UTC().Format(time.RFC3339Nano)
			}
			data, _ := json.Marshal(item)
			_, err = tx.ExecContext(ctx, "UPDATE task_schedules SET data=? WHERE id=?", string(data), item.ID)
			if err != nil {
				tx.Rollback()
				return err
			}
			if err := tx.Commit(); err != nil {
				return err
			}
			continue
		}
		data, _ := json.Marshal(item)
		if _, err := s.db.ExecContext(ctx, "UPDATE task_schedules SET data=? WHERE id=?", string(data), item.ID); err != nil {
			return err
		}
	}
	tasks, err := s.ListRuntimeTasks(ctx)
	if err != nil {
		return err
	}
	for _, task := range tasks {
		if task.Status != "WAITING_WINDOW" && task.Status != "PAUSED_WINDOW" {
			continue
		}
		_, allowed, err := scheduler.AllowedUntil(task.TimeWindows, now)
		if err != nil {
			return err
		}
		if allowed {
			if _, err := s.db.ExecContext(ctx, `UPDATE scan_tasks SET status='PENDING' WHERE id=? AND status IN ('WAITING_WINDOW','PAUSED_WINDOW')`, task.ID); err != nil {
				return err
			}
		}
	}
	return nil
}

type LocalNode struct {
	ID               string                  `json:"id"`
	Kind             string                  `json:"kind"`
	HostID           string                  `json:"hostId"`
	IP               string                  `json:"ip"`
	Status           string                  `json:"status"`
	CurrentTask      string                  `json:"currentTask"`
	BoundRuleVersion string                  `json:"boundRuleVersion"`
	LastHeartbeat    time.Time               `json:"lastHeartbeat"`
	FenceStatus      string                  `json:"fenceStatus"`
	DropCount        int                     `json:"dropCount"`
	Engines          []taskflow.EngineStatus `json:"engines,omitempty"`
}

func (s *RuntimeStore) ListQuarantines(ctx context.Context) ([]map[string]any, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT q.asset_id,a.address,q.port,q.reason,q.detected_at,q.status FROM port_quarantine q JOIN assets a ON a.id=q.asset_id WHERE q.status='ACTIVE' ORDER BY a.address,q.port`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id, address, reason, at, status string
		var port int
		if err := rows.Scan(&id, &address, &port, &reason, &at, &status); err != nil {
			return nil, err
		}
		items = append(items, map[string]any{"assetId": id, "address": address, "port": port, "reason": reason, "detectedAt": at, "status": status})
	}
	return items, rows.Err()
}

func (s *RuntimeStore) TouchNode(ctx context.Context, id, kind, task string, engineStatus ...[]taskflow.EngineStatus) error {
	return s.TouchNodeState(ctx, id, kind, task, "", "", engineStatus...)
}

// TouchNodeState persists the Worker-local rule version and an explicit
// readiness status. An empty localRuleVersion preserves the last reported
// value so older updater/report heartbeats do not erase Worker state.
func (s *RuntimeStore) TouchNodeState(ctx context.Context, id, kind, task, localRuleVersion, nodeStatus string, engineStatus ...[]taskflow.EngineStatus) error {
	status := "ONLINE"
	if task != "" {
		status = "BUSY"
	}
	if nodeStatus != "" {
		status = nodeStatus
	}
	node := LocalNode{ID: id, Kind: kind, HostID: "local", IP: "127.0.0.1", Status: status, CurrentTask: task, BoundRuleVersion: localRuleVersion, LastHeartbeat: time.Now().UTC(), FenceStatus: "NOT_SUPPORTED"}
	if len(engineStatus) > 0 {
		node.Engines = engineStatus[0]
	}
	data, _ := json.Marshal(node)
	_, err := s.db.ExecContext(ctx, `INSERT INTO local_nodes(id,data) VALUES(?,?) ON CONFLICT(id) DO UPDATE SET data=json_set(
		json_set(excluded.data,'$.boundRuleVersion',CASE WHEN json_extract(excluded.data,'$.status') IN ('WAITING_FOR_RULES','RULES_ERROR') THEN '' WHEN COALESCE(json_extract(excluded.data,'$.boundRuleVersion'),'')='' THEN COALESCE(json_extract(local_nodes.data,'$.boundRuleVersion'),'') ELSE json_extract(excluded.data,'$.boundRuleVersion') END),
		'$.engines',CASE WHEN json_extract(excluded.data,'$.engines') IS NULL THEN json_extract(local_nodes.data,'$.engines') ELSE json_extract(excluded.data,'$.engines') END)`, id, string(data))
	return err
}

func (s *RuntimeStore) ListNodes(ctx context.Context) ([]LocalNode, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT data FROM local_nodes ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []LocalNode{}
	for rows.Next() {
		var data string
		var node LocalNode
		if err := rows.Scan(&data); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(data), &node); err != nil {
			return nil, err
		}
		if time.Since(node.LastHeartbeat) > 10*time.Second {
			node.Status = "OFFLINE"
		}
		out = append(out, node)
	}
	return out, rows.Err()
}

func (s *RuntimeStore) TaskStateForWorker(ctx context.Context, id, worker string) string {
	var state string
	if err := s.db.QueryRowContext(ctx, "SELECT status FROM scan_tasks WHERE id=? AND worker_id=?", id, worker).Scan(&state); err != nil {
		return "UNKNOWN"
	}
	return state
}
