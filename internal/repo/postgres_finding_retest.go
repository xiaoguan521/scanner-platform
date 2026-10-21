package repo

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"scanner-platform/internal/portprobe"
	"scanner-platform/internal/rules"
	"scanner-platform/internal/scheduler"
	"scanner-platform/internal/taskflow"
)

func postgresExactRetestRanges(ports []int) []portprobe.Range {
	if len(ports) == 0 {
		return nil
	}
	ordered := append([]int(nil), ports...)
	sort.Ints(ordered)
	ranges := make([]portprobe.Range, 0, len(ordered))
	start, end := ordered[0], ordered[0]
	for _, port := range ordered[1:] {
		if port == end+1 {
			end = port
			continue
		}
		ranges = append(ranges, portprobe.Range{Start: start, End: end})
		start, end = port, port
	}
	return append(ranges, portprobe.Range{Start: start, End: end})
}

func postgresContainsPort(ports []int, wanted int) bool {
	for _, port := range ports {
		if port == wanted {
			return true
		}
	}
	return false
}

func postgresPolicyTx(ctx context.Context, tx *sql.Tx) (ScanPolicy, error) {
	policy := defaultPolicy()
	var raw string
	err := tx.QueryRowContext(ctx, `SELECT data FROM product_settings WHERE id=$1`, "scan-policy").Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return policy, nil
	}
	if err != nil {
		return policy, err
	}
	if err := json.Unmarshal([]byte(raw), &policy); err != nil {
		return policy, err
	}
	return normalizeScanPolicy(policy)
}

func postgresCurrentRuleVersionTx(ctx context.Context, tx *sql.Tx) (string, error) {
	var version string
	if err := tx.QueryRowContext(ctx, `SELECT version FROM rule_bundles WHERE is_current=TRUE
		ORDER BY published_at DESC,version DESC LIMIT 1`).Scan(&version); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", fmt.Errorf("%w: PostgreSQL 尚未登记活动规则包", ErrInvalidTask)
		}
		return "", err
	}
	if !rules.ValidateVersion(version) {
		return "", fmt.Errorf("%w: PostgreSQL 规则版本无效", ErrInvalidTask)
	}
	return version, nil
}

func postgresExcludedPortsTx(ctx context.Context, tx *sql.Tx, assetID string) (map[int]bool, error) {
	rows, err := tx.QueryContext(ctx, `SELECT port FROM asset_ports
		WHERE asset_id=$1 AND kind='EXCLUDED_PROXY'
		UNION SELECT port FROM port_quarantine WHERE asset_id=$1 AND status='ACTIVE'`, assetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	excluded := make(map[int]bool)
	for rows.Next() {
		var port int
		if err := rows.Scan(&port); err != nil {
			return nil, err
		}
		excluded[port] = true
	}
	return excluded, rows.Err()
}

func postgresApprovedVulnerabilityPortsTx(ctx context.Context, tx *sql.Tx, assetID string, ports []int) (int, error) {
	if len(ports) == 0 {
		return 0, nil
	}
	args := make([]any, 0, len(ports)+1)
	args = append(args, assetID)
	placeholders := make([]string, len(ports))
	for i, port := range ports {
		args = append(args, port)
		placeholders[i] = fmt.Sprintf("$%d", len(args))
	}
	var count int
	err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM asset_port_reviews r
		JOIN asset_ports p ON p.asset_id=r.asset_id AND p.port=r.port
		WHERE r.asset_id=$1 AND r.status='APPROVED' AND p.kind IN ('WEB','NON_WEB')
		AND r.port IN (`+strings.Join(placeholders, ",")+`)`, args...).Scan(&count)
	return count, err
}

func postgresCanonicalRetestTarget(raw string) (string, int, error) {
	host, portText, err := net.SplitHostPort(strings.TrimSpace(raw))
	if err != nil {
		return "", 0, ErrInvalidTask
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || ip.IsUnspecified() || ip.IsMulticast() || ip.Zone() != "" {
		return "", 0, ErrInvalidTask
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return "", 0, ErrInvalidTask
	}
	return ip.Unmap().String(), port, nil
}

func postgresRetestTaskProjection(ctx context.Context, tx *sql.Tx, findingID string) (taskflow.Finding, taskflow.Task, error) {
	var finding taskflow.Finding
	finding, err := (&PostgresFindingStore{}).readFindingTx(ctx, tx, findingID)
	if err != nil {
		return finding, taskflow.Task{}, err
	}
	var raw string
	var fixedThreshold int
	var fixedThresholdFrozen bool
	var status, scopeID, enginesRaw, targetsRaw string
	if err := tx.QueryRowContext(ctx, `SELECT t.status,t.scope_id,t.engines,p.data,p.fixed_threshold,p.fixed_threshold_frozen,c.targets
		FROM scan_tasks t JOIN scan_task_projections p ON p.task_id=t.id
		JOIN scan_task_chunks c ON c.task_id=t.id
		WHERE t.id=$1 AND c.id=$1||'-chunk' FOR UPDATE OF t,c,p`, finding.TaskID).
		Scan(&status, &scopeID, &enginesRaw, &raw, &fixedThreshold, &fixedThresholdFrozen, &targetsRaw); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return finding, taskflow.Task{}, ErrTaskConflict
		}
		return finding, taskflow.Task{}, err
	}
	if status != "COMPLETED" {
		return finding, taskflow.Task{}, fmt.Errorf("%w: parent scan is not complete", ErrInvalidTask)
	}
	var task taskflow.Task
	if err := json.Unmarshal([]byte(raw), &task); err != nil {
		return finding, taskflow.Task{}, err
	}
	if err := json.Unmarshal([]byte(enginesRaw), &task.Engines); err != nil {
		return finding, taskflow.Task{}, err
	}
	if err := json.Unmarshal([]byte(targetsRaw), &task.Chunks); err != nil {
		var targets []string
		if err := json.Unmarshal([]byte(targetsRaw), &targets); err != nil {
			return finding, taskflow.Task{}, err
		}
		task.Chunks = []taskflow.Chunk{{ID: task.ID + "-chunk", TaskID: task.ID, Targets: targets, Status: status}}
	}
	task.ID, task.ScopeID, task.Status = finding.TaskID, scopeID, status
	if fixedThresholdFrozen {
		task.FixedThreshold = fixedThreshold
		if task.FixedThreshold < 1 {
			task.FixedThreshold = 1
		}
	} else {
		task.FixedThreshold = 0
	}
	return finding, task, nil
}

func (s *PostgresRuntimeStore) CreateFindingRetest(ctx context.Context, findingID, actor string) (taskflow.Task, FindingRetest, error) {
	if !validPostgresWorkID(actor, 128) || !validPostgresWorkID(findingID, 256) {
		return taskflow.Task{}, FindingRetest{}, ErrInvalidTask
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return taskflow.Task{}, FindingRetest{}, fmt.Errorf("begin postgres finding retest: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, findingID); err != nil {
		return taskflow.Task{}, FindingRetest{}, err
	}
	finding, parent, err := postgresRetestTaskProjection(ctx, tx, findingID)
	if err != nil {
		if errors.Is(err, ErrPostgresFindingMissing) {
			return taskflow.Task{}, FindingRetest{}, ErrTaskNotFound
		}
		return taskflow.Task{}, FindingRetest{}, err
	}
	if finding.Synthetic || finding.Status == "FALSE_POSITIVE" || len(parent.Engines) != 1 || parent.Engines[0] != "auto" || (finding.Engine != "nuclei" && finding.Engine != "trivy") {
		return taskflow.Task{}, FindingRetest{}, fmt.Errorf("%w: this finding cannot be retested", ErrInvalidTask)
	}
	var existingID string
	err = tx.QueryRowContext(ctx, `SELECT fr.id FROM finding_retests fr JOIN scan_tasks st ON st.id=fr.task_id
		WHERE fr.finding_id=$1 AND st.status IN ('PENDING','WAITING_WINDOW','RUNNING','PAUSED_WINDOW','PAUSED')
		ORDER BY fr.created_at,fr.id LIMIT 1`, findingID).Scan(&existingID)
	if err == nil {
		return taskflow.Task{}, FindingRetest{}, fmt.Errorf("%w: an active retest already exists", ErrTaskConflict)
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return taskflow.Task{}, FindingRetest{}, err
	}
	if parent.AssetID == "" || finding.AssetID != parent.AssetID || len(parent.Chunks) != 1 || len(parent.Chunks[0].Targets) != 1 {
		return taskflow.Task{}, FindingRetest{}, fmt.Errorf("%w: finding is outside the frozen scan scope", ErrInvalidTask)
	}
	host, port, err := postgresCanonicalRetestTarget(finding.Target)
	if err != nil || host != parent.Chunks[0].Targets[0] || !postgresContainsPort(parent.PortProbePorts, port) || len(parent.VulnerabilityPorts) > 0 && !postgresContainsPort(parent.VulnerabilityPorts, port) {
		return taskflow.Task{}, FindingRetest{}, fmt.Errorf("%w: finding is outside the frozen scan scope", ErrInvalidTask)
	}

	var address, businessGroup, owner string
	if err := tx.QueryRowContext(ctx, `SELECT address,business_group,owner FROM assets WHERE id=$1 AND kind='host' FOR SHARE`, parent.AssetID).Scan(&address, &businessGroup, &owner); err != nil {
		return taskflow.Task{}, FindingRetest{}, err
	}
	parsedAsset, err := netip.ParseAddr(address)
	if err != nil || parsedAsset.Unmap().String() != host {
		return taskflow.Task{}, FindingRetest{}, fmt.Errorf("%w: asset address changed", ErrInvalidTask)
	}
	var scopeID, scopeHost, windowsRaw string
	var expires time.Time
	if err := tx.QueryRowContext(ctx, `SELECT id,cidr_or_host,time_windows,expires_at FROM authorized_scopes
		WHERE asset_id=$1 AND status='APPROVED' AND expires_at>CURRENT_TIMESTAMP
		ORDER BY expires_at DESC,id LIMIT 1`, parent.AssetID).Scan(&scopeID, &scopeHost, &windowsRaw, &expires); err != nil {
		return taskflow.Task{}, FindingRetest{}, fmt.Errorf("%w: current authorization is unavailable", ErrInvalidTask)
	}
	if scopeHost != host || !expires.After(time.Now().UTC()) {
		return taskflow.Task{}, FindingRetest{}, fmt.Errorf("%w: current authorization is unavailable", ErrInvalidTask)
	}
	var currentWindows []scheduler.Window
	if err := json.Unmarshal([]byte(windowsRaw), &currentWindows); err != nil || scheduler.ValidateWindows(currentWindows) != nil {
		return taskflow.Task{}, FindingRetest{}, fmt.Errorf("%w: invalid current authorization window", ErrInvalidTask)
	}
	requestedWindows, _ := json.Marshal(parent.TimeWindows)
	approvedWindows, _ := json.Marshal(currentWindows)
	if len(parent.TimeWindows) > 0 && string(requestedWindows) != string(approvedWindows) {
		return taskflow.Task{}, FindingRetest{}, fmt.Errorf("%w: parent time window is no longer authorized", ErrInvalidTask)
	}
	if len(parent.TimeWindows) == 0 {
		parent.TimeWindows = currentWindows
	}

	policy, err := postgresPolicyTx(ctx, tx)
	if err != nil {
		return taskflow.Task{}, FindingRetest{}, err
	}
	excluded, err := postgresExcludedPortsTx(ctx, tx, parent.AssetID)
	if err != nil {
		return taskflow.Task{}, FindingRetest{}, err
	}
	effective := make([]int, 0, len(parent.PortProbePorts))
	skipped := make([]string, 0)
	for _, candidate := range parent.PortProbePorts {
		if excluded[candidate] {
			skipped = append(skipped, net.JoinHostPort(host, strconv.Itoa(candidate)))
			continue
		}
		effective = append(effective, candidate)
	}
	if !postgresContainsPort(effective, port) || len(effective) == 0 {
		return taskflow.Task{}, FindingRetest{}, fmt.Errorf("%w: finding port is excluded or quarantined", ErrInvalidTask)
	}
	if approved, err := postgresApprovedVulnerabilityPortsTx(ctx, tx, parent.AssetID, effective); err != nil || approved != len(effective) {
		if err != nil {
			return taskflow.Task{}, FindingRetest{}, err
		}
		return taskflow.Task{}, FindingRetest{}, fmt.Errorf("%w: current port approvals are incomplete", ErrInvalidTask)
	}
	ruleVersion, err := postgresCurrentRuleVersionTx(ctx, tx)
	if err != nil {
		return taskflow.Task{}, FindingRetest{}, err
	}
	now := time.Now().UTC()
	deadline, allowed, err := scheduler.AllowedUntil(parent.TimeWindows, now)
	if err != nil {
		return taskflow.Task{}, FindingRetest{}, ErrInvalidTask
	}
	status := "PENDING"
	if !allowed {
		status = "WAITING_WINDOW"
		deadline = time.Time{}
	}
	childID := "task-" + randomLocalID()
	chunkID := childID + "-chunk"
	config := portprobe.Config{
		Preset:                    portprobe.PresetCustom,
		Ranges:                    postgresExactRetestRanges(parent.PortProbePorts),
		Exclusions:                append([]portprobe.Range(nil), policy.Exclusions...),
		OpsApproved:               true,
		FullConfirmed:             len(parent.PortProbePorts) == portprobe.MaxPorts,
		Intensity:                 parent.PortProbeConfig.Intensity,
		IdentificationMaxAttempts: policy.DiscoveryAttempts,
		QuarantineThreshold:       policy.QuarantineThreshold,
	}
	child := taskflow.Task{
		ID: childID, ScopeID: scopeID, ScopeName: parent.ScopeName, Engines: []string{"auto"}, Status: status,
		AssetID: parent.AssetID, FixedThreshold: policy.FixedThreshold, TargetCount: 1, TotalChunks: 1,
		RuleVersion: ruleVersion, TimeWindows: parent.TimeWindows, Chunks: []taskflow.Chunk{{ID: chunkID, TaskID: childID, Targets: []string{host}, Status: status, PinnedRuleVersion: ruleVersion}},
		EffectiveExclusions: compactPostgresPortRanges(appendRanges(config.Exclusions, excluded)), SkippedTargets: skipped,
		PortProbeConfig: config, PortProbePorts: effective, VulnerabilityPorts: append([]int(nil), effective...),
		CustomTemplates: append([]json.RawMessage(nil), parent.CustomTemplates...), CustomRuleCount: len(parent.CustomTemplates),
		SystemScanStatus: taskflow.SystemScanNotStarted, RetestFindingID: findingID,
	}
	if allowed {
		child.HardDeadline = deadline.UTC().Format(time.RFC3339Nano)
	}
	if err := s.queue.createTaskWithProjectionTx(ctx, tx, ScanTask{
		ID: childID, ScopeID: scopeID, Status: status, HardDeadline: deadline, CreatedBy: actor,
		Engines: child.Engines, Targets: []string{host}, PinnedRuleVersion: ruleVersion,
	}, s.projection, child); err != nil {
		return taskflow.Task{}, FindingRetest{}, err
	}
	retest := FindingRetest{ID: "retest-" + randomLocalID(), FindingID: findingID, TaskID: childID, Actor: actor, Status: status, CreatedAt: now}
	if _, err := tx.ExecContext(ctx, `INSERT INTO finding_retests(id,finding_id,task_id,actor,created_at)
		VALUES ($1,$2,$3,$4,$5)`, retest.ID, findingID, childID, actor, now); err != nil {
		return taskflow.Task{}, FindingRetest{}, fmt.Errorf("insert postgres finding retest: %w", err)
	}
	detail, _ := json.Marshal(map[string]string{"retestId": retest.ID, "taskId": childID})
	if err := s.postgresAuditTx(ctx, tx, actor, "retest_finding", "finding", findingID, string(detail)); err != nil {
		return taskflow.Task{}, FindingRetest{}, err
	}
	if err := tx.Commit(); err != nil {
		return taskflow.Task{}, FindingRetest{}, fmt.Errorf("commit postgres finding retest: %w", err)
	}
	created, err := s.GetRuntimeTask(ctx, childID)
	if err != nil {
		return taskflow.Task{}, FindingRetest{}, err
	}
	_ = businessGroup
	_ = owner
	return created, retest, nil
}

func (s *PostgresRuntimeStore) ListFindingRetests(ctx context.Context, findingID string) ([]FindingRetest, error) {
	if err := s.findingWorkExists(ctx, findingID); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT fr.id,fr.finding_id,fr.task_id,fr.actor,st.status,fr.created_at
		FROM finding_retests fr JOIN scan_tasks st ON st.id=fr.task_id
		WHERE fr.finding_id=$1 ORDER BY fr.created_at,fr.id`, findingID)
	if err != nil {
		return nil, fmt.Errorf("list postgres finding retests: %w", err)
	}
	defer rows.Close()
	items := make([]FindingRetest, 0)
	for rows.Next() {
		var item FindingRetest
		if err := rows.Scan(&item.ID, &item.FindingID, &item.TaskID, &item.Actor, &item.Status, &item.CreatedAt); err != nil {
			return nil, err
		}
		item.CreatedAt = item.CreatedAt.UTC()
		items = append(items, item)
	}
	return items, rows.Err()
}
