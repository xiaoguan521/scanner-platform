package repo

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"scanner-platform/internal/portprobe"
	"scanner-platform/internal/rules"
	"scanner-platform/internal/taskflow"
)

func approveFixturePort(t *testing.T, store *RuntimeStore, actor, address string, port int) {
	t.Helper()
	var assetID string
	if err := store.db.QueryRowContext(context.Background(), "SELECT id FROM assets WHERE address=?", address).Scan(&assetID); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := store.db.ExecContext(context.Background(), `INSERT INTO asset_port_reviews
 (asset_id,port,status,reviewed_by,approval_ticket,reviewed_at,review_note) VALUES(?,?,'APPROVED',?,'fixture-approval',?,'')`, assetID, port, actor, now); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(context.Background(), `INSERT INTO asset_ports(asset_id,port,kind,source) VALUES(?,?,'WEB','fixture-approval')`, assetID, port); err != nil {
		t.Fatal(err)
	}
}

func installNucleiFixtureBundle(t *testing.T, store *RuntimeStore, version string) {
	t.Helper()
	data, err := json.Marshal(rules.Bundle{Version: version, Engines: []string{"nuclei"}, IsCurrent: true, IntegrityVerified: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(context.Background(), "INSERT INTO local_rule_bundles(version,data) VALUES(?,?)", version, string(data)); err != nil {
		t.Fatal(err)
	}
}

func createClaimedNucleiTask(t *testing.T, store *RuntimeStore, actor, worker string) taskflow.Task {
	t.Helper()
	task, err := store.CreateLocalTask(context.Background(), taskflow.TaskInput{Engine: "nuclei", Scheme: "http", Targets: []string{"192.0.2.20:80"}}, actor)
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := store.ClaimRuntimeTask(context.Background(), worker)
	if err != nil || claimed == nil || claimed.ID != task.ID {
		t.Fatalf("claim task: %+v %v", claimed, err)
	}
	return *claimed
}

func completeNucleiFixture(t *testing.T, store *RuntimeStore, task taskflow.Task, findings ...taskflow.Detection) {
	t.Helper()
	report := taskflow.Report{TaskID: task.ID, WorkerID: task.Chunks[0].WorkerNodeID, Status: "COMPLETED", Findings: findings,
		CompletedFully: true, RulesExecuted: true, ExecutedEngines: []string{"nuclei"}, RuleVersion: task.RuleVersion}
	if err := store.CompleteRuntimeTask(context.Background(), report); err != nil {
		t.Fatal(err)
	}
}

func TestFenceTelemetryIsPersistedAndAudited(t *testing.T) {
	store, actor := localFixture(t)
	ctx := context.Background()
	approveFixturePort(t, store, actor, "192.0.2.20", 80)
	installNucleiFixtureBundle(t, store, "20261020.07")
	task := createClaimedNucleiTask(t, store, actor, "fenced-worker")
	report := taskflow.Report{TaskID: task.ID, WorkerID: "fenced-worker", Status: "COMPLETED", CompletedFully: true,
		RulesExecuted: true, ExecutedEngines: []string{"nuclei"}, RuleVersion: task.RuleVersion,
		FenceStatus: "ENFORCED", DropCount: 2}
	if err := store.CompleteRuntimeTask(ctx, report); err != nil {
		t.Fatal(err)
	}
	tasks, err := store.ListRuntimeTasks(ctx)
	if err != nil || len(tasks) != 1 || tasks[0].FenceStatus != "ENFORCED" || tasks[0].DropCount != 2 {
		t.Fatalf("fence telemetry was not persisted: %+v %v", tasks, err)
	}
	logs, err := store.ListTaskLogs(ctx, task.ID)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, log := range logs {
		if log.Action == "fence_drop_observed" {
			found = true
			if log.Message == "" || log.Message == "drop_count=2" {
				t.Fatalf("unsafe fence log message: %+v", log)
			}
		}
	}
	if !found {
		t.Fatalf("fence audit event missing: %+v", logs)
	}
}

func TestFenceTelemetryValidationIsFailClosed(t *testing.T) {
	for _, report := range []taskflow.Report{
		{FenceStatus: "", DropCount: 1},
		{FenceStatus: "UNKNOWN"},
		{FenceStatus: "ENFORCED", DropCount: maxFenceDropCount + 1},
	} {
		if err := validateFenceTelemetry(report); !errors.Is(err, ErrInvalidTask) {
			t.Fatalf("invalid telemetry accepted: %+v err=%v", report, err)
		}
	}
	if err := validateFenceTelemetry(taskflow.Report{FenceStatus: "ENFORCED"}); err != nil {
		t.Fatalf("zero-drop enforced telemetry rejected: %v", err)
	}
}

func fixtureNucleiFinding() taskflow.Detection {
	return taskflow.Detection{Engine: "nuclei", Target: "192.0.2.20:80", TemplateID: "fixture-header", Title: "fixture header", Severity: "LOW", MatchedPath: "/"}
}

func TestFindingLifecycleMarksFixedOnlyAfterCompleteEligibleMiss(t *testing.T) {
	store, actor := localFixture(t)
	ctx := context.Background()
	approveFixturePort(t, store, actor, "192.0.2.20", 80)
	installNucleiFixtureBundle(t, store, "20261020.05")

	first := createClaimedNucleiTask(t, store, actor, "fixed-worker")
	completeNucleiFixture(t, store, first, fixtureNucleiFinding())
	items, err := store.ListRuntimeFindings(ctx)
	if err != nil || len(items) != 1 || items[0].Status != "OPEN" || items[0].ConsecutiveMisses != 0 || !items[0].VerifiedInRun {
		t.Fatalf("first eligible report did not create OPEN finding: %+v %v", items, err)
	}

	second := createClaimedNucleiTask(t, store, actor, "fixed-worker")
	completeNucleiFixture(t, store, second)
	items, err = store.ListRuntimeFindings(ctx)
	if err != nil || len(items) != 1 || items[0].Status != "FIXED" || items[0].ConsecutiveMisses != 1 || items[0].VerifiedInRun || items[0].ResolvedAt == nil {
		t.Fatalf("eligible missing finding did not become FIXED: %+v %v", items, err)
	}

	third := createClaimedNucleiTask(t, store, actor, "fixed-worker")
	completeNucleiFixture(t, store, third, fixtureNucleiFinding())
	items, err = store.ListRuntimeFindings(ctx)
	if err != nil || len(items) != 1 || items[0].Status != "REOPENED" || items[0].ConsecutiveMisses != 0 || !items[0].VerifiedInRun || items[0].ResolvedAt != nil {
		t.Fatalf("reappearance did not reopen finding: %+v %v", items, err)
	}
}

func TestFindingLifecycleRequiresCompleteMatchingRulesAndScope(t *testing.T) {
	store, actor := localFixture(t)
	ctx := context.Background()
	approveFixturePort(t, store, actor, "192.0.2.20", 80)
	installNucleiFixtureBundle(t, store, "20261020.06")
	first := createClaimedNucleiTask(t, store, actor, "lifecycle-worker")
	completeNucleiFixture(t, store, first, fixtureNucleiFinding())

	// A report without the new metadata is accepted for compatibility, but it
	// cannot make an absent finding count as a verified miss.
	old := createClaimedNucleiTask(t, store, actor, "lifecycle-worker")
	if err := store.CompleteRuntimeTask(ctx, taskflow.Report{TaskID: old.ID, WorkerID: "lifecycle-worker", Status: "COMPLETED"}); err != nil {
		t.Fatal(err)
	}
	items, _ := store.ListRuntimeFindings(ctx)
	if items[0].Status != "OPEN" || items[0].ConsecutiveMisses != 0 {
		t.Fatalf("old report changed lifecycle: %+v", items[0])
	}

	failed := createClaimedNucleiTask(t, store, actor, "lifecycle-worker")
	if err := store.CompleteRuntimeTask(ctx, taskflow.Report{TaskID: failed.ID, WorkerID: "lifecycle-worker", Status: "FAILED", Error: "fixture"}); err != nil {
		t.Fatal(err)
	}
	items, _ = store.ListRuntimeFindings(ctx)
	if items[0].ConsecutiveMisses != 0 {
		t.Fatalf("failed report changed lifecycle: %+v", items[0])
	}

	mismatch := createClaimedNucleiTask(t, store, actor, "lifecycle-worker")
	bad := taskflow.Report{TaskID: mismatch.ID, WorkerID: "lifecycle-worker", Status: "COMPLETED", CompletedFully: true, RulesExecuted: true, ExecutedEngines: []string{"nuclei"}, RuleVersion: "wrong-version"}
	if err := store.CompleteRuntimeTask(ctx, bad); err != nil {
		t.Fatal(err)
	}
	items, _ = store.ListRuntimeFindings(ctx)
	if items[0].ConsecutiveMisses != 0 {
		t.Fatalf("version mismatch changed lifecycle: %+v", items[0])
	}

	// A finding for a different port is outside this task's exact target and
	// must not be touched by a later eligible 80/tcp scan. Seed it directly to
	// keep this test independent of the fixture's registered-port approvals.
	var assetID string
	if err := store.db.QueryRowContext(ctx, "SELECT id FROM assets WHERE address=?", "192.0.2.20").Scan(&assetID); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	outOfScope := taskflow.Finding{ID: "finding-out-of-scope", TaskID: first.ID, Fingerprint: "out-of-scope", AssetID: assetID, Severity: "LOW", Title: "out of scope", Engine: "nuclei", TemplateOrCVE: "fixture-other", Target: "192.0.2.20:443", Status: "OPEN", FirstSeen: now, LastSeen: now, VerifiedInRun: true}
	raw, _ := json.Marshal(outOfScope)
	if _, err := store.db.ExecContext(ctx, "INSERT INTO security_findings(id,task_id,data) VALUES(?,?,?)", outOfScope.ID, first.ID, string(raw)); err != nil {
		t.Fatal(err)
	}
	scopeCheck := createClaimedNucleiTask(t, store, actor, "lifecycle-worker")
	completeNucleiFixture(t, store, scopeCheck)
	items, _ = store.ListRuntimeFindings(ctx)
	for _, item := range items {
		if item.Target == "192.0.2.20:443" && item.Status != "OPEN" {
			t.Fatalf("out-of-scope finding was changed: %+v", item)
		}
	}
}

func TestFindingLifecycleUsesFrozenThreshold(t *testing.T) {
	store, actor := localFixture(t)
	ctx := context.Background()
	approveFixturePort(t, store, actor, "192.0.2.20", 80)
	installNucleiFixtureBundle(t, store, "20261020.07")
	policy := defaultPolicy()
	policy.FixedThreshold = 2
	if _, err := store.SaveScanPolicy(ctx, policy, actor); err != nil {
		t.Fatal(err)
	}
	first := createClaimedNucleiTask(t, store, actor, "threshold-worker")
	if first.FixedThreshold != 2 {
		t.Fatalf("task did not freeze fixed threshold: %d", first.FixedThreshold)
	}
	completeNucleiFixture(t, store, first, fixtureNucleiFinding())
	for i := 0; i < 2; i++ {
		task := createClaimedNucleiTask(t, store, actor, "threshold-worker")
		completeNucleiFixture(t, store, task)
		items, _ := store.ListRuntimeFindings(ctx)
		wantStatus := "OPEN"
		wantMisses := i + 1
		if i == 1 {
			wantStatus = "FIXED"
		}
		if items[0].Status != wantStatus || items[0].ConsecutiveMisses != wantMisses {
			t.Fatalf("threshold=%d iteration=%d: %+v", first.FixedThreshold, i, items[0])
		}
	}
}

func TestFindingLifecyclePreservesManualDisposition(t *testing.T) {
	for _, status := range []string{"FALSE_POSITIVE", "ACCEPTED_RISK"} {
		t.Run(status, func(t *testing.T) {
			store, actor := localFixture(t)
			ctx := context.Background()
			approveFixturePort(t, store, actor, "192.0.2.20", 80)
			installNucleiFixtureBundle(t, store, "20261020.08")
			first := createClaimedNucleiTask(t, store, actor, "manual-state-worker")
			completeNucleiFixture(t, store, first, fixtureNucleiFinding())
			items, err := store.ListRuntimeFindings(ctx)
			if err != nil || len(items) != 1 {
				t.Fatalf("initial finding missing: %+v %v", items, err)
			}
			if status == "FALSE_POSITIVE" {
				if _, err := store.UpdateFinding(ctx, items[0].ID, status, actor); err != nil {
					t.Fatal(err)
				}
			} else {
				if _, err := store.UpdateFindingDisposition(ctx, items[0].ID, FindingDisposition{Status: status, Reason: "测试风险接受", AcceptedUntil: time.Now().Add(time.Hour).Format(time.RFC3339)}, actor); err != nil {
					t.Fatal(err)
				}
			}

			second := createClaimedNucleiTask(t, store, actor, "manual-state-worker")
			completeNucleiFixture(t, store, second)
			items, err = store.ListRuntimeFindings(ctx)
			if err != nil || len(items) != 1 || items[0].Status != status || items[0].ConsecutiveMisses != 0 {
				t.Fatalf("manual disposition changed by missing scan: %+v %v", items, err)
			}
		})
	}
}

func TestRealTasksMultipleResultsDedupAndFailure(t *testing.T) {
	store, actor := localFixture(t)
	ctx := context.Background()
	approveFixturePort(t, store, actor, "192.0.2.20", 80)
	input := taskflow.TaskInput{Engine: "nuclei", Scheme: "http", Targets: []string{"192.0.2.20:80", "192.0.2.20:443"}}
	if _, err := store.CreateLocalTask(ctx, input, actor); !errors.Is(err, ErrInvalidTask) {
		t.Fatal("missing rules accepted", err)
	}
	data, _ := json.Marshal(rules.Bundle{Version: "20261016.01", Engines: []string{"nuclei", "trivy"}, IsCurrent: true, IntegrityVerified: true})
	if _, err := store.db.ExecContext(ctx, "INSERT INTO local_rule_bundles(version,data) VALUES(?,?)", "20261016.01", string(data)); err != nil {
		t.Fatal(err)
	}
	for iteration := 0; iteration < 2; iteration++ {
		created, err := store.CreateLocalTask(ctx, input, actor)
		if err != nil {
			t.Fatal(err)
		}
		if created.Synthetic || len(created.SkippedTargets) != 1 {
			t.Fatal(created)
		}
		task, err := store.ClaimRuntimeTask(ctx, "real-worker")
		if err != nil || task == nil {
			t.Fatal(task, err)
		}
		report := taskflow.Report{TaskID: task.ID, WorkerID: "real-worker", Status: "COMPLETED", Findings: []taskflow.Detection{
			{Engine: "nuclei", TemplateID: "header-one", Target: "192.0.2.20:80", Title: "Header one", Severity: "LOW", MatchedPath: "/"},
			{Engine: "nuclei", TemplateID: "header-two", Target: "192.0.2.20:80", Title: "Header two", Severity: "INFO", MatchedPath: "/"},
		}}
		wrong := report
		wrong.WorkerID = "other"
		if err := store.CompleteRuntimeTask(ctx, wrong); !errors.Is(err, ErrTaskConflict) {
			t.Fatal("wrong worker accepted", err)
		}
		wrong = report
		wrong.Findings = append([]taskflow.Detection{}, report.Findings...)
		wrong.Findings[0].Target = "192.0.2.20:443"
		if err := store.CompleteRuntimeTask(ctx, wrong); !errors.Is(err, ErrInvalidTask) {
			t.Fatal("skipped target result accepted", err)
		}
		wrong.Findings[0] = report.Findings[0]
		wrong.Findings[0].Engine = "zap"
		if err := store.CompleteRuntimeTask(ctx, wrong); !errors.Is(err, ErrInvalidTask) {
			t.Fatal("wrong engine accepted", err)
		}
		for range 2 {
			if err := store.CompleteRuntimeTask(ctx, report); err != nil {
				t.Fatal(err)
			}
		}
		findings, err := store.ListRuntimeFindings(ctx)
		if err != nil || len(findings) != 2 {
			t.Fatal("dedup or multiple finding failure", findings, err)
		}
		if findings[0].Synthetic || findings[0].BusinessGroup != "QA" {
			t.Fatal(findings[0])
		}
		if iteration == 0 {
			if _, err := store.UpdateFinding(ctx, findings[0].ID, "FALSE_POSITIVE", actor); err != nil {
				t.Fatal(err)
			}
		} else {
			found := false
			for _, f := range findings {
				found = found || f.Status == "FALSE_POSITIVE"
			}
			if !found {
				t.Fatal("repeat scan overwrote review state")
			}
		}
	}
	input.Engine = "zap"
	created, err := store.CreateLocalTask(ctx, input, actor)
	if err != nil {
		t.Fatal(err)
	}
	task, err := store.ClaimRuntimeTask(ctx, "real-worker")
	if err != nil || task.ID != created.ID {
		t.Fatal(task, err)
	}
	if err := store.CompleteRuntimeTask(ctx, taskflow.Report{TaskID: task.ID, WorkerID: "real-worker", Status: "FAILED", Error: "fixture failure"}); err != nil {
		t.Fatal(err)
	}
	tasks, _ := store.ListRuntimeTasks(ctx)
	if tasks[0].Status != "FAILED" || tasks[0].Error != "fixture failure" {
		t.Fatal(tasks[0])
	}
}

func TestAutomaticTaskAllowsOnlySelectedOpenPortsAndStoresSafeSystemStatus(t *testing.T) {
	store, actor := localFixture(t)
	ctx := context.Background()
	bundle, _ := json.Marshal(rules.Bundle{Version: "20261019.01", Engines: []string{"nuclei", "trivy"}, IsCurrent: true, IntegrityVerified: true})
	if _, err := store.db.ExecContext(ctx, "INSERT INTO local_rule_bundles(version,data) VALUES(?,?)", "20261019.01", string(bundle)); err != nil {
		t.Fatal(err)
	}
	var assetID string
	if err := store.db.QueryRowContext(ctx, "SELECT id FROM assets WHERE address=?", "192.0.2.20").Scan(&assetID); err != nil {
		t.Fatal(err)
	}
	input := taskflow.TaskInput{Engine: "auto", AssetID: assetID, Targets: []string{}, PortProbe: portprobe.Config{Preset: "custom", Ranges: []portprobe.Range{{Start: 22, End: 22}, {Start: 80, End: 80}}, OpsApproved: true}}
	task, err := store.CreateLocalTask(ctx, input, actor)
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := store.ClaimRuntimeTask(ctx, "auto-worker")
	if err != nil || claimed == nil || len(claimed.VulnerabilityPorts) != 2 {
		t.Fatalf("auto task claim failed: %+v %v", claimed, err)
	}
	report := taskflow.Report{TaskID: task.ID, WorkerID: "auto-worker", Status: "COMPLETED", SystemScanStatus: taskflow.SystemScanCompleted,
		ApplicationScanStatus: taskflow.ApplicationScanCompleted,
		ApplicationResults:    []taskflow.ApplicationResult{{Alias: "demo", Status: taskflow.ApplicationScanCompleted, SelectedCount: 2, AnalyzedCount: 2}},
		PortProbeResults:      []taskflow.PortProbeResult{{Port: 22}, {Port: 80}},
		ServiceResults:        []taskflow.ServiceResult{{Port: 22, Kind: "OTHER"}, {Port: 80, Kind: "HTTP", Scheme: "http"}},
		Findings: []taskflow.Detection{
			{Engine: "trivy", Target: "192.0.2.20:22", TemplateID: "CVE-2099-0001", Title: "fixture package issue", Severity: "HIGH", Package: "fixture", InstalledVersion: "1.0"},
			{Engine: "nuclei", Target: "192.0.2.20:80", TemplateID: "fixture-header", Title: "fixture web issue", Severity: "LOW", MatchedPath: "/"},
		},
	}
	wrong := report
	wrong.SystemScanStatus = "SSH key=secret"
	if err := store.CompleteRuntimeTask(ctx, wrong); !errors.Is(err, ErrInvalidTask) {
		t.Fatalf("untrusted system scan status accepted: %v", err)
	}
	wrong = report
	wrong.Findings = append([]taskflow.Detection(nil), report.Findings...)
	wrong.Findings[0].Target = "192.0.2.20:23"
	if err := store.CompleteRuntimeTask(ctx, wrong); !errors.Is(err, ErrInvalidTask) {
		t.Fatalf("out-of-scope SSH finding accepted: %v", err)
	}
	if err := store.CompleteRuntimeTask(ctx, report); err != nil {
		t.Fatal(err)
	}
	tasks, err := store.ListRuntimeTasks(ctx)
	if err != nil || len(tasks) != 1 || tasks[0].SystemScanStatus != taskflow.SystemScanCompleted || len(tasks[0].ServiceResults) != 2 || tasks[0].ApplicationScanStatus != taskflow.ApplicationScanCompleted || len(tasks[0].ApplicationResults) != 1 || tasks[0].ApplicationResults[0].AnalyzedCount != 2 {
		t.Fatalf("auto scan status/results not persisted: %+v %v", tasks, err)
	}
	findings, err := store.ListRuntimeFindings(ctx)
	if err != nil || len(findings) != 2 {
		t.Fatalf("auto scan findings not stored: %+v %v", findings, err)
	}
}

func TestAutomaticFailureStatusIsAcceptedAndPersisted(t *testing.T) {
	store, actor := localFixture(t)
	ctx := context.Background()
	bundle, _ := json.Marshal(rules.Bundle{Version: "20261019.01", Engines: []string{"nuclei", "trivy"}, IsCurrent: true, IntegrityVerified: true})
	if _, err := store.db.ExecContext(ctx, "INSERT INTO local_rule_bundles(version,data) VALUES(?,?)", "20261019.01", string(bundle)); err != nil {
		t.Fatal(err)
	}
	var assetID string
	if err := store.db.QueryRowContext(ctx, "SELECT id FROM assets WHERE address=?", "192.0.2.20").Scan(&assetID); err != nil {
		t.Fatal(err)
	}
	input := taskflow.TaskInput{Engine: "auto", AssetID: assetID, Targets: []string{}, PortProbe: portprobe.Config{Preset: "custom", Ranges: []portprobe.Range{{Start: 80, End: 80}}, OpsApproved: true}}
	task, err := store.CreateLocalTask(ctx, input, actor)
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := store.ClaimRuntimeTask(ctx, "auto-worker")
	if err != nil || claimed == nil || claimed.ID != task.ID {
		t.Fatalf("auto task claim failed: %+v %v", claimed, err)
	}
	report := taskflow.Report{TaskID: task.ID, WorkerID: "auto-worker", Status: "FAILED", Error: "应用分析未完成", SystemScanStatus: taskflow.SystemScanCompleted, ApplicationScanStatus: taskflow.ApplicationScanAnalysisFailed,
		ApplicationResults: []taskflow.ApplicationResult{{Alias: "demo", Status: taskflow.ApplicationScanAnalysisFailed, SelectedCount: 2, AnalyzedCount: 1}}}
	missingStatus := report
	missingStatus.SystemScanStatus = ""
	if err := store.CompleteRuntimeTask(ctx, missingStatus); !errors.Is(err, ErrInvalidTask) {
		t.Fatalf("auto failure without system status was accepted: %v", err)
	}
	partial := report
	partial.Findings = []taskflow.Detection{{Engine: "nuclei", Target: "192.0.2.20:80", TemplateID: "fixture-header", Title: "partial finding", Severity: "LOW", MatchedPath: "/"}}
	if err := store.CompleteRuntimeTask(ctx, partial); !errors.Is(err, ErrInvalidTask) {
		t.Fatalf("partial findings in failed report accepted: %v", err)
	}
	if err := store.CompleteRuntimeTask(ctx, report); err != nil {
		t.Fatalf("auto failure report was rejected: %v", err)
	}
	tasks, err := store.ListRuntimeTasks(ctx)
	if err != nil || len(tasks) != 1 || tasks[0].Status != "FAILED" || tasks[0].SystemScanStatus != taskflow.SystemScanCompleted || tasks[0].ApplicationScanStatus != taskflow.ApplicationScanAnalysisFailed || len(tasks[0].ApplicationResults) != 1 || tasks[0].ApplicationResults[0].AnalyzedCount != 1 || tasks[0].Error != report.Error {
		t.Fatalf("failed automatic status was not persisted: %+v %v", tasks, err)
	}
	findings, err := store.ListRuntimeFindings(ctx)
	if err != nil || len(findings) != 0 {
		t.Fatalf("failed task stored partial findings: %+v %v", findings, err)
	}
}

func TestTrivyInputAndZeroFindingsCompletion(t *testing.T) {
	store, actor := localFixture(t)
	ctx := context.Background()
	data, _ := json.Marshal(rules.Bundle{Version: "20261016.01", Engines: []string{"trivy"}, IsCurrent: true, IntegrityVerified: true})
	if _, err := store.db.ExecContext(ctx, "INSERT INTO local_rule_bundles(version,data) VALUES(?,?)", "20261016.01", string(data)); err != nil {
		t.Fatal(err)
	}
	input := taskflow.TaskInput{Engine: "trivy", InputKind: "filesystem", InputPath: "deps/local-fixture"}
	for _, path := range []string{"../outside", "/absolute", "https://example.com", "C:\\secret"} {
		bad := input
		bad.InputPath = path
		if _, err := store.CreateLocalTask(ctx, bad, actor); !errors.Is(err, ErrInvalidTask) {
			t.Fatal(path, err)
		}
	}
	if _, err := store.CreateLocalTask(ctx, input, actor); err != nil {
		t.Fatal(err)
	}
	task, err := store.ClaimRuntimeTask(ctx, "worker")
	if err != nil || task == nil || task.InputPath != input.InputPath {
		t.Fatal(task, err)
	}
	if err := store.CompleteRuntimeTask(ctx, taskflow.Report{TaskID: task.ID, WorkerID: "worker", Status: "COMPLETED"}); err != nil {
		t.Fatal(err)
	}
	findings, _ := store.ListRuntimeFindings(ctx)
	if len(findings) != 0 {
		t.Fatal("zero findings manufactured a finding")
	}
}

func TestImageFingerprintUsesImageIdentityAcrossArchiveNames(t *testing.T) {
	store, actor := localFixture(t)
	ctx := context.Background()
	data, _ := json.Marshal(rules.Bundle{Version: "20261016.01", Engines: []string{"trivy"}, IsCurrent: true, IntegrityVerified: true})
	if _, err := store.db.ExecContext(ctx, "INSERT INTO local_rule_bundles(version,data) VALUES(?,?)", "20261016.01", string(data)); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"images/first.tar", "images/renamed.tar"} {
		if _, err := store.CreateLocalTask(ctx, taskflow.TaskInput{Engine: "trivy", InputKind: "image-archive", InputPath: path}, actor); err != nil {
			t.Fatal(err)
		}
		task, err := store.ClaimRuntimeTask(ctx, "worker")
		if err != nil || task == nil {
			t.Fatal(task, err)
		}
		report := taskflow.Report{TaskID: task.ID, WorkerID: "worker", Status: "COMPLETED", Findings: []taskflow.Detection{{Engine: "trivy", Target: path, TemplateID: "CVE-2099-0001", Title: "fixture", Severity: "HIGH", Package: "fixture", InstalledVersion: "1.0", MatchedPath: path, ArtifactID: "sha256:0000000000000000000000000000000000000000000000000000000000000001"}}}
		if err := store.CompleteRuntimeTask(ctx, report); err != nil {
			t.Fatal(err)
		}
	}
	findings, err := store.ListRuntimeFindings(ctx)
	if err != nil || len(findings) != 1 {
		t.Fatalf("image duplicated after rename: %+v %v", findings, err)
	}
}

func TestRootfsTaskDedupUsesStableHostAndPackage(t *testing.T) {
	store, actor := localFixture(t)
	ctx := context.Background()
	data, _ := json.Marshal(rules.Bundle{Version: "20261019.01", Engines: []string{"trivy"}, IsCurrent: true, IntegrityVerified: true})
	if _, err := store.db.ExecContext(ctx, "INSERT INTO local_rule_bundles(version,data) VALUES(?,?)", "20261019.01", string(data)); err != nil {
		t.Fatal(err)
	}
	for iteration, path := range []string{"lab-a/os", "lab-a/os", "lab-b/os"} {
		input := taskflow.TaskInput{Engine: "trivy", InputKind: "rootfs", InputPath: path}
		if _, err := store.CreateLocalTask(ctx, input, actor); err != nil {
			t.Fatal(err)
		}
		task, err := store.ClaimRuntimeTask(ctx, "worker")
		if err != nil || task == nil || task.InputKind != "rootfs" {
			t.Fatal(task, err)
		}
		if err := store.CompleteRuntimeTask(ctx, taskflow.Report{TaskID: task.ID, WorkerID: "worker", Status: "COMPLETED", Findings: []taskflow.Detection{{Engine: "trivy", Target: path, TemplateID: "CVE-2099-0001", Title: "fixture", Severity: "HIGH", Package: "fixture", InstalledVersion: "1.0", MatchedPath: time.Now().String()}}}); err != nil {
			t.Fatal(err)
		}
		findings, err := store.ListRuntimeFindings(ctx)
		expected := 1
		if iteration == 2 {
			expected = 2
		}
		if err != nil || len(findings) != expected {
			t.Fatalf("host/package dedup failed: %d results: %v", len(findings), err)
		}
	}
	for _, input := range []taskflow.TaskInput{
		{Engine: "trivy", InputKind: "rootfs", InputPath: "../outside"},
		{Engine: "trivy", InputKind: "rootfs", InputPath: "lab-a/os", Targets: []string{"192.0.2.10:80"}},
		{Engine: "trivy", InputKind: "rootfs", InputPath: "lab-a/os", Scheme: "http"},
	} {
		if _, err := store.CreateLocalTask(ctx, input, actor); !errors.Is(err, ErrInvalidTask) {
			t.Fatal("invalid rootfs input accepted", err)
		}
	}
}

func TestLateEngineCompletionPausesWithoutFinding(t *testing.T) {
	store, actor := localFixture(t)
	ctx := context.Background()
	approveFixturePort(t, store, actor, "192.0.2.20", 80)
	created, err := store.CreateLocalTask(ctx, taskflow.TaskInput{Engine: "zap", Scheme: "http", Targets: []string{"192.0.2.20:80"}}, actor)
	if err != nil {
		t.Fatal(err)
	}
	task, err := store.ClaimRuntimeTask(ctx, "worker")
	if err != nil || task.ID != created.ID {
		t.Fatal(task, err)
	}
	if _, err := store.db.ExecContext(ctx, `UPDATE scan_tasks SET details=json_set(details,'$.deadline',?) WHERE id=?`, time.Now().Add(-time.Second).Format(time.RFC3339Nano), task.ID); err != nil {
		t.Fatal(err)
	}
	if err := store.CompleteRuntimeTask(ctx, taskflow.Report{TaskID: task.ID, WorkerID: "worker", Status: "COMPLETED"}); !errors.Is(err, ErrTaskConflict) {
		t.Fatal(err)
	}
	tasks, _ := store.ListRuntimeTasks(ctx)
	if tasks[0].Status != "PAUSED_WINDOW" {
		t.Fatal(tasks[0])
	}
	findings, _ := store.ListRuntimeFindings(ctx)
	if len(findings) != 0 {
		t.Fatal("late result persisted")
	}
}

func TestLegacySingleFindingSchemaKeepsStoredRows(t *testing.T) {
	store, _ := localFixture(t)
	ctx := context.Background()
	if _, err := store.CreateSyntheticTask(ctx); err != nil {
		t.Fatal(err)
	}
	task, err := store.ClaimRuntimeTask(ctx, "worker")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CompleteRuntimeTask(ctx, taskflow.Report{TaskID: task.ID, WorkerID: "worker", Target: task.Chunks[0].Targets[0], Title: taskflow.SyntheticTitle}); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{`CREATE TABLE early_findings(id TEXT PRIMARY KEY,task_id TEXT NOT NULL UNIQUE REFERENCES scan_tasks(id),data TEXT NOT NULL)`, `INSERT INTO early_findings SELECT * FROM security_findings`, `DROP TABLE security_findings`, `ALTER TABLE early_findings RENAME TO security_findings`} {
		if _, err := store.db.ExecContext(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := NewRuntime(store.db); err != nil {
		t.Fatal(err)
	}
	findings, err := store.ListRuntimeFindings(ctx)
	if err != nil || len(findings) != 1 || !findings[0].Synthetic || findings[0].TaskID != task.ID {
		t.Fatal(findings, err)
	}
}
