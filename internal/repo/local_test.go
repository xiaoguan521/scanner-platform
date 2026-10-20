package repo

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"scanner-platform/internal/account"
	"scanner-platform/internal/assets"
	"scanner-platform/internal/portprobe"
	"scanner-platform/internal/scheduler"
	"scanner-platform/internal/taskflow"
)

func localFixture(t *testing.T) (*RuntimeStore, string) {
	t.Helper()
	ctx := context.Background()
	accounts, err := account.New(filepath.Join(t.TempDir(), "local.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { accounts.Close() })
	if err := accounts.InitAdmin(ctx, "localadmin", "Local-Test-Password-2026"); err != nil {
		t.Fatal(err)
	}
	admin, _, err := accounts.Authenticate(ctx, "localadmin", "Local-Test-Password-2026")
	if err != nil {
		t.Fatal(err)
	}
	registry, err := assets.New(accounts.SQLDB())
	if err != nil {
		t.Fatal(err)
	}
	_, err = registry.Create(ctx, admin.ID, assets.Input{Kind: "host", Address: "192.0.2.20", BusinessGroup: "QA", Owner: "Example", RequestedPorts: []int{80, 443}, SkippedPorts: []int{443}})
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewRuntime(accounts.SQLDB())
	if err != nil {
		t.Fatal(err)
	}
	return store, admin.ID
}
func TestLocalTargetsSchedulesAndCancellation(t *testing.T) {
	store, actor := localFixture(t)
	ctx := context.Background()
	input := taskflow.TaskInput{Synthetic: true, Targets: []string{"192.0.2.20:80", "192.0.2.20:443"}}
	task, err := store.CreateLocalTask(ctx, input, actor)
	if err != nil {
		t.Fatal(err)
	}
	if task.TargetCount != 1 || len(task.SkippedTargets) != 1 || task.Chunks[0].Targets[0] != "192.0.2.20:80" {
		t.Fatalf("skip failed %+v", task)
	}
	for _, targets := range [][]string{{"192.0.2.21:80"}, {"192.0.2.20:81"}, {"example.com:80"}, {"192.0.2.0/24:80"}, {"192.0.2.20:443"}, {"192.0.2.20:80", "192.0.2.20:080"}} {
		bad := input
		bad.Targets = targets
		if _, err := store.CreateLocalTask(ctx, bad, actor); !errors.Is(err, ErrInvalidTask) {
			t.Fatalf("invalid targets accepted %v: %v", targets, err)
		}
	}
	if err := store.CancelTask(ctx, task.ID, actor); err != nil {
		t.Fatal(err)
	}
	if task, err := store.ClaimRuntimeTask(ctx, "test-worker"); err != nil || task != nil {
		t.Fatalf("canceled task claimed: %+v %v", task, err)
	}
	due := time.Now().Add(time.Minute).Truncate(time.Second)
	schedule, err := store.SaveSchedule(ctx, taskflow.Schedule{Name: "Every minute", TaskInput: input, NextRun: due.Format(time.RFC3339), IntervalMinutes: 1}, actor)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := store.Tick(ctx, due); err != nil {
			t.Fatal(err)
		}
	}
	tasks, err := store.ListRuntimeTasks(ctx)
	if err != nil || len(tasks) != 2 {
		t.Fatalf("duplicated trigger %d %v", len(tasks), err)
	}
	if err := store.Tick(ctx, due.Add(10*time.Minute)); err != nil {
		t.Fatal(err)
	}
	tasks, err = store.ListRuntimeTasks(ctx)
	if err != nil || len(tasks) != 3 {
		t.Fatalf("missed ticks replayed %d %v", len(tasks), err)
	}
	runs, total, err := store.ListScheduleRuns(ctx, schedule.ID, 10, 0)
	if err != nil || total != 2 || len(runs) != 2 {
		t.Fatalf("schedule run history missing: total=%d runs=%+v err=%v", total, runs, err)
	}
	for _, run := range runs {
		if run.ScheduleID != schedule.ID || run.TaskID == "" || run.Status != "PENDING" || run.Error != "" {
			t.Fatalf("unexpected schedule run projection: %+v", run)
		}
	}
	if err := store.ToggleSchedule(ctx, schedule.ID, actor, false); err != nil {
		t.Fatal(err)
	}
	updated, err := store.UpdateSchedule(ctx, schedule.ID, taskflow.Schedule{
		Name: "Updated schedule", TaskInput: input,
		NextRun: due.Add(time.Hour).Format(time.RFC3339), IntervalMinutes: 30,
	}, actor)
	if err != nil || updated.ID != schedule.ID || updated.Name != "Updated schedule" || updated.Enabled {
		t.Fatalf("schedule update=%+v err=%v", updated, err)
	}
	if err := store.DeleteSchedule(ctx, schedule.ID, actor); err != nil {
		t.Fatal(err)
	}
	if items, err := store.ListSchedules(ctx); err != nil || len(items) != 0 {
		t.Fatalf("schedule delete left records: %+v err=%v", items, err)
	}
	runs, total, err = store.ListScheduleRuns(ctx, schedule.ID, 1, 1)
	if err != nil || total != 2 || len(runs) != 1 || runs[0].Status != "PENDING" {
		t.Fatalf("schedule history was not retained or paginated: total=%d runs=%+v err=%v", total, runs, err)
	}
	if err := store.Tick(ctx, due.Add(20*time.Minute)); err != nil {
		t.Fatal(err)
	}
	tasks, _ = store.ListRuntimeTasks(ctx)
	if len(tasks) != 3 {
		t.Fatal("disabled schedule triggered")
	}
}

func TestManualPauseAndResumeIsPersistentAcrossWindowTicks(t *testing.T) {
	store, actor := localFixture(t)
	ctx := context.Background()
	task, err := store.CreateLocalTask(ctx, taskflow.TaskInput{Synthetic: true, Targets: []string{"192.0.2.20:80"}}, actor)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.PauseTask(ctx, task.ID, actor); err != nil {
		t.Fatal(err)
	}
	items, err := store.ListRuntimeTasks(ctx)
	if err != nil || len(items) != 1 || items[0].Status != "PAUSED" {
		t.Fatalf("task was not manually paused: %+v err=%v", items, err)
	}
	if err := store.Tick(ctx, time.Now().Add(24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	items, _ = store.ListRuntimeTasks(ctx)
	if items[0].Status != "PAUSED" {
		t.Fatalf("window tick silently resumed manual pause: %+v", items[0])
	}
	if err := store.ResumeTask(ctx, task.ID, actor); err != nil {
		t.Fatal(err)
	}
	items, _ = store.ListRuntimeTasks(ctx)
	if items[0].Status != "PENDING" {
		t.Fatalf("manual resume did not return task to queue: %+v", items[0])
	}
	if err := store.ResumeTask(ctx, task.ID, actor); err != nil {
		t.Fatalf("idempotent resume failed: %v", err)
	}
	if err := store.CancelTask(ctx, task.ID, actor); err != nil {
		t.Fatal(err)
	}
}

func TestScheduleInvalidTriggerIsRecordedAndStopsOneShot(t *testing.T) {
	store, actor := localFixture(t)
	ctx := context.Background()
	due := time.Now().Add(time.Minute).Truncate(time.Second)
	schedule, err := store.SaveSchedule(ctx, taskflow.Schedule{
		Name:      "Invalid trigger",
		TaskInput: taskflow.TaskInput{Synthetic: true, Targets: []string{"192.0.2.20:80"}},
		NextRun:   due.Format(time.RFC3339),
	}, actor)
	if err != nil {
		t.Fatal(err)
	}
	var raw string
	if err := store.db.QueryRowContext(ctx, "SELECT data FROM task_schedules WHERE id=?", schedule.ID).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var tampered taskflow.Schedule
	if err := json.Unmarshal([]byte(raw), &tampered); err != nil {
		t.Fatal(err)
	}
	tampered.Engine = "nuclei"
	encoded, err := json.Marshal(tampered)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, "UPDATE task_schedules SET data=? WHERE id=?", string(encoded), schedule.ID); err != nil {
		t.Fatal(err)
	}
	if err := store.Tick(ctx, due); err != nil {
		t.Fatal(err)
	}
	runs, total, err := store.ListScheduleRuns(ctx, schedule.ID, 10, 0)
	if err != nil || total != 1 || len(runs) != 1 || runs[0].Status != "FAILED" || runs[0].TaskID != "" || runs[0].Error == "" {
		t.Fatalf("invalid trigger history missing: total=%d runs=%+v err=%v", total, runs, err)
	}
	items, err := store.ListSchedules(ctx)
	if err != nil || len(items) != 1 || items[0].Enabled || items[0].LastError == "" {
		t.Fatalf("invalid schedule was not disabled with error: items=%+v err=%v", items, err)
	}
}

func TestPortProbeIsBoundedToOneRegisteredAssetAndStoresCandidates(t *testing.T) {
	store, actor := localFixture(t)
	ctx := context.Background()
	var assetID string
	if err := store.db.QueryRowContext(ctx, "SELECT id FROM assets WHERE address=?", "192.0.2.20").Scan(&assetID); err != nil {
		t.Fatal(err)
	}
	input := taskflow.TaskInput{
		Engine: "port-probe", AssetID: assetID, Targets: []string{},
		PortProbe: portprobe.Config{Preset: portprobe.PresetCommon, Exclusions: []portprobe.Range{{Start: 80, End: 81}}, OpsApproved: true},
	}
	task, err := store.CreateLocalTask(ctx, input, actor)
	if err != nil {
		t.Fatal(err)
	}
	if task.Synthetic || task.AssetID != assetID || task.TargetCount != 1 || len(task.Chunks[0].Targets) != 1 || task.Chunks[0].Targets[0] != "192.0.2.20" {
		t.Fatalf("probe escaped its single registered asset: %+v", task)
	}
	if len(task.PortProbePorts) != len(portprobe.CommonPorts())-2 {
		t.Fatalf("wrong effective port count: %d (%v)", len(task.PortProbePorts), task.PortProbePorts)
	}
	for _, excluded := range []int{80, 81, 443} {
		for _, port := range task.PortProbePorts {
			if port == excluded {
				t.Fatalf("excluded port %d included in task", excluded)
			}
		}
	}
	if _, err := store.CreateLocalTask(ctx, taskflow.TaskInput{Engine: "port-probe", AssetID: assetID, PortProbe: portprobe.Config{Preset: portprobe.PresetCommon}}, actor); !errors.Is(err, ErrInvalidTask) {
		t.Fatalf("probe without operation acknowledgement accepted: %v", err)
	}
	if _, err := store.CreateLocalTask(ctx, taskflow.TaskInput{Engine: "port-probe", AssetID: "missing-asset", PortProbe: portprobe.Config{Preset: portprobe.PresetCommon, OpsApproved: true}}, actor); !errors.Is(err, ErrInvalidTask) {
		t.Fatalf("unregistered asset probe accepted: %v", err)
	}
	if _, err := store.SaveSchedule(ctx, taskflow.Schedule{Name: "probe", TaskInput: input, NextRun: time.Now().Add(time.Hour).UTC().Format(time.RFC3339), IntervalMinutes: 0}, actor); !errors.Is(err, ErrInvalidTask) {
		t.Fatalf("scheduled port probe accepted: %v", err)
	}
	if _, err := store.CreateLocalTask(ctx, taskflow.TaskInput{Engine: "nuclei", Scheme: "http", Targets: []string{"192.0.2.20:80"}}, actor); !errors.Is(err, ErrInvalidTask) {
		t.Fatalf("unapproved port accepted for vulnerability scan: %v", err)
	}
	claimed, err := store.ClaimRuntimeTask(ctx, "probe-worker")
	if err != nil || claimed == nil || claimed.AssetID != assetID || len(claimed.PortProbePorts) != len(task.PortProbePorts) {
		t.Fatalf("probe task claim failed: task=%+v err=%v", claimed, err)
	}
	if err := store.CompleteRuntimeTask(ctx, taskflow.Report{TaskID: task.ID, WorkerID: "probe-worker", Status: "COMPLETED", PortProbeResults: []taskflow.PortProbeResult{{Port: 443}}}); !errors.Is(err, ErrInvalidTask) {
		t.Fatalf("report included skipped port: %v", err)
	}
	if err := store.CompleteRuntimeTask(ctx, taskflow.Report{TaskID: task.ID, WorkerID: "probe-worker", Status: "COMPLETED", PortProbeResults: []taskflow.PortProbeResult{{Port: 22}}}); err != nil {
		t.Fatal(err)
	}
	tasks, err := store.ListRuntimeTasks(ctx)
	if err != nil || len(tasks) == 0 || tasks[0].Status != "COMPLETED" || len(tasks[0].PortProbeResults) != 1 || tasks[0].PortProbeResults[0].Port != 22 {
		t.Fatalf("port probe result not persisted: %+v err=%v", tasks, err)
	}
}

func TestPortProbeAppliesManyAutomaticExclusionsWithoutChangingUserConfig(t *testing.T) {
	store, actor := localFixture(t)
	ctx := context.Background()
	var assetID string
	if err := store.db.QueryRowContext(ctx, "SELECT id FROM assets WHERE address=?", "192.0.2.20").Scan(&assetID); err != nil {
		t.Fatal(err)
	}
	for port := 1000; port < 1140; port++ {
		if _, err := store.db.ExecContext(ctx, `INSERT INTO port_quarantine(asset_id,port,reason,detected_at,status)
VALUES(?,?,?,?,'ACTIVE')`, assetID, port, "fixture", time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
			t.Fatal(err)
		}
	}
	config := portprobe.Config{Preset: portprobe.PresetCustom, Ranges: []portprobe.Range{{Start: 1000, End: 1200}}, OpsApproved: true}
	task, err := store.CreateLocalTask(ctx, taskflow.TaskInput{Engine: "port-probe", AssetID: assetID, PortProbe: config}, actor)
	if err != nil {
		t.Fatal(err)
	}
	if len(task.PortProbePorts) != 61 || len(task.SkippedTargets) != 140 {
		t.Fatalf("automatic quarantine exclusions were not applied: ports=%d skipped=%d", len(task.PortProbePorts), len(task.SkippedTargets))
	}
	if len(task.PortProbeConfig.Exclusions) != 0 {
		t.Fatalf("automatic exclusions changed the user plan: %+v", task.PortProbeConfig.Exclusions)
	}
	for _, port := range task.PortProbePorts {
		if port < 1140 || port > 1200 {
			t.Fatalf("quarantined port %d remains in the effective plan", port)
		}
	}
}

func TestWindowWaitPauseResumeAndNoFalseSuccess(t *testing.T) {
	store, actor := localFixture(t)
	ctx := context.Background()
	now := time.Now().UTC()
	input := taskflow.TaskInput{Synthetic: true, Targets: []string{"192.0.2.20:80"}, TimeWindows: []scheduler.Window{{Weekdays: []int{(int(now.Weekday()) + 1) % 7}, Start: "00:00", End: "24:00", TimeZone: "UTC"}}}
	task, err := store.CreateLocalTask(ctx, input, actor)
	if err != nil || task.Status != "WAITING_WINDOW" {
		t.Fatalf("outside window %+v %v", task, err)
	}
	if claimed, err := store.ClaimRuntimeTask(ctx, "worker"); err != nil || claimed != nil {
		t.Fatalf("outside task dispatched %+v %v", claimed, err)
	}
	if err := store.Tick(ctx, now.Add(24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	tasks, _ := store.ListRuntimeTasks(ctx)
	if tasks[0].Status != "PENDING" {
		t.Fatal("window did not resume")
	}
	// Simulate the next window using a past hard deadline, without waiting a day.
	detail := taskDetails{Input: taskflow.TaskInput{Synthetic: true}, Deadline: time.Now().Add(-time.Second).UTC().Format(time.RFC3339Nano)}
	data, _ := json.Marshal(detail)
	if _, err := store.db.ExecContext(ctx, "UPDATE scan_tasks SET status='RUNNING',worker_id='worker',details=? WHERE id=?", string(data), task.ID); err != nil {
		t.Fatal(err)
	}
	err = store.CompleteRuntimeTask(ctx, taskflow.Report{TaskID: task.ID, WorkerID: "worker", Target: "192.0.2.20:80", Title: taskflow.SyntheticTitle})
	if !errors.Is(err, ErrTaskConflict) {
		t.Fatalf("expired task completed: %v", err)
	}
	findings, _ := store.ListRuntimeFindings(ctx)
	if len(findings) != 0 {
		t.Fatal("expired task inserted a finding")
	}
	tasks, _ = store.ListRuntimeTasks(ctx)
	if tasks[0].Status != "PAUSED_WINDOW" {
		t.Fatalf("expired task not paused: %+v", tasks[0])
	}
}
func TestLegacyRuntimeAssetTableIsPreserved(t *testing.T) {
	accounts, err := account.New(filepath.Join(t.TempDir(), "legacy.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer accounts.Close()
	for _, q := range []string{`CREATE TABLE assets(id TEXT PRIMARY KEY,address TEXT,created_at TEXT,data TEXT)`, `INSERT INTO assets VALUES('old','192.0.2.1','','{}')`} {
		if _, err := accounts.SQLDB().Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	store, err := NewRuntime(accounts.SQLDB())
	if err != nil {
		t.Fatal(err)
	}
	var count int
	if err := store.db.QueryRow("SELECT count(*) FROM assets_legacy_runtime").Scan(&count); err != nil || count != 1 {
		t.Fatalf("legacy data lost: %d %v", count, err)
	}
	registry, err := assets.New(accounts.SQLDB())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := registry.List(context.Background()); err != nil {
		t.Fatalf("unified assets unavailable: %v", err)
	}
}

func TestNewSkipBeforeClaimCannotBeDispatched(t *testing.T) {
	store, actor := localFixture(t)
	ctx := context.Background()
	task, err := store.CreateLocalTask(ctx, taskflow.TaskInput{Synthetic: true, Targets: []string{"192.0.2.20:80"}}, actor)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, `INSERT INTO asset_ports(asset_id,port,kind,source) SELECT id,80,'EXCLUDED_PROXY','manual_skip' FROM assets WHERE address='192.0.2.20'`); err != nil {
		t.Fatal(err)
	}
	if claimed, err := store.ClaimRuntimeTask(ctx, "worker"); err != nil || claimed != nil {
		t.Fatalf("newly skipped target dispatched %+v %v", claimed, err)
	}
	tasks, err := store.ListRuntimeTasks(ctx)
	if err != nil || tasks[0].ID != task.ID || tasks[0].Status != "CANCELED" {
		t.Fatalf("changed task not canceled %+v %v", tasks, err)
	}
}
