package repo

import (
	"context"
	"encoding/json"
	"errors"
	"scanner-platform/internal/assets"
	"scanner-platform/internal/findings"
	"scanner-platform/internal/inventory"
	"scanner-platform/internal/portprobe"
	"scanner-platform/internal/rules"
	"scanner-platform/internal/taskflow"
	"testing"
)

func TestSystemSettingsDefaultsValidationPersistenceAndAudit(t *testing.T) {
	store, actor := localFixture(t)
	ctx := context.Background()

	settings, err := store.GetSystemSettings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if settings != (SystemSettings{TimeZone: "Asia/Shanghai", SessionDurationMinutes: 480}) {
		t.Fatalf("unexpected defaults: %+v", settings)
	}
	if _, err := store.SaveSystemSettings(ctx, SystemSettings{TimeZone: "Mars/Phobos", SessionDurationMinutes: 480}, actor); !errors.Is(err, ErrInvalidTask) {
		t.Fatalf("invalid timezone accepted: %v", err)
	}
	if _, err := store.SaveSystemSettings(ctx, SystemSettings{TimeZone: "UTC", SessionDurationMinutes: 29}, actor); !errors.Is(err, ErrInvalidTask) {
		t.Fatalf("invalid session duration accepted: %v", err)
	}
	saved, err := store.SaveSystemSettings(ctx, SystemSettings{TimeZone: "UTC", SessionDurationMinutes: 90}, actor)
	if err != nil || saved.TimeZone != "UTC" || saved.SessionDurationMinutes != 90 {
		t.Fatalf("save settings: %+v %v", saved, err)
	}
	loaded, err := store.GetSystemSettings(ctx)
	if err != nil || loaded != saved {
		t.Fatalf("load settings: %+v %v", loaded, err)
	}
	var count int
	if err := store.db.QueryRowContext(ctx, "SELECT count(*) FROM audit_logs WHERE actor=? AND action='update_system_settings'", actor).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("settings audit count=%d", count)
	}
}

func TestProductInventoryKnowledgeAndTaskObservationRemainHistorical(t *testing.T) {
	store, actor := localFixture(t)
	ctx := context.Background()
	var assetID string
	if err := store.db.QueryRowContext(ctx, "SELECT id FROM assets WHERE address=?", "192.0.2.20").Scan(&assetID); err != nil {
		t.Fatal(err)
	}
	score := 7.9
	_, err := store.SaveKnowledge(ctx, findings.KnowledgeEntry{ID: "EXAMPLE-001", Title: "示例组件风险", Description: "版本推断示例", Component: "nginx", Source: "示例公开公告摘要", CVSSScore: &score, AffectedRanges: []findings.VersionRange{{Introduced: "1.0", Fixed: "2.0"}}, Language: "zh-CN", Solution: "升级至2.0"}, actor)
	if err != nil {
		t.Fatal(err)
	}
	bundle, _ := json.Marshal(rules.Bundle{Version: "20261019.01", Engines: []string{"nuclei", "trivy"}, IsCurrent: true, IntegrityVerified: true})
	if _, err = store.db.ExecContext(ctx, "INSERT INTO local_rule_bundles(version,data) VALUES(?,?)", "20261019.01", string(bundle)); err != nil {
		t.Fatal(err)
	}
	var firstTask string
	for i := 0; i < 2; i++ {
		task, err := store.CreateLocalTask(ctx, taskflow.TaskInput{Engine: "auto", AssetID: assetID, PortProbe: portprobe.Config{Preset: "custom", Ranges: []portprobe.Range{{Start: 80, End: 80}}, OpsApproved: true}}, actor)
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			firstTask = task.ID
		}
		if claimed, err := store.ClaimRuntimeTask(ctx, "example-worker"); err != nil || claimed == nil {
			t.Fatal(claimed, err)
		}
		report := taskflow.Report{TaskID: task.ID, WorkerID: "example-worker", Status: "COMPLETED", SystemScanStatus: taskflow.SystemScanNotConfigured, PortProbeResults: []taskflow.PortProbeResult{{Port: 80}}, ServiceResults: []taskflow.ServiceResult{{Port: 80, Kind: "HTTP", Scheme: "http", Software: "nginx", Version: "1.5", Title: "示例网站", LoginEntries: []inventory.LoginEntry{{Type: "web", Port: 80, Name: "示例登录", URL: "http://192.0.2.20:80/login"}}}}, AssetProfile: inventory.Profile{OSName: "Example Linux", OSFamily: "linux"}}
		if err = store.CompleteRuntimeTask(ctx, report); err != nil {
			t.Fatal(err)
		}
	}
	observations, err := store.ListTaskFindings(ctx, firstTask)
	if err != nil || len(observations) != 1 || observations[0].TaskID != firstTask || observations[0].BusinessGroup != "QA" || observations[0].DetectMethod != "version" || observations[0].Solution != "升级至2.0" {
		t.Fatalf("historical observation: count=%d err=%v", len(observations), err)
	}
	list, err := assets.ListSnapshot(ctx, store.db)
	if err != nil || len(list) != 1 || len(list[0].Services) != 1 || len(list[0].LoginEntries) != 1 || list[0].OSName != "Example Linux" {
		t.Fatalf("inventory not persisted: %+v %v", list, err)
	}
	latest, _ := store.ListRuntimeFindings(ctx)
	if len(latest) != 1 || latest[0].AssetID != assetID {
		t.Fatal("latest dedup or ownership lost")
	}
}
func TestSystemAndAssetExclusionsAndRegisteredPolicy(t *testing.T) {
	store, actor := localFixture(t)
	ctx := context.Background()
	var assetID string
	_ = store.db.QueryRowContext(ctx, "SELECT id FROM assets LIMIT 1").Scan(&assetID)
	p := defaultPolicy()
	p.Exclusions = []portprobe.Range{{Start: 80, End: 80}}
	if _, err := store.SaveScanPolicy(ctx, p, actor); err != nil {
		t.Fatal(err)
	}
	task, err := store.CreateLocalTask(ctx, taskflow.TaskInput{Engine: "port-probe", AssetID: assetID, PortProbe: portprobe.Config{Preset: "custom", Ranges: []portprobe.Range{{Start: 79, End: 81}, {Start: 443, End: 443}}, OpsApproved: true}}, actor)
	if err != nil || len(task.PortProbePorts) != 2 || len(task.EffectiveExclusions) != 2 {
		t.Fatalf("exclusion union failed: %+v %v", task, err)
	}
	if len(task.PortProbePorts) == 2 && (task.PortProbePorts[0] != 79 || task.PortProbePorts[1] != 81) {
		t.Fatal(task.PortProbePorts)
	}
	if _, err = store.db.ExecContext(ctx, `INSERT INTO asset_services(asset_id,port,data) VALUES(?,8080,'{"port":8080,"kind":"OTHER"}')`, assetID); err != nil {
		t.Fatal(err)
	}
	task, err = store.CreateLocalTask(ctx, taskflow.TaskInput{Engine: "port-probe", AssetID: assetID, PortProbe: portprobe.Config{Preset: "registered", OpsApproved: true}}, actor)
	if err != nil || len(task.PortProbePorts) != 1 || task.PortProbePorts[0] != 8080 {
		t.Fatalf("registered inventory ports: %+v %v", task, err)
	}
}

func TestInventoryRejectsCrossHostEvidenceAndStopsQuarantinedFindings(t *testing.T) {
	task := taskflow.Task{Engines: []string{"auto"}, Chunks: []taskflow.Chunk{{Targets: []string{"192.0.2.20"}}}, VulnerabilityPorts: []int{80}}
	open := []taskflow.PortProbeResult{{Port: 80}}
	for _, raw := range []string{"http://192.0.2.21:80/", "http://example.org:80/", "http://user:password@192.0.2.20/", "http://192.0.2.20:81/"} {
		if validServiceResults([]taskflow.ServiceResult{{Port: 80, Kind: "HTTP", Scheme: "http", URL: raw}}, task, open) {
			t.Fatal("out-of-scope service URL accepted")
		}
	}
	if !validServiceResults([]taskflow.ServiceResult{{Port: 80, Kind: "HTTP", Scheme: "http", URL: "http://192.0.2.20:80/"}}, task, open) {
		t.Fatal("scoped URL rejected")
	}
}
func TestClosedPreviouslyObservedPortDoesNotStayOpen(t *testing.T) {
	store, _ := localFixture(t)
	ctx := context.Background()
	var id string
	_ = store.db.QueryRowContext(ctx, "SELECT id FROM assets LIMIT 1").Scan(&id)
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	task := taskflow.Task{AssetID: id, PortProbePorts: []int{80}}
	report := taskflow.Report{PortProbeResults: []taskflow.PortProbeResult{{Port: 80}}, ServiceResults: []taskflow.ServiceResult{{Port: 80, Kind: "HTTP", Scheme: "http"}}}
	if err = recordInventory(ctx, tx, task, report); err != nil {
		t.Fatal(err)
	}
	if err = recordInventory(ctx, tx, task, taskflow.Report{}); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	list, err := assets.ListSnapshot(ctx, store.db)
	if err != nil || len(list[0].Services) != 1 || list[0].Services[0].State != "closed" {
		t.Fatalf("closed port remained open: %+v %v", list, err)
	}
}
