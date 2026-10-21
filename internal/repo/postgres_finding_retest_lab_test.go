//go:build lab

package repo

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"scanner-platform/internal/portprobe"
	"scanner-platform/internal/taskflow"
)

func TestPostgresFindingRetestLab(t *testing.T) {
	dsnFile := os.Getenv("POSTGRES_DSN_FILE")
	if dsnFile == "" {
		t.Skip("set POSTGRES_DSN_FILE to an isolated PostgreSQL fixture")
	}
	ctx := context.Background()
	dsn, err := ReadPostgresDSNFile(filepath.Clean(dsnFile))
	if err != nil {
		t.Fatal(err)
	}
	db, err := OpenPostgres(ctx, PostgresConfig{DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := MigratePostgres(ctx, db); err != nil {
		t.Fatal(err)
	}
	const (
		actorID  = "lab-pg-retest-admin"
		engineer = "lab-pg-retest-engineer"
		assetID  = "lab-pg-retest-asset"
		scopeID  = "lab-pg-retest-scope"
		parentID = "lab-pg-retest-parent"
		finding  = "lab-pg-retest-finding"
		rule     = "20261021.120000"
	)
	childID := ""
	cleanup := func() {
		if childID != "" {
			_, _ = db.ExecContext(ctx, `DELETE FROM finding_retests WHERE task_id=$1`, childID)
			_, _ = db.ExecContext(ctx, `DELETE FROM scan_task_projections WHERE task_id=$1`, childID)
			_, _ = db.ExecContext(ctx, `DELETE FROM scan_task_chunks WHERE task_id=$1`, childID)
			_, _ = db.ExecContext(ctx, `DELETE FROM scan_tasks WHERE id=$1`, childID)
		}
		_, _ = db.ExecContext(ctx, `DELETE FROM audit_logs WHERE object_id=$1`, finding)
		_, _ = db.ExecContext(ctx, `DELETE FROM finding_retests WHERE finding_id=$1`, finding)
		_, _ = db.ExecContext(ctx, `DELETE FROM finding_projections WHERE finding_id=$1`, finding)
		_, _ = db.ExecContext(ctx, `DELETE FROM task_finding_observations WHERE task_id=$1`, parentID)
		_, _ = db.ExecContext(ctx, `DELETE FROM security_findings WHERE id=$1`, finding)
		_, _ = db.ExecContext(ctx, `DELETE FROM scan_task_projections WHERE task_id=$1`, parentID)
		_, _ = db.ExecContext(ctx, `DELETE FROM scan_task_chunks WHERE task_id=$1`, parentID)
		_, _ = db.ExecContext(ctx, `DELETE FROM scan_tasks WHERE id=$1`, parentID)
		_, _ = db.ExecContext(ctx, `DELETE FROM asset_port_reviews WHERE asset_id=$1`, assetID)
		_, _ = db.ExecContext(ctx, `DELETE FROM asset_port_request_authors WHERE asset_id=$1`, assetID)
		_, _ = db.ExecContext(ctx, `DELETE FROM asset_port_requests WHERE asset_id=$1`, assetID)
		_, _ = db.ExecContext(ctx, `DELETE FROM authorized_scopes WHERE id=$1`, scopeID)
		_, _ = db.ExecContext(ctx, `DELETE FROM assets WHERE id=$1`, assetID)
		_, _ = db.ExecContext(ctx, `DELETE FROM rule_bundles WHERE version=$1`, rule)
		_, _ = db.ExecContext(ctx, `DELETE FROM users WHERE id IN ($1,$2)`, actorID, engineer)
	}
	cleanup()
	defer cleanup()
	for _, user := range []struct{ id, name, role string }{{actorID, "lab_pg_retest_admin", "admin"}, {engineer, "lab_pg_retest_engineer", "security_engineer"}} {
		if _, err := db.ExecContext(ctx, `INSERT INTO users(id,username,role,is_active,password_hash)
			VALUES ($1,$2,$3,TRUE,'fixture-only')`, user.id, user.name, user.role); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO assets(id,kind,address,business_group,owner)
		VALUES ($1,'host','192.0.2.81','fixture','fixture-owner')`, assetID); err != nil {
		t.Fatal(err)
	}
	for _, port := range []int{22, 8080} {
		if _, err := db.ExecContext(ctx, `INSERT INTO asset_port_requests(asset_id,port) VALUES ($1,$2)`, assetID, port); err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, `INSERT INTO asset_port_request_authors(asset_id,port,requested_by) VALUES ($1,$2,$3)`, assetID, port, actorID); err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, `INSERT INTO asset_ports(asset_id,port,kind,source) VALUES ($1,$2,'NON_WEB','lab')`, assetID, port); err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, `INSERT INTO asset_port_reviews(asset_id,port,status,reviewed_by,approval_ticket,reviewed_at)
			VALUES ($1,$2,'APPROVED',$3,'LAB-RETEST',CURRENT_TIMESTAMP)`, assetID, port, engineer); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO authorized_scopes
		(id,asset_id,cidr_or_host,max_targets,time_windows,requested_by,approved_by,approval_ticket,expires_at,status,created_at)
		VALUES ($1,$2,'192.0.2.81',1,'[]',$3,$4,'LAB-RETEST',CURRENT_TIMESTAMP + INTERVAL '1 hour','APPROVED',CURRENT_TIMESTAMP)`, scopeID, assetID, actorID, engineer); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO rule_bundles(version,channel,manifest_sha256,published_at,engines,is_current,is_backup,integrity_verified,signature_verified,engine_validated)
		VALUES ($1,'stable','fixture',CURRENT_TIMESTAMP,'["nuclei","trivy"]',TRUE,FALSE,TRUE,TRUE,TRUE)`, rule); err != nil {
		t.Fatal(err)
	}
	queue, err := NewPostgresTaskStore(db)
	if err != nil {
		t.Fatal(err)
	}
	if err := queue.CreateTask(ctx, ScanTask{ID: parentID, ScopeID: scopeID, Status: "PENDING", CreatedBy: actorID,
		Engines: []string{"auto"}, Targets: []string{"192.0.2.81"}, PinnedRuleVersion: rule}); err != nil {
		t.Fatal(err)
	}
	projection, err := NewPostgresTaskProjection(db)
	if err != nil {
		t.Fatal(err)
	}
	parent := taskflow.Task{ID: parentID, ScopeID: scopeID, ScopeName: "fixture", Engines: []string{"auto"}, Status: "PENDING", AssetID: assetID,
		FixedThreshold: 2, TargetCount: 1, TotalChunks: 1, RuleVersion: rule,
		Chunks:          []taskflow.Chunk{{ID: parentID + "-chunk", TaskID: parentID, Targets: []string{"192.0.2.81"}, Status: "PENDING", PinnedRuleVersion: rule}},
		PortProbeConfig: portprobe.Config{Preset: portprobe.PresetCustom, Ranges: []portprobe.Range{{Start: 22, End: 22}, {Start: 8080, End: 8080}}, Intensity: portprobe.IntensityGentle, OpsApproved: true},
		PortProbePorts:  []int{22, 8080}, VulnerabilityPorts: []int{22, 8080}}
	if err := projection.Save(ctx, parent); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE scan_tasks SET status='COMPLETED' WHERE id=$1`, parentID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE scan_task_chunks SET status='COMPLETED',completed_fully=TRUE,finished_at=CURRENT_TIMESTAMP WHERE task_id=$1`, parentID); err != nil {
		t.Fatal(err)
	}
	fingerprint := stablePostgresFindingFingerprint("192.0.2.81:8080", "nuclei", "fixture-retest-rule", "/", "", "")
	findings, err := NewPostgresFindingStore(db)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := findings.SaveFinding(ctx, taskflow.Finding{ID: finding, TaskID: parentID, AssetID: assetID, Fingerprint: fingerprint,
		Severity: "HIGH", Title: "fixture retest finding", Engine: "nuclei", TemplateOrCVE: "fixture-retest-rule",
		Target: "192.0.2.81:8080", Status: "OPEN", FirstSeen: time.Now().UTC(), LastSeen: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	store, err := NewPostgresRuntime(db)
	if err != nil {
		t.Fatal(err)
	}
	child, retest, err := store.CreateFindingRetest(ctx, finding, actorID)
	if err != nil {
		t.Fatal(err)
	}
	childID = child.ID
	if retest.TaskID != child.ID || child.AssetID != assetID || len(child.PortProbePorts) != 2 || child.PortProbeConfig.Preset != portprobe.PresetCustom {
		t.Fatalf("child=%+v retest=%+v", child, retest)
	}
	if _, _, err := store.CreateFindingRetest(ctx, finding, actorID); !errors.Is(err, ErrTaskConflict) {
		t.Fatalf("duplicate retest err=%v", err)
	}
	items, err := store.ListFindingRetests(ctx, finding)
	if err != nil || len(items) != 1 || items[0].TaskID != child.ID {
		t.Fatalf("retests=%+v err=%v", items, err)
	}
}
