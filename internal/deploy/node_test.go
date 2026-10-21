package deploy

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"scanner-platform/internal/provision"
)

func TestBuildPlanRequiresRoleScopedPackageAndPinnedSSHFiles(t *testing.T) {
	root := t.TempDir()
	now := time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC)
	complete := filepath.Join(root, "complete")
	if _, err := provision.Provision(provision.Options{
		OutputDir: complete,
		CADir:     filepath.Join(root, "ca"),
		ServerIP:  netip.MustParseAddr("192.0.2.10"),
		Nodes:     []provision.NodeSpec{{ID: "worker-a", Kind: "worker"}},
		ValidFor:  30 * 24 * time.Hour, CAValidFor: 31 * 24 * time.Hour,
		GenerateCA: true, Now: func() time.Time { return now },
	}); err != nil {
		t.Fatal(err)
	}
	identity := filepath.Join(root, "id_ed25519")
	knownHosts := filepath.Join(root, "known_hosts")
	if err := os.WriteFile(identity, []byte("fixture-private-key"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(knownHosts, []byte("[192.0.2.20]:2222 ssh-ed25519 AAAAfixture\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := BuildPlan(Options{
		PackageDir:     complete,
		TargetIP:       netip.MustParseAddr("192.0.2.20"),
		SSHPort:        2222,
		User:           "scanner",
		IdentityFile:   identity,
		KnownHostsFile: knownHosts,
		RemoteDir:      "/var/lib/scanner-platform/node-materials",
		ServiceName:    "sec-worker",
	}); err == nil {
		t.Fatal("complete material directory was accepted")
	}
	packageDir := filepath.Join(root, "worker-package")
	if _, err := provision.Package(provision.PackageOptions{
		SourceDir: complete, OutputDir: packageDir, Role: provision.PackageRoleWorker, NodeID: "worker-a", Now: func() time.Time { return now },
	}); err != nil {
		t.Fatal(err)
	}
	plan, err := BuildPlan(Options{
		PackageDir:     packageDir,
		TargetIP:       netip.MustParseAddr("192.0.2.20"),
		SSHPort:        2222,
		User:           "scanner",
		IdentityFile:   identity,
		KnownHostsFile: knownHosts,
		RemoteDir:      "/var/lib/scanner-platform/node-materials",
		ServiceName:    "sec-worker",
	})
	if err != nil {
		t.Fatalf("BuildPlan() error = %v", err)
	}
	if plan.Role != provision.PackageRoleWorker || plan.NodeID != "worker-a" || len(plan.Steps) != 5 {
		t.Fatalf("unexpected plan: %#v", plan)
	}
	data, err := os.ReadFile(filepath.Join(packageDir, "worker-a-token"))
	if err != nil {
		t.Fatal(err)
	}
	for _, step := range plan.Steps {
		if strings.Contains(string(mustJoin(step.Args)), strings.TrimSpace(string(data))) {
			t.Fatal("deployment plan leaked the node token")
		}
	}
	if !strings.Contains(plan.Steps[0].Args[len(plan.Steps[0].Args)-1], "install -d") {
		t.Fatalf("staging command = %q", plan.Steps[0].Args[len(plan.Steps[0].Args)-1])
	}
}

func TestPlanExecuteCleansStagingOnlyBeforePublish(t *testing.T) {
	plan := Plan{
		Steps:   []Step{{Name: "one", Binary: "ssh", Args: []string{"one"}}, {Name: "two", Binary: "scp", Args: []string{"two"}}, {Name: "three", Binary: "ssh", Args: []string{"three"}}, {Name: "publish", Binary: "ssh", Args: []string{"publish"}}},
		cleanup: Step{Name: "cleanup", Binary: "ssh", Args: []string{"cleanup"}},
	}
	runner := &recordingRunner{failAt: 1}
	if err := plan.Execute(context.Background(), runner); err == nil {
		t.Fatal("failed step was accepted")
	}
	if len(runner.calls) != 3 || runner.calls[2] != "cleanup" {
		t.Fatalf("pre-publish cleanup calls = %#v", runner.calls)
	}
	runner = &recordingRunner{failAt: 3}
	if err := plan.Execute(context.Background(), runner); err == nil {
		t.Fatal("publish failure was accepted")
	}
	if len(runner.calls) != 5 || runner.calls[4] != "cleanup" {
		t.Fatalf("post-publish cleanup calls = %#v", runner.calls)
	}
}

func TestBuildRotationPlanHasExplicitBackupAndRecovery(t *testing.T) {
	root := t.TempDir()
	now := time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC)
	complete := filepath.Join(root, "complete")
	if _, err := provision.Provision(provision.Options{
		OutputDir: complete, CADir: filepath.Join(root, "ca"), ServerIP: netip.MustParseAddr("192.0.2.10"),
		Nodes: []provision.NodeSpec{{ID: "worker-a", Kind: "worker"}}, ValidFor: 24 * time.Hour, CAValidFor: 48 * time.Hour,
		GenerateCA: true, Now: func() time.Time { return now },
	}); err != nil {
		t.Fatal(err)
	}
	packageDir := filepath.Join(root, "worker-package")
	if _, err := provision.Package(provision.PackageOptions{
		SourceDir: complete, OutputDir: packageDir, Role: provision.PackageRoleWorker, NodeID: "worker-a", Now: func() time.Time { return now },
	}); err != nil {
		t.Fatal(err)
	}
	identity := filepath.Join(root, "id")
	knownHosts := filepath.Join(root, "known")
	if err := os.WriteFile(identity, []byte("key"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(knownHosts, []byte("known\n"), 0644); err != nil {
		t.Fatal(err)
	}
	plan, err := BuildPlan(Options{
		PackageDir: packageDir, TargetIP: netip.MustParseAddr("192.0.2.20"), SSHPort: 22, User: "scanner",
		IdentityFile: identity, KnownHostsFile: knownHosts, RemoteDir: "/var/lib/scanner-platform/node-materials",
		ServiceName: "sec-worker", RotateExisting: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Operation != OperationRotate || plan.BackupDir == "" || len(plan.Steps) != 6 || len(plan.Recovery) != 2 {
		t.Fatalf("unexpected rotation plan: %#v", plan)
	}
	publishCommand := plan.Steps[3].Args[len(plan.Steps[3].Args)-1]
	if !strings.Contains(publishCommand, "test -d") || !strings.Contains(publishCommand, "mv --") {
		t.Fatalf("rotation plan did not guard and move the existing package: %q", publishCommand)
	}
	if !strings.Contains(plan.Recovery[0].Args[len(plan.Recovery[0].Args)-1], "mv --") {
		t.Fatal("rotation plan has no remote restore")
	}
}

func TestRotationRestartFailureRunsRollback(t *testing.T) {
	plan := Plan{
		Operation: OperationRotate,
		Steps: []Step{
			{Name: "stage", Binary: "ssh", Args: []string{"stage"}},
			{Name: "copy", Binary: "scp", Args: []string{"copy"}},
			{Name: "verify", Binary: "ssh", Args: []string{"verify"}},
			{Name: "publish", Binary: "ssh", Args: []string{"publish"}},
			{Name: "restart", Binary: "ssh", Args: []string{"restart"}},
			{Name: "cleanup", Binary: "ssh", Args: []string{"cleanup"}},
		},
		Recovery: []Step{{Name: "rollback", Binary: "ssh", Args: []string{"rollback"}}, {Name: "restart-old", Binary: "ssh", Args: []string{"restart-old"}}},
		cleanup:  Step{Name: "cleanup-staging", Binary: "ssh", Args: []string{"cleanup-staging"}},
	}
	runner := &recordingRunner{failAt: 4}
	if err := plan.Execute(context.Background(), runner); err == nil {
		t.Fatal("restart failure was accepted")
	}
	want := []string{"stage", "copy", "verify", "publish", "restart", "rollback", "restart-old", "cleanup-staging"}
	if strings.Join(runner.calls, "|") != strings.Join(want, "|") {
		t.Fatalf("rollback calls = %#v, want %#v", runner.calls, want)
	}
}

func TestBuildPlanRejectsUnsafeDeploymentInputs(t *testing.T) {
	root := t.TempDir()
	identity := filepath.Join(root, "id")
	knownHosts := filepath.Join(root, "known")
	if err := os.WriteFile(identity, []byte("key"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(knownHosts, []byte("known"), 0644); err != nil {
		t.Fatal(err)
	}
	base := Options{PackageDir: filepath.Join(root, "package"), TargetIP: netip.MustParseAddr("192.0.2.20"), SSHPort: 22, User: "scanner", IdentityFile: identity, KnownHostsFile: knownHosts, RemoteDir: "/var/lib/scanner-platform/node-materials", ServiceName: "sec-worker"}
	for name, change := range map[string]func(*Options){
		"wide identity": func(o *Options) { o.IdentityFile = identity },
		"host path":     func(o *Options) { o.RemoteDir = "/var/lib/../etc" },
		"service":       func(o *Options) { o.ServiceName = "systemd" },
		"user":          func(o *Options) { o.User = "scanner;id" },
	} {
		candidate := base
		change(&candidate)
		if _, err := BuildPlan(candidate); err == nil {
			t.Fatalf("%s accepted unsafe input", name)
		}
	}
}

type recordingRunner struct {
	calls  []string
	failAt int
}

func (r *recordingRunner) Run(_ context.Context, _ string, args []string) error {
	name := "step"
	if len(args) > 0 {
		name = args[len(args)-1]
	}
	r.calls = append(r.calls, name)
	if len(r.calls)-1 == r.failAt {
		return os.ErrPermission
	}
	return nil
}

func mustJoin(args []string) string { return strings.Join(args, "\x00") }
