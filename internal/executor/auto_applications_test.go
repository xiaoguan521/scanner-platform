package executor

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"scanner-platform/internal/sshcollect"
	"scanner-platform/internal/taskflow"
	"strings"
	"testing"
)

func TestArtifactAnalysisRequiresRecognizedResultEvenWhenNoVulnerabilities(t *testing.T) {
	for _, tc := range []struct {
		body, kind string
		ok         bool
	}{
		{`{"Results":[{"Class":"lang-pkgs","Type":"jar","Target":"application"}]}`, "jar", true},
		{`{"Results":[{"Class":"lang-pkgs","Type":"gobinary","Target":"application","Vulnerabilities":[]}]}`, "gobinary", true},
		{`{"Results":[]}`, "jar", false},
		{`{"Results":[{"Class":"lang-pkgs","Type":"jar","Target":""}]}`, "jar", false},
		{`{"Results":[{"Class":"lang-pkgs","Type":"npm","Target":"application"}]}`, "jar", false},
		{`{"Results":[{"Class":"os-pkgs","Type":"gobinary","Target":"application"}]}`, "gobinary", false},
	} {
		if err := validateArtifactAnalysis([]byte(tc.body), tc.kind); (err == nil) != tc.ok {
			t.Errorf("body=%s kind=%s err=%v", tc.body, tc.kind, err)
		}
	}
}

func TestCollectedApplicationsTrackEachFileAndStableHostTarget(t *testing.T) {
	task := taskflow.Task{RuleVersion: "1", Chunks: []taskflow.Chunk{{Targets: []string{"192.0.2.10"}}}}
	inputs := []sshcollect.AppInput{{Alias: "demo", InputPath: "random-1/a", ArtifactType: "jar"}, {Alias: "demo", InputPath: "random-2/b", ArtifactType: "jar"}}
	for _, failSecond := range []bool{false, true} {
		result := taskflow.AutoResult{ApplicationResults: []taskflow.ApplicationResult{{Alias: "demo"}}}
		calls := 0
		execute := func(_ context.Context, subtask taskflow.Task) ([]taskflow.Detection, error) {
			calls++
			if !subtask.RequireInputSnapshot || subtask.ExpectedArtifactType != "jar" || subtask.RuleVersion != task.RuleVersion {
				t.Fatal("missing strict application task fields")
			}
			if failSecond && calls == 2 {
				return nil, errors.New("no analyzer result")
			}
			return []taskflow.Detection{{Target: subtask.InputPath}}, nil
		}
		err := scanCollectedApplications(context.Background(), task, &result, inputs, execute, 2222)
		if (err != nil) != failSecond {
			t.Fatalf("failure=%t err=%v", failSecond, err)
		}
		expected := 2
		if failSecond {
			expected = 1
		}
		app := result.ApplicationResults[0]
		if app.SelectedCount != 2 || app.AnalyzedCount != expected {
			t.Fatalf("app=%+v", app)
		}
		for _, finding := range result.Findings {
			if finding.Target != "192.0.2.10:2222" {
				t.Fatal("unstable target")
			}
		}
	}
}

func TestApplicationCancellationDoesNotStartNextArtifact(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	task := taskflow.Task{Chunks: []taskflow.Chunk{{Targets: []string{"192.0.2.10"}}}}
	result := taskflow.AutoResult{ApplicationResults: []taskflow.ApplicationResult{{Alias: "demo"}}}
	calls := 0
	execute := func(context.Context, taskflow.Task) ([]taskflow.Detection, error) { calls++; cancel(); return nil, nil }
	inputs := []sshcollect.AppInput{{Alias: "demo", ArtifactType: "jar"}, {Alias: "demo", ArtifactType: "jar"}}
	if err := scanCollectedApplications(ctx, task, &result, inputs, execute, 22); !errors.Is(err, context.Canceled) {
		t.Fatalf("err=%v", err)
	}
	if calls != 1 || result.ApplicationResults[0].AnalyzedCount != 0 {
		t.Fatal("cancelled scan accepted or started next artifact")
	}
}

func FuzzArtifactAnalysisGate(f *testing.F) {
	for _, seed := range []string{`{"Results":[]}`, `{"Results":[{"Class":"lang-pkgs","Type":"jar","Target":"artifact"}]}`, `null`, `{`} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data string) {
		if len(data) > 64<<10 {
			return
		}
		_ = validateArtifactAnalysis([]byte(data), "jar")
	})
}

func TestInternalApplicationRequiresSnapshotBeforeEngine(t *testing.T) {
	root := t.TempDir()
	input := filepath.Join(root, "app")
	if err := os.Mkdir(input, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(input, "artifact.jar"), []byte("synthetic"), 0600); err != nil {
		t.Fatal(err)
	}
	runner := Runner{InputsDir: root}
	_, err := runner.trivy(context.Background(), taskflow.Task{InputPath: "app", InputKind: "artifact", RequireInputSnapshot: true, ExpectedArtifactType: "jar"}, t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "requires a verified snapshot") {
		t.Fatalf("err=%v", err)
	}
}
