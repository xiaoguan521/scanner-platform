package executor

import (
	"testing"

	"scanner-platform/internal/taskflow"
)

func TestAutoScanCompletedRequiresEveryConfiguredStage(t *testing.T) {
	tests := []struct {
		name        string
		system      string
		application string
		want        bool
	}{
		{name: "nothing configured", system: taskflow.SystemScanNotConfigured, application: taskflow.ApplicationScanNotConfigured, want: true},
		{name: "system completed", system: taskflow.SystemScanCompleted, application: taskflow.ApplicationScanNotConfigured, want: true},
		{name: "system port closed", system: taskflow.SystemScanPortClosed, application: taskflow.ApplicationScanNotConfigured, want: false},
		{name: "system out of scope", system: taskflow.SystemScanPortOutOfScope, application: taskflow.ApplicationScanNotConfigured, want: false},
		{name: "system authentication failed", system: taskflow.SystemScanAuthFailed, application: taskflow.ApplicationScanNotConfigured, want: false},
		{name: "application completed", system: taskflow.SystemScanCompleted, application: taskflow.ApplicationScanCompleted, want: true},
		{name: "application port out of scope", system: taskflow.SystemScanCompleted, application: taskflow.ApplicationScanPortOutOfScope, want: false},
		{name: "application analysis failed", system: taskflow.SystemScanCompleted, application: taskflow.ApplicationScanAnalysisFailed, want: false},
		{name: "system collection not started", system: taskflow.SystemScanNotStarted, application: taskflow.ApplicationScanNotConfigured, want: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := autoScanCompleted(taskflow.AutoResult{SystemStatus: test.system, ApplicationStatus: test.application})
			if got != test.want {
				t.Fatalf("autoScanCompleted(%q, %q) = %v, want %v", test.system, test.application, got, test.want)
			}
		})
	}
}
