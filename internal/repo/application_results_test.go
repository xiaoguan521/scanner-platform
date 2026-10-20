package repo

import (
	"fmt"
	"testing"

	"scanner-platform/internal/taskflow"
)

func TestApplicationReportValidation(t *testing.T) {
	good := taskflow.Report{Status: "COMPLETED", ApplicationScanStatus: taskflow.ApplicationScanCompleted, ApplicationResults: []taskflow.ApplicationResult{{Alias: "demo", Status: taskflow.ApplicationScanCompleted, SelectedCount: 2, AnalyzedCount: 2}}}
	tests := []struct {
		name string
		auto bool
		edit func(*taskflow.Report)
		want bool
	}{
		{"completed", true, func(*taskflow.Report) {}, true},
		{"legacy", true, func(r *taskflow.Report) { r.ApplicationScanStatus = ""; r.ApplicationResults = nil }, true},
		{"non-auto", false, func(*taskflow.Report) {}, false},
		{"raw-status", true, func(r *taskflow.Report) { r.ApplicationScanStatus = "/opt/private" }, false},
		{"raw-alias", true, func(r *taskflow.Report) { r.ApplicationResults[0].Alias = "../private" }, false},
		{"negative", true, func(r *taskflow.Report) { r.ApplicationResults[0].AnalyzedCount = -1 }, false},
		{"over-selected", true, func(r *taskflow.Report) { r.ApplicationResults[0].AnalyzedCount = 3 }, false},
		{"incomplete-success", true, func(r *taskflow.Report) { r.ApplicationResults[0].AnalyzedCount = 1 }, false},
		{"partial-success", true, func(r *taskflow.Report) { r.ApplicationResults[0].Status = taskflow.ApplicationScanAnalysisFailed }, false},
		{"failure-success", true, func(r *taskflow.Report) { r.ApplicationScanStatus = taskflow.ApplicationScanAnalysisFailed }, false},
		{"partial-failure", true, func(r *taskflow.Report) {
			r.Status = "FAILED"
			r.ApplicationScanStatus = taskflow.ApplicationScanAnalysisFailed
			r.ApplicationResults[0].Status = taskflow.ApplicationScanAnalysisFailed
			r.ApplicationResults[0].AnalyzedCount = 1
		}, true},
		{"paused", true, func(r *taskflow.Report) {
			r.Status = "PAUSED_WINDOW"
			r.ApplicationScanStatus = taskflow.ApplicationScanScanning
			r.ApplicationResults[0].Status = taskflow.ApplicationScanScanning
			r.ApplicationResults[0].AnalyzedCount = 1
		}, true},
		{"not-configured-with-results", true, func(r *taskflow.Report) { r.ApplicationScanStatus = taskflow.ApplicationScanNotConfigured }, false},
		{"missing-status-with-results", true, func(r *taskflow.Report) { r.ApplicationScanStatus = "" }, false},
		{"duplicate-alias", true, func(r *taskflow.Report) { r.ApplicationResults = append(r.ApplicationResults, r.ApplicationResults[0]) }, false},
		{"no-completed-alias", true, func(r *taskflow.Report) { r.ApplicationResults = nil }, false},
		{"empty-completed-alias", true, func(r *taskflow.Report) {
			r.ApplicationResults[0].SelectedCount = 0
			r.ApplicationResults[0].AnalyzedCount = 0
		}, false},
		{"over-limit", true, func(r *taskflow.Report) {
			r.ApplicationResults[0].SelectedCount = 17
			r.ApplicationResults[0].AnalyzedCount = 17
		}, false},
		{"total-limit", true, func(r *taskflow.Report) {
			for i := 0; i < 3; i++ {
				r.ApplicationResults = append(r.ApplicationResults, taskflow.ApplicationResult{Alias: fmt.Sprintf("app%d", i), Status: taskflow.ApplicationScanCompleted, SelectedCount: 16, AnalyzedCount: 16})
			}
		}, false},
		{"out-of-scope", true, func(r *taskflow.Report) {
			r.ApplicationScanStatus = taskflow.ApplicationScanPortOutOfScope
			r.ApplicationResults[0].Status = taskflow.ApplicationScanPortOutOfScope
			r.ApplicationResults[0].SelectedCount = 0
			r.ApplicationResults[0].AnalyzedCount = 0
		}, true},
		{"out-of-scope-with-analysis", true, func(r *taskflow.Report) {
			r.ApplicationScanStatus = taskflow.ApplicationScanPortOutOfScope
			r.ApplicationResults[0].Status = taskflow.ApplicationScanPortOutOfScope
		}, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			report := good
			report.ApplicationResults = append([]taskflow.ApplicationResult(nil), good.ApplicationResults...)
			test.edit(&report)
			if got := validApplicationReport(report, test.auto); got != test.want {
				t.Fatalf("got %v want %v: %+v", got, test.want, report)
			}
		})
	}
}
