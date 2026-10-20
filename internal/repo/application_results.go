package repo

import (
	"regexp"

	"scanner-platform/internal/taskflow"
)

var applicationAlias = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`)

func validApplicationStatus(status string) bool {
	switch status {
	case taskflow.ApplicationScanNotConfigured, taskflow.ApplicationScanNotStarted,
		taskflow.ApplicationScanPortOutOfScope, taskflow.ApplicationScanCollecting,
		taskflow.ApplicationScanCollectionFailed, taskflow.ApplicationScanScanning,
		taskflow.ApplicationScanAnalysisFailed, taskflow.ApplicationScanCompleted:
		return true
	}
	return false
}

func validApplicationReport(report taskflow.Report, autoTask bool) bool {
	status, results := report.ApplicationScanStatus, report.ApplicationResults
	if !autoTask || status == "" {
		// Older Workers do not report application coverage.
		return status == "" && len(results) == 0
	}
	if !validApplicationStatus(status) || len(results) > 8 {
		return false
	}
	if report.Status == "COMPLETED" && status != taskflow.ApplicationScanNotConfigured && status != taskflow.ApplicationScanPortOutOfScope && status != taskflow.ApplicationScanCompleted {
		return false
	}
	if status == taskflow.ApplicationScanNotConfigured {
		return len(results) == 0
	}
	if status == taskflow.ApplicationScanCompleted && len(results) == 0 {
		return false
	}
	seen := make(map[string]bool, len(results))
	total := 0
	for _, result := range results {
		if !applicationAlias.MatchString(result.Alias) || seen[result.Alias] || !validApplicationStatus(result.Status) || result.Status == taskflow.ApplicationScanNotConfigured {
			return false
		}
		seen[result.Alias] = true
		if result.SelectedCount < 0 || result.SelectedCount > 16 || result.AnalyzedCount < 0 || result.AnalyzedCount > result.SelectedCount {
			return false
		}
		total += result.SelectedCount
		if total > 32 || result.Status == taskflow.ApplicationScanCompleted && (result.SelectedCount == 0 || result.AnalyzedCount != result.SelectedCount) {
			return false
		}
		if status == taskflow.ApplicationScanCompleted && result.Status != taskflow.ApplicationScanCompleted {
			return false
		}
		if status == taskflow.ApplicationScanPortOutOfScope && (result.Status != status || result.SelectedCount != 0 || result.AnalyzedCount != 0) {
			return false
		}
	}
	return true
}
