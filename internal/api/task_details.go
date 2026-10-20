package api

import (
	"encoding/csv"
	"net/http"
	"strconv"
	"strings"

	"scanner-platform/internal/repo"
	"scanner-platform/internal/taskflow"
)

// TaskResultFinding is the stable, exportable finding projection. Evidence,
// references, request/response data and credentials stay in the detail API and
// are deliberately not part of a task download.
type TaskResultFinding struct {
	ID               string `json:"id"`
	Severity         string `json:"severity"`
	Title            string `json:"title"`
	Target           string `json:"target"`
	Port             int    `json:"port,omitempty"`
	Status           string `json:"status"`
	Engine           string `json:"engine"`
	TemplateOrCVE    string `json:"templateOrCve"`
	RiskType         string `json:"riskType,omitempty"`
	DetectMethod     string `json:"detectMethod,omitempty"`
	Package          string `json:"package,omitempty"`
	InstalledVersion string `json:"installedVersion,omitempty"`
	FixedVersion     string `json:"fixedVersion,omitempty"`
}

type TaskResultExport struct {
	TaskID        string              `json:"taskId"`
	Status        string              `json:"status"`
	CreatedAt     string              `json:"createdAt"`
	TargetCount   int                 `json:"targetCount"`
	FindingCount  int                 `json:"findingCount"`
	OpenPortCount int                 `json:"openPortCount"`
	Findings      []TaskResultFinding `json:"findings"`
}

func registerTaskDetailHandlers(mux *http.ServeMux, store *repo.RuntimeStore, ui func(bool, http.HandlerFunc) http.HandlerFunc) {
	mux.HandleFunc("GET /api/v1/tasks/{id}", ui(false, func(w http.ResponseWriter, r *http.Request) {
		task, err := store.GetRuntimeTask(r.Context(), r.PathValue("id"))
		if !runtimeStoreError(w, err) {
			runtimeJSON(w, http.StatusOK, task)
		}
	}))
	mux.HandleFunc("GET /api/v1/tasks/{id}/logs", ui(false, func(w http.ResponseWriter, r *http.Request) {
		items, err := store.ListTaskLogs(r.Context(), r.PathValue("id"))
		if !runtimeStoreError(w, err) {
			runtimeJSON(w, http.StatusOK, ListResponse[repo.TaskLog]{Items: items, Total: len(items)})
		}
	}))
	mux.HandleFunc("GET /api/v1/tasks/{id}/export", ui(false, func(w http.ResponseWriter, r *http.Request) {
		format, ok := taskExportFormat(r)
		if !ok {
			bad(w, http.StatusBadRequest, "invalid_task_export_format")
			return
		}
		task, err := store.GetRuntimeTask(r.Context(), r.PathValue("id"))
		if err != nil {
			runtimeStoreError(w, err)
			return
		}
		findings, err := store.ListTaskFindings(r.Context(), task.ID)
		if err != nil {
			runtimeStoreError(w, err)
			return
		}
		export := taskResultExport(task, findings)
		if format == "csv" {
			data, err := renderTaskCSV(export)
			if err != nil {
				bad(w, http.StatusInternalServerError, "db_error")
				return
			}
			w.Header().Set("Content-Type", "text/csv; charset=utf-8")
			w.Header().Set("Content-Disposition", `attachment; filename="task-result.csv"`)
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(data)
			return
		}
		w.Header().Set("Content-Disposition", `attachment; filename="task-result.json"`)
		runtimeJSON(w, http.StatusOK, export)
	}))
}

func taskExportFormat(r *http.Request) (string, bool) {
	values, present := r.URL.Query()["format"]
	if !present {
		return "json", true
	}
	if len(values) != 1 || (values[0] != "json" && values[0] != "csv") {
		return "", false
	}
	return values[0], true
}

func taskResultExport(task taskflow.Task, findings []taskflow.Finding) TaskResultExport {
	items := make([]TaskResultFinding, 0, len(findings))
	for _, finding := range findings {
		items = append(items, TaskResultFinding{
			ID:               finding.ID,
			Severity:         finding.Severity,
			Title:            finding.Title,
			Target:           finding.Target,
			Port:             finding.Port,
			Status:           finding.Status,
			Engine:           finding.Engine,
			TemplateOrCVE:    finding.TemplateOrCVE,
			RiskType:         finding.RiskType,
			DetectMethod:     finding.DetectMethod,
			Package:          finding.Package,
			InstalledVersion: finding.InstalledVersion,
			FixedVersion:     finding.FixedVersion,
		})
	}
	return TaskResultExport{
		TaskID:        task.ID,
		Status:        task.Status,
		CreatedAt:     task.CreatedAt.UTC().Format("2006-01-02T15:04:05.999999999Z07:00"),
		TargetCount:   task.TargetCount,
		FindingCount:  len(items),
		OpenPortCount: len(task.PortProbeResults),
		Findings:      items,
	}
}

var taskExportHeader = []string{
	"taskId", "status", "createdAt", "targetCount", "findingCount", "openPortCount",
	"findingId", "severity", "title", "target", "port", "findingStatus", "engine",
	"templateOrCve", "riskType", "detectMethod", "package", "installedVersion", "fixedVersion",
}

func renderTaskCSV(export TaskResultExport) ([]byte, error) {
	var builder strings.Builder
	writer := csv.NewWriter(&builder)
	writer.UseCRLF = true
	if err := writer.Write(taskExportHeader); err != nil {
		return nil, err
	}
	if len(export.Findings) == 0 {
		row := make([]string, len(taskExportHeader))
		row[0] = export.TaskID
		row[1] = export.Status
		row[2] = export.CreatedAt
		row[3] = strconv.Itoa(export.TargetCount)
		row[4] = "0"
		row[5] = strconv.Itoa(export.OpenPortCount)
		if err := writer.Write(taskCSVRow(row)); err != nil {
			return nil, err
		}
	} else {
		for _, finding := range export.Findings {
			row := []string{
				export.TaskID, export.Status, export.CreatedAt, strconv.Itoa(export.TargetCount), strconv.Itoa(export.FindingCount), strconv.Itoa(export.OpenPortCount),
				finding.ID, finding.Severity, finding.Title, finding.Target, strconv.Itoa(finding.Port), finding.Status, finding.Engine,
				finding.TemplateOrCVE, finding.RiskType, finding.DetectMethod, finding.Package, finding.InstalledVersion, finding.FixedVersion,
			}
			if err := writer.Write(taskCSVRow(row)); err != nil {
				return nil, err
			}
		}
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		return nil, err
	}
	return []byte(builder.String()), nil
}

func taskCSVRow(values []string) []string {
	for index, value := range values {
		values[index] = safeAssetCSVCell(value)
	}
	return values
}
