package api

import (
	"errors"
	"mime"
	"net/http"
	"scanner-platform/internal/repo"
	"scanner-platform/internal/reporting"
)

func reportStoreError(w http.ResponseWriter, err error) bool {
	if err == nil {
		return false
	}
	switch {
	case errors.Is(err, reporting.ErrInvalid):
		runtimeJSON(w, 400, APIError{Error: "invalid_report", Message: err.Error()})
	case errors.Is(err, repo.ErrInvalidReportListQuery):
		runtimeJSON(w, 400, APIError{Error: "invalid_report_list_query", Message: "报告分页、筛选或排序条件无效"})
	case errors.Is(err, repo.ErrReportNotFound):
		runtimeJSON(w, 404, APIError{Error: "report_not_found", Message: "报告或模板不存在"})
	case errors.Is(err, repo.ErrReportConflict):
		runtimeJSON(w, 409, APIError{Error: "report_conflict", Message: "报告状态不允许此操作"})
	default:
		runtimeStoreError(w, err)
	}
	return true
}
func registerReportHandlers(mux *http.ServeMux, store *repo.RuntimeStore, ui func(bool, http.HandlerFunc) http.HandlerFunc, actor func(*http.Request) string) {
	mux.HandleFunc("GET /api/v1/report-templates", ui(false, func(w http.ResponseWriter, r *http.Request) {
		items, err := store.ListReportTemplates(r.Context())
		if !reportStoreError(w, err) {
			runtimeJSON(w, 200, ListResponse[reporting.Template]{Items: items, Total: len(items)})
		}
	}))
	mux.HandleFunc("GET /api/v1/report-templates/{id}", ui(false, func(w http.ResponseWriter, r *http.Request) {
		item, err := store.GetReportTemplate(r.Context(), r.PathValue("id"))
		if !reportStoreError(w, err) {
			runtimeJSON(w, 200, item)
		}
	}))
	mux.HandleFunc("PUT /api/v1/report-templates/{id}", ui(true, func(w http.ResponseWriter, r *http.Request) {
		var body reporting.Template
		if !runtimeDecodeLimit(w, r, &body, 2<<20) {
			return
		}
		if body.ID != "" && body.ID != r.PathValue("id") {
			bad(w, 400, "template_id_mismatch")
			return
		}
		body.ID = r.PathValue("id")
		item, err := store.SaveReportTemplate(r.Context(), body, actor(r))
		if !reportStoreError(w, err) {
			runtimeJSON(w, 200, item)
		}
	}))
	mux.HandleFunc("GET /api/v1/reports", ui(false, func(w http.ResponseWriter, r *http.Request) {
		if query, paged, ok := parseReportListQuery(r); paged {
			if !ok {
				bad(w, http.StatusBadRequest, "invalid_report_list_query")
				return
			}
			page, err := store.ListReportsPage(r.Context(), query)
			if errors.Is(err, repo.ErrInvalidReportListQuery) {
				bad(w, http.StatusBadRequest, "invalid_report_list_query")
				return
			}
			if !reportStoreError(w, err) {
				runtimeJSON(w, http.StatusOK, ReportPageResponse{Items: page.Items, Total: page.Total, Page: page.Page, PageSize: page.PageSize})
			}
			return
		}
		items, err := store.ListReports(r.Context())
		if !reportStoreError(w, err) {
			runtimeJSON(w, 200, ListResponse[reporting.Job]{Items: items, Total: len(items)})
		}
	}))
	mux.HandleFunc("POST /api/v1/reports", ui(true, func(w http.ResponseWriter, r *http.Request) {
		var body reporting.Request
		if !runtimeDecode(w, r, &body) {
			return
		}
		item, err := store.CreateReport(r.Context(), body, actor(r))
		if !reportStoreError(w, err) {
			runtimeJSON(w, http.StatusAccepted, item)
		}
	}))
	mux.HandleFunc("GET /api/v1/reports/{id}", ui(false, func(w http.ResponseWriter, r *http.Request) {
		item, err := store.GetReport(r.Context(), r.PathValue("id"))
		if !reportStoreError(w, err) {
			runtimeJSON(w, 200, item)
		}
	}))
	mux.HandleFunc("POST /api/v1/reports/{id}/formats", ui(true, func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Format string `json:"format"`
		}
		if !runtimeDecode(w, r, &body) {
			return
		}
		job, err := store.CreateReportFormat(r.Context(), r.PathValue("id"), body.Format, actor(r))
		if !reportStoreError(w, err) {
			runtimeJSON(w, http.StatusAccepted, job)
		}
	}))
	mux.HandleFunc("POST /api/v1/reports/{id}/retry", ui(true, func(w http.ResponseWriter, r *http.Request) {
		item, err := store.RetryReport(r.Context(), r.PathValue("id"), actor(r))
		if !reportStoreError(w, err) {
			runtimeJSON(w, http.StatusAccepted, item)
		}
	}))
	mux.HandleFunc("GET /api/v1/reports/{id}/download", ui(false, func(w http.ResponseWriter, r *http.Request) {
		job, file, err := store.OpenReport(r.Context(), r.PathValue("id"))
		if reportStoreError(w, err) {
			return
		}
		defer file.Close()
		types := map[string]string{"html": "text/html; charset=utf-8", "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document", "csv": "text/csv; charset=utf-8", "json": "application/json; charset=utf-8", "pdf": "application/pdf"}
		w.Header().Set("Content-Type", types[job.Format])
		w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": job.FileName}))
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", "sandbox; default-src 'none'; img-src data:; style-src 'unsafe-inline'")
		http.ServeContent(w, r, job.FileName, job.CreatedAt, file)
	}))
}
