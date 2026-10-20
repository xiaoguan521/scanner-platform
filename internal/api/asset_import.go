package api

import (
	"errors"
	"io"
	"mime"
	"net/http"

	"scanner-platform/internal/account"
	"scanner-platform/internal/assets"
)

func registerAssetImportHandlers(mux *http.ServeMux, accounts account.Repository, store assets.Repository) {
	importer, available := store.(assets.ImportRepository)
	wrap := func(mutate bool, next func(http.ResponseWriter, *http.Request, account.User)) http.HandlerFunc {
		return auth(accounts, false, func(w http.ResponseWriter, r *http.Request, u account.User) {
			if u.Role != "admin" && u.Role != "security_engineer" {
				bad(w, 403, "forbidden")
				return
			}
			if mutate && !mutationGuard(w, r) {
				return
			}
			if !available {
				bad(w, 501, "asset_import_unavailable")
				return
			}
			next(w, r, u)
		})
	}
	mux.HandleFunc("GET /api/v1/assets/import/template", wrap(false, func(w http.ResponseWriter, r *http.Request, _ account.User) {
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="asset-import-template.csv"`)
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		_, _ = io.WriteString(w, assets.ImportTemplate)
	}))
	mux.HandleFunc("POST /api/v1/assets/import/preview", wrap(true, func(w http.ResponseWriter, r *http.Request, u account.User) {
		media, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || media != "text/csv" || (params["charset"] != "" && params["charset"] != "utf-8") {
			bad(w, 415, "csv_required")
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, assets.MaxImportBytes)
		data, err := io.ReadAll(r.Body)
		if err != nil {
			var tooLarge *http.MaxBytesError
			if errors.As(err, &tooLarge) {
				bad(w, 413, "asset_import_limit")
			} else {
				bad(w, 400, "invalid_asset_csv")
			}
			return
		}
		preview, err := importer.PreviewImport(r.Context(), u.ID, data)
		if assetImportError(w, err) {
			return
		}
		respond(w, 200, preview)
	}))
	mux.HandleFunc("POST /api/v1/assets/import/confirm", wrap(true, func(w http.ResponseWriter, r *http.Request, u account.User) {
		var input struct {
			PreviewID string `json:"previewId"`
		}
		if !readJSON(w, r, &input) {
			return
		}
		result, err := importer.ConfirmImport(r.Context(), u.ID, input.PreviewID)
		if assetImportError(w, err) {
			return
		}
		respond(w, 201, result)
	}))
}
func assetImportError(w http.ResponseWriter, err error) bool {
	if err == nil {
		return false
	}
	switch {
	case errors.Is(err, assets.ErrImportFormat), errors.Is(err, assets.ErrInvalid):
		bad(w, 400, "invalid_asset_csv")
	case errors.Is(err, assets.ErrImportLimit):
		bad(w, 413, "asset_import_limit")
	case errors.Is(err, assets.ErrImportUnavailable):
		bad(w, 409, "asset_import_unavailable")
	case errors.Is(err, assets.ErrImportConflict):
		bad(w, 409, "asset_import_conflict")
	default:
		bad(w, 500, "db_error")
	}
	return true
}
