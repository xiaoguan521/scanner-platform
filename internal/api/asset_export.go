package api

import (
	"bytes"
	"encoding/csv"
	"net/http"
	"strconv"
	"strings"

	"scanner-platform/internal/account"
	"scanner-platform/internal/assets"
)

const assetExportMaxFilterBytes = 160

var assetExportHeader = []string{
	"id",
	"kind",
	"address",
	"name",
	"isCore",
	"businessGroup",
	"owner",
	"requestedPorts",
	"skippedPorts",
	"quarantinedPorts",
	"reachabilityStatus",
	"reachabilityCheckedAt",
	"createdAt",
}

func registerAssetExportHandler(mux *http.ServeMux, accounts account.Repository, store assets.Repository) {
	mux.HandleFunc("GET /api/v1/assets/export", auth(accounts, false, func(w http.ResponseWriter, r *http.Request, _ account.User) {
		filter, ok := assetExportFilter(r)
		if !ok {
			bad(w, http.StatusBadRequest, "invalid_asset_export_filter")
			return
		}
		list, err := store.List(r.Context())
		if err != nil {
			bad(w, http.StatusInternalServerError, "db_error")
			return
		}
		if filter != "" {
			filtered := make([]assets.Asset, 0, len(list))
			for _, item := range list {
				if assetExportMatches(item, filter) {
					filtered = append(filtered, item)
				}
			}
			list = filtered
		}
		data, err := renderAssetCSV(list)
		if err != nil {
			bad(w, http.StatusInternalServerError, "db_error")
			return
		}
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="assets.csv"`)
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(data)
	}))
}

func assetExportFilter(r *http.Request) (string, bool) {
	values, present := r.URL.Query()["q"]
	if !present {
		return "", true
	}
	if len(values) != 1 || strings.IndexByte(values[0], 0) >= 0 || len(values[0]) > assetExportMaxFilterBytes {
		return "", false
	}
	return strings.ToLower(strings.TrimSpace(values[0])), true
}

func assetExportMatches(item assets.Asset, filter string) bool {
	return strings.Contains(strings.ToLower(item.Address), filter) ||
		strings.Contains(strings.ToLower(item.Name), filter) ||
		strings.Contains(strings.ToLower(item.BusinessGroup), filter) ||
		strings.Contains(strings.ToLower(item.Owner), filter)
}

func renderAssetCSV(list []assets.Asset) ([]byte, error) {
	var buffer bytes.Buffer
	writer := csv.NewWriter(&buffer)
	writer.UseCRLF = true
	if err := writer.Write(assetExportHeader); err != nil {
		return nil, err
	}
	for _, item := range list {
		row := []string{
			item.ID,
			item.Kind,
			item.Address,
			item.Name,
			strconv.FormatBool(item.IsCore),
			item.BusinessGroup,
			item.Owner,
			joinAssetExportInts(item.RequestedPorts),
			joinAssetExportInts(item.SkippedPorts),
			joinAssetExportInts(item.QuarantinedPorts),
			item.ReachabilityStatus,
			item.ReachabilityCheckedAt,
			item.CreatedAt,
		}
		for index := range row {
			row[index] = safeAssetCSVCell(row[index])
		}
		if err := writer.Write(row); err != nil {
			return nil, err
		}
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func joinAssetExportInts(values []int) string {
	parts := make([]string, 0, len(values))
	for _, value := range values {
		parts = append(parts, strconv.Itoa(value))
	}
	return strings.Join(parts, ",")
}

// Prefix spreadsheet formula markers so a downloaded inventory cannot execute
// a formula when opened in a spreadsheet application.
func safeAssetCSVCell(value string) string {
	if value == "" {
		return value
	}
	switch value[0] {
	case '=', '+', '-', '@':
		return "'" + value
	default:
		return value
	}
}
