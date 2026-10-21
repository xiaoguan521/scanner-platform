package api

import (
	"net/http"
	"strconv"

	"scanner-platform/internal/repo"
)

func parseFindingListQuery(r *http.Request) (repo.FindingListQuery, bool, bool) {
	values := r.URL.Query()
	if len(values) == 0 {
		return repo.FindingListQuery{}, false, true
	}
	for key := range values {
		switch key {
		case "page", "page_size", "q", "severity", "status", "method", "confidence", "risk", "onlyVerified", "businessGroup", "assetId", "sort":
		default:
			return repo.FindingListQuery{}, true, false
		}
	}
	single := func(key string) (string, bool) {
		items, ok := values[key]
		if !ok {
			return "", true
		}
		if len(items) != 1 {
			return "", false
		}
		return items[0], true
	}
	pageText, pageOK := single("page")
	pageSizeText, pageSizeOK := single("page_size")
	search, searchOK := single("q")
	severity, severityOK := single("severity")
	status, statusOK := single("status")
	method, methodOK := single("method")
	confidence, confidenceOK := single("confidence")
	risk, riskOK := single("risk")
	onlyVerifiedText, onlyVerifiedOK := single("onlyVerified")
	businessGroup, businessGroupOK := single("businessGroup")
	assetID, assetIDOK := single("assetId")
	sort, sortOK := single("sort")
	if !pageOK || !pageSizeOK || !searchOK || !severityOK || !statusOK || !methodOK || !confidenceOK || !riskOK || !onlyVerifiedOK || !businessGroupOK || !assetIDOK || !sortOK {
		return repo.FindingListQuery{}, true, false
	}
	normalizeAll := func(value string) string {
		if value == "ALL" || value == "all" {
			return ""
		}
		return value
	}
	query := repo.FindingListQuery{Page: 1, Search: search, Severity: normalizeAll(severity), Status: normalizeAll(status), Method: normalizeAll(method), Confidence: normalizeAll(confidence), Risk: normalizeAll(risk), BusinessGroup: businessGroup, AssetID: assetID, Sort: sort}
	if onlyVerifiedText != "" {
		if onlyVerifiedText != "true" && onlyVerifiedText != "false" {
			return repo.FindingListQuery{}, true, false
		}
		query.OnlyVerified = onlyVerifiedText == "true"
	}
	if pageText != "" {
		page, err := strconv.Atoi(pageText)
		if err != nil || page < 1 {
			return repo.FindingListQuery{}, true, false
		}
		query.Page = page
	}
	if pageSizeText != "" {
		pageSize, err := strconv.Atoi(pageSizeText)
		if err != nil || pageSize < 1 {
			return repo.FindingListQuery{}, true, false
		}
		query.PageSize = pageSize
	} else {
		query.PageSize = repo.DefaultFindingPageSize
	}
	if _, err := repo.NormalizeFindingListQuery(query); err != nil {
		return repo.FindingListQuery{}, true, false
	}
	return query, true, true
}
