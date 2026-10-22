package api

import (
	"errors"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"time"

	"scanner-platform/internal/repo"
	"scanner-platform/internal/taskflow"
)

const (
	maxFindingGroupPageSize = 100
	maxFindingGroupSamples  = 10
)

// FindingGroup aggregates findings that share a CVE (or template ID) or a
// software package. The UI drills into a group with the exact cve= or
// package= filter on the findings list.
type FindingGroup struct {
	Key               string         `json:"key"`
	Title             string         `json:"title,omitempty"`
	Count             int            `json:"count"`
	MaxSeverity       string         `json:"maxSeverity"`
	StatusCounts      map[string]int `json:"statusCounts"`
	AssetCount        int            `json:"assetCount"`
	Packages          []string       `json:"packages,omitempty"`
	CVECount          int            `json:"cveCount,omitempty"`
	InstalledVersions []string       `json:"installedVersions,omitempty"`
	FixedVersions     []string       `json:"fixedVersions,omitempty"`
	LastSeen          time.Time      `json:"lastSeen"`
}

type FindingGroupPage struct {
	Items     []FindingGroup         `json:"items"`
	Total     int                    `json:"total"`
	Page      int                    `json:"page"`
	PageSize  int                    `json:"pageSize"`
	Findings  int                    `json:"findings"`
	Ungrouped int                    `json:"ungrouped"`
	Counts    repo.FindingListCounts `json:"counts"`
}

func registerFindingGroupHandlers(mux *http.ServeMux, store repo.RuntimeBackend, ui func(bool, http.HandlerFunc) http.HandlerFunc) {
	mux.HandleFunc("GET /api/v1/findings/groups", ui(false, func(w http.ResponseWriter, r *http.Request) {
		by, page, pageSize, query, ok := parseFindingGroupQuery(r.URL.Query())
		if !ok {
			bad(w, http.StatusBadRequest, "invalid_finding_group_query")
			return
		}
		// PageSize 0 asks the store for every match, using exactly the same
		// filters as the findings list; grouping then happens here.
		all, err := store.ListRuntimeFindingsPage(r.Context(), query)
		if errors.Is(err, repo.ErrInvalidFindingListQuery) {
			bad(w, http.StatusBadRequest, "invalid_finding_group_query")
			return
		}
		if runtimeStoreError(w, err) {
			return
		}
		groups, ungrouped := groupFindings(all.Items, by)
		start := min((page-1)*pageSize, len(groups))
		end := min(start+pageSize, len(groups))
		runtimeJSON(w, http.StatusOK, FindingGroupPage{Items: groups[start:end], Total: len(groups), Page: page, PageSize: pageSize, Findings: all.Total, Ungrouped: ungrouped, Counts: all.Counts})
	}))
}

func parseFindingGroupQuery(values url.Values) (string, int, int, repo.FindingListQuery, bool) {
	single := func(key string, fallback string) (string, bool) {
		items, present := values[key]
		if !present {
			return fallback, true
		}
		return items[0], len(items) == 1
	}
	by, byOK := single("by", "")
	pageText, pageOK := single("page", "1")
	sizeText, sizeOK := single("page_size", "20")
	page, pageErr := strconv.Atoi(pageText)
	pageSize, sizeErr := strconv.Atoi(sizeText)
	if !byOK || !pageOK || !sizeOK || (by != "cve" && by != "package") || pageErr != nil || sizeErr != nil || page < 1 || page > repo.MaxFindingPage || pageSize < 1 || pageSize > maxFindingGroupPageSize {
		return "", 0, 0, repo.FindingListQuery{}, false
	}
	filters := url.Values{}
	for key, items := range values {
		switch key {
		case "by", "page", "page_size":
		case "sort":
			return "", 0, 0, repo.FindingListQuery{}, false
		default:
			filters[key] = items
		}
	}
	query := repo.FindingListQuery{Page: 1}
	if len(filters) > 0 {
		parsed, _, valid := parseFindingListValues(filters)
		if !valid {
			return "", 0, 0, repo.FindingListQuery{}, false
		}
		query = parsed
	}
	query.Page, query.PageSize, query.Sort = 1, 0, ""
	return by, page, pageSize, query, true
}

func findingSeverityRank(severity string) int {
	return map[string]int{"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}[severity]
}

// groupFindings returns groups ordered by highest severity, then size, then
// key, and the number of findings that have no key for this dimension.
func groupFindings(items []taskflow.Finding, by string) ([]FindingGroup, int) {
	type accumulator struct {
		group     FindingGroup
		assets    map[string]bool
		packages  map[string]bool
		cves      map[string]bool
		installed map[string]bool
		fixed     map[string]bool
	}
	byKey := map[string]*accumulator{}
	order := []string{}
	ungrouped := 0
	addSample := func(set map[string]bool, list *[]string, value string) {
		if value == "" || set[value] {
			return
		}
		set[value] = true
		if len(*list) < maxFindingGroupSamples {
			*list = append(*list, value)
		}
	}
	for _, f := range items {
		key := f.TemplateOrCVE
		if by == "package" {
			key = f.Package
		}
		if key == "" {
			ungrouped++
			continue
		}
		acc := byKey[key]
		if acc == nil {
			acc = &accumulator{group: FindingGroup{Key: key, StatusCounts: map[string]int{}}, assets: map[string]bool{}, packages: map[string]bool{}, cves: map[string]bool{}, installed: map[string]bool{}, fixed: map[string]bool{}}
			byKey[key] = acc
			order = append(order, key)
		}
		g := &acc.group
		g.Count++
		g.StatusCounts[f.Status]++
		if findingSeverityRank(f.Severity) > findingSeverityRank(g.MaxSeverity) {
			g.MaxSeverity = f.Severity
		}
		if f.LastSeen.After(g.LastSeen) {
			g.LastSeen = f.LastSeen
		}
		asset := f.AssetID
		if asset == "" {
			asset = f.Target
		}
		acc.assets[asset] = true
		if by == "cve" {
			if g.Title == "" {
				g.Title = f.Title
			}
			addSample(acc.packages, &g.Packages, f.Package)
		} else if f.TemplateOrCVE != "" {
			acc.cves[f.TemplateOrCVE] = true
		}
		addSample(acc.installed, &g.InstalledVersions, f.InstalledVersion)
		addSample(acc.fixed, &g.FixedVersions, f.FixedVersion)
	}
	groups := make([]FindingGroup, 0, len(order))
	for _, key := range order {
		acc := byKey[key]
		acc.group.AssetCount = len(acc.assets)
		acc.group.CVECount = len(acc.cves)
		if by == "cve" {
			acc.group.InstalledVersions = nil
		}
		groups = append(groups, acc.group)
	}
	sort.SliceStable(groups, func(i, j int) bool {
		if ri, rj := findingSeverityRank(groups[i].MaxSeverity), findingSeverityRank(groups[j].MaxSeverity); ri != rj {
			return ri > rj
		}
		if groups[i].Count != groups[j].Count {
			return groups[i].Count > groups[j].Count
		}
		return groups[i].Key < groups[j].Key
	})
	return groups, ungrouped
}
