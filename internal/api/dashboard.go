package api

import (
	"context"
	"net/http"
	"sort"
	"strings"
	"time"

	"scanner-platform/internal/assets"
	"scanner-platform/internal/repo"
	"scanner-platform/internal/rules"
	"scanner-platform/internal/taskflow"
)

type DashboardTrendPoint struct {
	Date  string `json:"date"`
	Label string `json:"label"`
	Count int    `json:"count"`
}

type DashboardRiskGroup struct {
	Name      string `json:"name"`
	Score     int    `json:"score"`
	OpenCount int    `json:"openCount"`
}

type DashboardRiskAsset struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Address   string `json:"address"`
	Score     int    `json:"score"`
	OpenCount int    `json:"openCount"`
}

type DashboardPendingFinding struct {
	ID            string `json:"id"`
	Severity      string `json:"severity"`
	Title         string `json:"title"`
	Target        string `json:"target"`
	Status        string `json:"status"`
	BusinessGroup string `json:"businessGroup"`
}

type DashboardFindingCounts struct {
	Vulnerabilities int `json:"vulnerabilities"`
	LoginEntries    int `json:"loginEntries"`
	Unknown         int `json:"unknown"`
	Version         int `json:"version"`
	Verified        int `json:"verified"`
}

type DashboardSummary struct {
	AssetCount           int                       `json:"assetCount"`
	TaskCount            int                       `json:"taskCount"`
	RunningTaskCount     int                       `json:"runningTaskCount"`
	HasNonSyntheticTask  bool                      `json:"hasNonSyntheticTask"`
	HasCompletedScan     bool                      `json:"hasCompletedScan"`
	RiskScore            int                       `json:"riskScore"`
	RiskyAssetCount      int                       `json:"riskyAssetCount"`
	FindingCount         int                       `json:"findingCount"`
	CriticalCount        int                       `json:"criticalCount"`
	HighCount            int                       `json:"highCount"`
	SeverityDistribution map[string]int            `json:"severityDistribution"`
	FindingCounts        DashboardFindingCounts    `json:"findingCounts"`
	Trend                []DashboardTrendPoint     `json:"trend"`
	RiskGroups           []DashboardRiskGroup      `json:"riskGroups"`
	RiskAssets           []DashboardRiskAsset      `json:"riskAssets"`
	PendingCount         int                       `json:"pendingCount"`
	PendingFindings      []DashboardPendingFinding `json:"pendingFindings"`
	CurrentRule          *rules.Bundle             `json:"currentRule,omitempty"`
}

func registerDashboardHandlers(mux *http.ServeMux, store repo.RuntimeBackend, ui func(bool, http.HandlerFunc) http.HandlerFunc) {
	mux.HandleFunc("GET /api/v1/dashboard/summary", ui(false, func(w http.ResponseWriter, r *http.Request) {
		days, ok := dashboardTrendDays(r)
		if !ok {
			bad(w, http.StatusBadRequest, "invalid_dashboard_trend_days")
			return
		}
		summary, err := buildDashboardSummary(r.Context(), store, days, time.Now().UTC())
		if !runtimeStoreError(w, err) {
			runtimeJSON(w, http.StatusOK, summary)
		}
	}))
}

func dashboardTrendDays(r *http.Request) (int, bool) {
	values, present := r.URL.Query()["days"]
	if !present {
		return 30, true
	}
	if len(values) != 1 {
		return 0, false
	}
	switch values[0] {
	case "7":
		return 7, true
	case "30":
		return 30, true
	case "90":
		return 90, true
	default:
		return 0, false
	}
}

func buildDashboardSummary(ctx context.Context, store repo.RuntimeBackend, days int, now time.Time) (DashboardSummary, error) {
	items, err := store.ListRuntimeFindings(ctx)
	if err != nil {
		return DashboardSummary{}, err
	}
	assetsList, err := store.ListRuntimeAssets(ctx)
	if err != nil {
		return DashboardSummary{}, err
	}
	tasks, err := store.ListRuntimeTasks(ctx)
	if err != nil {
		return DashboardSummary{}, err
	}
	bundles, err := store.ListRules(ctx)
	if err != nil {
		return DashboardSummary{}, err
	}
	summary := DashboardSummary{
		AssetCount:           len(assetsList),
		TaskCount:            len(tasks),
		SeverityDistribution: map[string]int{"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0},
		Trend:                dashboardTrend(items, days, now),
		RiskGroups:           dashboardRiskGroups(items, 5),
		RiskAssets:           dashboardRiskAssets(assetsList, items, 5),
		PendingFindings:      dashboardPendingFindings(items, 5),
	}
	for _, task := range tasks {
		if task.Status == "RUNNING" {
			summary.RunningTaskCount++
		}
		if !task.Synthetic {
			summary.HasNonSyntheticTask = true
			if task.Status == "COMPLETED" {
				summary.HasCompletedScan = true
			}
		}
	}
	for _, finding := range items {
		if finding.RiskType == "login_entry" {
			summary.FindingCounts.LoginEntries++
		} else if finding.RiskType == "system" || finding.RiskType == "web" {
			summary.FindingCounts.Vulnerabilities++
			if finding.DetectMethod == "version" {
				summary.FindingCounts.Version++
			}
			if finding.DetectMethod == "principle" || finding.DetectMethod == "configuration" {
				summary.FindingCounts.Verified++
			}
			summary.SeverityDistribution[finding.Severity]++
		} else {
			summary.FindingCounts.Unknown++
		}
		if dashboardActive(finding) {
			if finding.Severity == "CRITICAL" {
				summary.CriticalCount++
			}
			if finding.Severity == "HIGH" {
				summary.HighCount++
			}
		}
	}
	summary.FindingCount = summary.FindingCounts.Vulnerabilities
	summary.PendingCount = dashboardPendingCount(items)
	summary.RiskScore = dashboardRiskScore(items)
	summary.RiskyAssetCount = dashboardRiskAssetCount(items)
	for i := range bundles {
		if bundles[i].IsCurrent {
			bundle := bundles[i]
			summary.CurrentRule = &bundle
			break
		}
	}
	return summary, nil
}

func dashboardActive(f taskflow.Finding) bool {
	return (f.RiskType == "system" || f.RiskType == "web") && f.Status != "FIXED" && f.Status != "FALSE_POSITIVE"
}

func dashboardContribution(f taskflow.Finding) int {
	if !dashboardActive(f) {
		return 0
	}
	weights := map[string]int{"CRITICAL": 30, "HIGH": 20, "MEDIUM": 10, "LOW": 3, "INFO": 1}
	value := weights[f.Severity]
	if f.Status == "ACCEPTED_RISK" {
		return value / 4
	}
	return value
}

func dashboardRiskScore(items []taskflow.Finding) int {
	total := 0
	for _, finding := range items {
		total += dashboardContribution(finding)
	}
	if total > 100 {
		return 100
	}
	return total
}

func dashboardRiskAssetCount(items []taskflow.Finding) int {
	set := map[string]struct{}{}
	for _, finding := range items {
		if !dashboardActive(finding) {
			continue
		}
		key := finding.AssetID
		if key == "" {
			key = finding.Target
			if index := strings.LastIndex(key, ":"); index > 0 {
				key = key[:index]
			}
		}
		if key != "" {
			set[key] = struct{}{}
		}
	}
	return len(set)
}

func dashboardRiskGroups(items []taskflow.Finding, limit int) []DashboardRiskGroup {
	groups := map[string]DashboardRiskGroup{}
	for _, finding := range items {
		if !dashboardActive(finding) || finding.BusinessGroup == "" {
			continue
		}
		group := groups[finding.BusinessGroup]
		group.Name = finding.BusinessGroup
		group.Score += dashboardContribution(finding)
		group.OpenCount++
		if group.Score > 100 {
			group.Score = 100
		}
		groups[finding.BusinessGroup] = group
	}
	out := make([]DashboardRiskGroup, 0, len(groups))
	for _, group := range groups {
		out = append(out, group)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Score > out[j].Score || out[i].Score == out[j].Score && (out[i].OpenCount > out[j].OpenCount || out[i].OpenCount == out[j].OpenCount && out[i].Name < out[j].Name)
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

func dashboardRiskAssets(assetsList []assets.Asset, items []taskflow.Finding, limit int) []DashboardRiskAsset {
	out := make([]DashboardRiskAsset, 0, len(assetsList))
	for _, asset := range assetsList {
		item := DashboardRiskAsset{ID: asset.ID, Name: asset.Name, Address: asset.Address}
		if item.Name == "" {
			item.Name = item.Address
		}
		for _, finding := range items {
			if dashboardActive(finding) && (finding.AssetID == asset.ID || finding.Target == asset.Address || strings.HasPrefix(finding.Target, asset.Address+":")) {
				item.Score += dashboardContribution(finding)
				item.OpenCount++
			}
		}
		if item.Score > 100 {
			item.Score = 100
		}
		if item.OpenCount > 0 {
			out = append(out, item)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Score > out[j].Score || out[i].Score == out[j].Score && (out[i].OpenCount > out[j].OpenCount || out[i].OpenCount == out[j].OpenCount && out[i].Name < out[j].Name)
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

func dashboardPendingCount(items []taskflow.Finding) int {
	count := 0
	for _, finding := range items {
		if dashboardPending(finding) {
			count++
		}
	}
	return count
}

func dashboardPending(f taskflow.Finding) bool {
	return (f.RiskType == "system" || f.RiskType == "web") && (f.Severity == "CRITICAL" || f.Severity == "HIGH") && (f.Status == "OPEN" || f.Status == "REOPENED" || f.Status == "IN_PROGRESS")
}

func dashboardPendingFindings(items []taskflow.Finding, limit int) []DashboardPendingFinding {
	out := make([]DashboardPendingFinding, 0)
	for _, finding := range items {
		if dashboardPending(finding) {
			out = append(out, DashboardPendingFinding{ID: finding.ID, Severity: finding.Severity, Title: finding.Title, Target: finding.Target, Status: finding.Status, BusinessGroup: finding.BusinessGroup})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		rank := func(value string) int {
			if value == "CRITICAL" {
				return 0
			}
			return 1
		}
		return rank(out[i].Severity) < rank(out[j].Severity) || rank(out[i].Severity) == rank(out[j].Severity) && (out[i].ID < out[j].ID)
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

func dashboardTrend(items []taskflow.Finding, days int, now time.Time) []DashboardTrendPoint {
	end := time.Date(now.UTC().Year(), now.UTC().Month(), now.UTC().Day(), 0, 0, 0, 0, time.UTC)
	out := make([]DashboardTrendPoint, 0, days)
	for index := 0; index < days; index++ {
		date := end.AddDate(0, 0, -days+index+1)
		bucketEnd := date.Add(24*time.Hour - time.Nanosecond)
		count := 0
		for _, finding := range items {
			if !dashboardActive(finding) || finding.FirstSeen.After(bucketEnd) {
				continue
			}
			if finding.ResolvedAt != nil && !finding.ResolvedAt.After(bucketEnd) {
				continue
			}
			count++
		}
		out = append(out, DashboardTrendPoint{Date: date.Format("2006-01-02"), Label: date.Format("01/02"), Count: count})
	}
	return out
}
