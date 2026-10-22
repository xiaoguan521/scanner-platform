package api

import (
	"net/http"
	"sort"
	"strings"
	"time"

	"scanner-platform/internal/repo"
	"scanner-platform/internal/taskflow"
)

const (
	maxAssetInsightIDs      = 100
	maxAssetInsightFindings = 50
	maxAssetInsightTasks    = 20
)

// AssetInsightFinding is the list-row subset of an active finding; evidence,
// descriptions and references stay on the findings API.
type AssetInsightFinding struct {
	ID            string    `json:"id"`
	Severity      string    `json:"severity"`
	Title         string    `json:"title"`
	Status        string    `json:"status"`
	Engine        string    `json:"engine"`
	TemplateOrCVE string    `json:"templateOrCve"`
	LastSeen      time.Time `json:"lastSeen"`
}

type AssetInsightTask struct {
	ID           string     `json:"id"`
	Engines      []string   `json:"engines"`
	Status       string     `json:"status"`
	FindingCount int        `json:"findingCount"`
	CreatedAt    time.Time  `json:"createdAt"`
	FinishedAt   *time.Time `json:"finishedAt,omitempty"`
}

type AssetInsightProbe struct {
	ID        string    `json:"id"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"createdAt"`
	OpenPorts []int     `json:"openPorts"`
}

type AssetInsight struct {
	AssetID            string                `json:"assetId"`
	ActiveFindingCount int                   `json:"activeFindingCount"`
	ActiveFindings     []AssetInsightFinding `json:"activeFindings"`
	LatestProbe        *AssetInsightProbe    `json:"latestProbe,omitempty"`
	RecentTasks        []AssetInsightTask    `json:"recentTasks"`
}

func registerAssetInsightHandlers(mux *http.ServeMux, store repo.RuntimeBackend, ui func(bool, http.HandlerFunc) http.HandlerFunc) {
	mux.HandleFunc("GET /api/v1/assets/insights", ui(false, func(w http.ResponseWriter, r *http.Request) {
		ids, ok := parseAssetInsightIDs(r)
		if !ok {
			bad(w, http.StatusBadRequest, "invalid_asset_insight_query")
			return
		}
		findingItems, err := store.ListRuntimeFindings(r.Context())
		if runtimeStoreError(w, err) {
			return
		}
		tasks, err := store.ListRuntimeTasks(r.Context())
		if runtimeStoreError(w, err) {
			return
		}
		items := buildAssetInsights(ids, findingItems, tasks)
		runtimeJSON(w, http.StatusOK, ListResponse[AssetInsight]{Items: items, Total: len(items)})
	}))
}

func parseAssetInsightIDs(r *http.Request) ([]string, bool) {
	values := r.URL.Query()
	for key := range values {
		if key != "ids" {
			return nil, false
		}
	}
	raw := values["ids"]
	if len(raw) != 1 {
		return nil, false
	}
	seen := map[string]bool{}
	ids := make([]string, 0)
	for _, part := range strings.Split(raw[0], ",") {
		id := strings.TrimSpace(part)
		if id == "" || len(id) > 160 || strings.ContainsRune(id, 0) {
			return nil, false
		}
		if !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 || len(ids) > maxAssetInsightIDs {
		return nil, false
	}
	return ids, true
}

func assetInsightActive(f taskflow.Finding) bool {
	return f.Status != "FIXED" && f.Status != "FALSE_POSITIVE"
}

func assetInsightSeverityRank(severity string) int {
	return map[string]int{"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}[severity]
}

func buildAssetInsights(ids []string, findingItems []taskflow.Finding, tasks []taskflow.Task) []AssetInsight {
	byID := make(map[string]*AssetInsight, len(ids))
	items := make([]AssetInsight, len(ids))
	for i, id := range ids {
		items[i] = AssetInsight{AssetID: id, ActiveFindings: []AssetInsightFinding{}, RecentTasks: []AssetInsightTask{}}
		byID[id] = &items[i]
	}
	for _, f := range findingItems {
		insight := byID[f.AssetID]
		if insight == nil || !assetInsightActive(f) {
			continue
		}
		insight.ActiveFindingCount++
		insight.ActiveFindings = append(insight.ActiveFindings, AssetInsightFinding{ID: f.ID, Severity: f.Severity, Title: f.Title, Status: f.Status, Engine: f.Engine, TemplateOrCVE: f.TemplateOrCVE, LastSeen: f.LastSeen})
	}
	ordered := append([]taskflow.Task(nil), tasks...)
	sort.SliceStable(ordered, func(i, j int) bool { return ordered[i].CreatedAt.After(ordered[j].CreatedAt) })
	for _, task := range ordered {
		insight := byID[task.AssetID]
		if insight == nil {
			continue
		}
		engine := ""
		if len(task.Engines) > 0 {
			engine = task.Engines[0]
		}
		if insight.LatestProbe == nil && (engine == "port-probe" || engine == "auto") {
			ports := make([]int, 0, len(task.PortProbeResults))
			for _, result := range task.PortProbeResults {
				ports = append(ports, result.Port)
			}
			insight.LatestProbe = &AssetInsightProbe{ID: task.ID, Status: task.Status, CreatedAt: task.CreatedAt, OpenPorts: ports}
		}
		if task.Synthetic || len(insight.RecentTasks) >= maxAssetInsightTasks {
			continue
		}
		var finished *time.Time
		if len(task.Chunks) > 0 {
			finished = task.Chunks[0].FinishedAt
		}
		insight.RecentTasks = append(insight.RecentTasks, AssetInsightTask{ID: task.ID, Engines: task.Engines, Status: task.Status, FindingCount: task.FindingCount, CreatedAt: task.CreatedAt, FinishedAt: finished})
	}
	for i := range items {
		list := items[i].ActiveFindings
		sort.SliceStable(list, func(a, b int) bool {
			if ra, rb := assetInsightSeverityRank(list[a].Severity), assetInsightSeverityRank(list[b].Severity); ra != rb {
				return ra > rb
			}
			return list[a].LastSeen.After(list[b].LastSeen)
		})
		if len(list) > maxAssetInsightFindings {
			items[i].ActiveFindings = list[:maxAssetInsightFindings]
		}
	}
	return items
}
