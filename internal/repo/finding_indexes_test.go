package repo

import (
	"context"
	"strings"
	"testing"
)

func queryPlan(t *testing.T, store *RuntimeStore, query string, args ...any) string {
	t.Helper()
	rows, err := store.db.QueryContext(context.Background(), "EXPLAIN QUERY PLAN "+query, args...)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var plan []string
	for rows.Next() {
		var id, parent, unused int
		var detail string
		if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
			t.Fatal(err)
		}
		plan = append(plan, detail)
	}
	return strings.Join(plan, "; ")
}

func TestFindingReportQueriesUseIndexes(t *testing.T) {
	store, _ := localFixture(t)
	if plan := queryPlan(t, store, `SELECT id,data FROM security_findings WHERE json_extract(data,'$.status')='ACCEPTED_RISK'`); !strings.Contains(plan, "findings_status") {
		t.Fatalf("accepted-risk expiry must not scan every finding: %s", plan)
	}
	if plan := queryPlan(t, store, `SELECT id,data FROM security_findings WHERE json_extract(data,'$.target')>=? AND json_extract(data,'$.target')<?`, "192.0.2.20:", "192.0.2.20;"); !strings.Contains(plan, "findings_target") {
		t.Fatalf("per-host lifecycle lookup must not scan every finding: %s", plan)
	}
}
