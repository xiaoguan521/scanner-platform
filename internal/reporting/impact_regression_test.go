package reporting

import "testing"

// Two ports on one host may produce two independent observations, but the
// affected-asset column counts the unique host only (never IP:port pairs).
func TestReportImpactRegressionDistinctHostAcrossPorts(t *testing.T) {
	s := exampleSnapshot()
	s.Findings = []Finding{
		{
			ID: "port-80", Fingerprint: "fp-host-80", RiskType: "web",
			TemplateOrCVE: "CVE-2026-0002", Title: "共享示例漏洞",
			Target: "192.0.2.10:80", Severity: "HIGH",
		},
		{
			ID: "port-443", Fingerprint: "fp-host-443", RiskType: "web",
			TemplateOrCVE: "CVE-2026-0002", Title: "共享示例漏洞",
			Target: "192.0.2.10:443", Severity: "HIGH",
		},
	}
	s = Freeze(s)
	if s.Summary.Vulnerabilities != 2 || s.Summary.RiskAssets != 1 {
		t.Fatalf("observations and distinct risk assets mixed: %+v", s.Summary)
	}
	table := influenceTable(s, "web", 100)
	if len(table.Rows) != 1 {
		t.Fatalf("same vulnerability split across ports: %+v", table.Rows)
	}
	if row := table.Rows[0]; row[4] != "2" || row[5] != "1" || row[6] != "192.0.2.10" {
		t.Fatalf("impact table counted port endpoints instead of distinct host: %+v", row)
	}
	worksheets := Workbook(s)
	if len(worksheets) != 8 {
		t.Fatalf("report no longer has eight Excel sheets: %d", len(worksheets))
	}
	impact := worksheets[2]
	if len(impact.Rows) != 1 || impact.Rows[0][4] != "2" ||
		impact.Rows[0][5] != "1" || impact.Rows[0][6] != "192.0.2.10" {
		t.Fatalf("Excel impact count diverged from shared report model: %+v", impact.Rows)
	}
}
