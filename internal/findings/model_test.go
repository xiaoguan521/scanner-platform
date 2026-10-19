package findings

import (
	"math"
	"scanner-platform/internal/taskflow"
	"testing"
)

func TestRiskClassificationDoesNotClaimVersionPrincipleVerification(t *testing.T) {
	for _, tc := range []struct {
		score float64
		want  string
	}{{0, "LOW"}, {3.99, "LOW"}, {4, "MEDIUM"}, {6.99, "MEDIUM"}, {7, "HIGH"}, {8.99, "HIGH"}, {9, "CRITICAL"}, {10, "CRITICAL"}} {
		if got := SeverityFromCVSS(tc.score); got != tc.want {
			t.Fatalf("score %g: %s", tc.score, got)
		}
	}
	d := Normalize(taskflow.Detection{Engine: "trivy", TemplateID: "CVE-2099-0001", Target: "192.0.2.10:22", Package: "example", InstalledVersion: "1.0"})
	if d.DetectMethod != "version" || d.Confidence != "medium" || d.Port != 22 || d.Evidence == "" {
		t.Fatalf("wrong detection metadata: %+v", d)
	}
	for _, v := range []float64{-1, 11, math.NaN(), math.Inf(1)} {
		if ValidMetadata(taskflow.Detection{CVSSScore: &v}) {
			t.Fatal("invalid CVSS accepted")
		}
	}
	if ValidMetadata(taskflow.Detection{RiskType: "weak_credential"}) {
		t.Fatal("disabled capability accepted")
	}
	for _, cap := range Capabilities() {
		if cap.ID == "weak_credential" && (cap.Status != "disabled" || cap.Message != "本次未启用该检测项") {
			t.Fatal(cap)
		}
	}
}
func TestVersionMatchingBoundariesAndUnsupportedVendorSuffix(t *testing.T) {
	score := 9.1
	k := KnowledgeEntry{ID: "EXAMPLE-001", Title: "示例组件风险", Component: "tomcat", Source: "手工维护的公开公告摘要", CVSSScore: &score, AffectedRanges: []VersionRange{{Introduced: "9.0.0", Fixed: "9.0.10"}}, Language: "zh-CN"}
	if err := ValidateKnowledge(k); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		v    string
		want bool
	}{{"8.9.9", false}, {"9.0.0", true}, {"9.0.9", true}, {"9.0.10", false}, {"9.0.9-4.el7", false}, {"9.0.10-rc2", true}} {
		d, ok := Match(k, "Apache Tomcat", tc.v, "192.0.2.10:8080")
		if ok != tc.want {
			t.Fatalf("version %s match=%v", tc.v, ok)
		}
		if ok && (d.Severity != "CRITICAL" || d.DetectMethod != "version") {
			t.Fatal(d)
		}
	}
	if n, ok := CompareVersion("1.0.0-rc10", "1.0.0-rc2"); !ok || n <= 0 {
		t.Fatal("prerelease numeric ordering")
	}
	k.AffectedRanges = []VersionRange{{Introduced: "3.0", Fixed: "2.0"}}
	if ValidateKnowledge(k) == nil {
		t.Fatal("reversed interval accepted")
	}
}
func FuzzCompareVersion(f *testing.F) {
	for _, v := range []string{"1.0", "v2.3.4", "1.0.0-rc1", "0", "1.0-4.el7"} {
		f.Add(v)
	}
	f.Fuzz(func(t *testing.T, v string) {
		if n, ok := CompareVersion(v, v); ok && n != 0 {
			t.Fatal("self ordering changed")
		}
	})
}
