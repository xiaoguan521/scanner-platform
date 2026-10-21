package reporting

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"image/png"
	"io"
	"os"
	"path/filepath"
	"scanner-platform/internal/inventory"
	"strings"
	"testing"
	"time"
)

func exampleSnapshot() Snapshot {
	score := 9.1
	at := time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC)
	login := LoginEntry{Type: "web", Name: "示例登录", Port: 443, URL: "https://192.0.2.10/login", HTTPS: true, Evidence: "仅识别登录表单，未尝试认证"}
	s := Snapshot{CreatedAt: at, Template: DefaultTemplate(), Assets: []Asset{{ID: "a", Address: "192.0.2.10", Name: "示例资产", OSName: "Example Linux", DeviceType: "服务器", RuntimeServices: []inventory.RuntimeService{{Name: "sshd", Manager: "process", State: "running"}}, ReachabilityStatus: "NO_RESPONSE", Services: []Service{{Port: 443, Kind: "WEB", Protocol: "tcp", Software: "example", Version: "1.0", URL: "https://192.0.2.10", Title: "示例网站", LoginEntries: []LoginEntry{login}}}, LoginEntries: []LoginEntry{login}}}, Findings: []Finding{{ID: "one", Fingerprint: "f1", RiskType: "system", Title: "示例系统风险", Target: "192.0.2.10:443", TemplateOrCVE: "CVE-2026-0001", CVSSScore: &score, DetectMethod: "version", Confidence: "low", Description: "版本推断说明", Impact: "可能影响机密性", Solution: "升级修复版本", Evidence: "example:1.0", Identifiers: map[string][]string{"cve": {"CVE-2026-0001"}}, LastSeen: at}, {ID: "two", Fingerprint: "f2", RiskType: "web", Title: "示例 Web 风险<script>", Target: "192.0.2.10:443", Severity: "MEDIUM", TemplateOrCVE: "example-header", DetectMethod: "configuration", Confidence: "high", Evidence: "安全响应头缺失", LastSeen: at}}}
	return Freeze(s)
}
func TestSeverityBoundaries(t *testing.T) {
	for _, tc := range []struct {
		v    float64
		want string
	}{{0, "LOW"}, {3.99, "LOW"}, {4, "MEDIUM"}, {6.99, "MEDIUM"}, {7, "HIGH"}, {8.99, "HIGH"}, {9, "CRITICAL"}, {10, "CRITICAL"}} {
		if got := Severity(&tc.v, "INFO"); got != tc.want {
			t.Errorf("%v: %s", tc.v, got)
		}
	}
	if Severity(nil, "HIGH") != "HIGH" {
		t.Fatal("unknown score lost supplied severity")
	}
}
func TestSummaryUsesFindingFingerprintsAndSeparatesLogins(t *testing.T) {
	s := exampleSnapshot()
	s.Findings = append(s.Findings, s.Findings[0])
	other := s.Findings[0]
	other.ID = "different-port"
	other.Fingerprint = "other-port"
	other.Target = "192.0.2.10:8443"
	other.Port = 8443
	s.Findings = append(s.Findings, other, Finding{ID: "weak", RiskType: "weak_credential", Target: "192.0.2.10:443", Severity: "CRITICAL"})
	s = Freeze(s)
	if s.Summary.Vulnerabilities != 3 || s.Summary.SystemVulnerabilities != 2 || s.Summary.WebVulnerabilities != 1 || s.Summary.LoginEntries != 1 || s.Summary.RiskAssets != 1 || s.Summary.Level != "CRITICAL" || s.Summary.VersionInferences != 2 || s.Summary.Verified != 1 {
		t.Fatalf("bad summary: %+v", s.Summary)
	}
	if s.Summary.UnknownAliveAssets != 1 || s.Summary.AliveAssets != 0 {
		t.Fatal("no ICMP response was treated as offline")
	}
	if len(s.Findings) != 3 {
		t.Fatal("weak/duplicate records not removed")
	}
	s.Findings = []Finding{{ID: "login", Fingerprint: "login", RiskType: "login_entry", Severity: "CRITICAL", Target: "192.0.2.10:443"}}
	s = Freeze(s)
	if s.Summary.Level != "SAFE" || s.Summary.Vulnerabilities != 0 {
		t.Fatal("login changed vulnerability grade")
	}
}
func unzip(t *testing.T, data []byte) map[string]string {
	t.Helper()
	z, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, f := range z.File {
		r, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		b, err := io.ReadAll(r)
		r.Close()
		if err != nil {
			t.Fatal(err)
		}
		if strings.HasSuffix(f.Name, ".xml") || strings.HasSuffix(f.Name, ".rels") {
			dec := xml.NewDecoder(bytes.NewReader(b))
			for {
				_, err := dec.Token()
				if errors.Is(err, io.EOF) {
					break
				}
				if err != nil {
					t.Fatalf("invalid XML %s: %v", f.Name, err)
				}
			}
			out[f.Name] = string(b)
		} else if strings.HasSuffix(f.Name, ".png") {
			if _, err := png.Decode(bytes.NewReader(b)); err != nil {
				t.Fatalf("bad PNG: %v", err)
			}
		}
	}
	return out
}
func xmlText(t *testing.T, document string) string {
	t.Helper()
	d := xml.NewDecoder(strings.NewReader(document))
	var out strings.Builder
	for {
		tok, err := d.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if chars, ok := tok.(xml.CharData); ok {
			out.Write(chars)
		}
	}
	return out.String()
}
func TestThreeFormatsHaveSameSnapshotAndDetailContent(t *testing.T) {
	s := exampleSnapshot()
	for _, format := range []string{"html", "xlsx", "docx"} {
		t.Run(format, func(t *testing.T) {
			var b bytes.Buffer
			if err := Render(context.Background(), &b, s, format); err != nil {
				t.Fatal(err)
			}
			content := b.String()
			if format != "html" {
				files := unzip(t, b.Bytes())
				content = ""
				for name, value := range files {
					if format == "docx" && name == "word/document.xml" || format == "xlsx" && strings.HasPrefix(name, "xl/worksheets/sheet") {
						content += xmlText(t, value)
					}
				}
				if format == "xlsx" {
					workbook := files["xl/workbook.xml"]
					if strings.Count(workbook, "<sheet ") != 8 {
						t.Fatal("expected eight worksheets")
					}
					if !strings.Contains(files["xl/worksheets/sheet6.xml"], `t="inlineStr"`) {
						t.Fatal("finding cells must remain text")
					}
				}
			}
			for _, value := range []string{s.ID, "示例系统风险", "CVE-2026-0001", "版本推断", "置信度", "example:1.0", "示例登录", "sshd", "弱口令", "未启用"} {
				if !strings.Contains(content, value) {
					t.Errorf("missing %q", value)
				}
			}
			if format == "html" && strings.Contains(content, "<script>") {
				t.Fatal("unescaped HTML finding")
			}
			if strings.Contains(content, "弱口令：0") || strings.Contains(content, "弱口令 0") {
				t.Fatal("disabled capability rendered as zero")
			}
		})
	}
	d := BuildDocument(s)
	if len(d.Sections) != 8 {
		t.Fatal("expected eight chapters")
	}
	if len(Workbook(s)) != 8 {
		t.Fatal("expected eight worksheets")
	}
}

func TestPDFFormatContainsSnapshotTextAndUsesCJKFont(t *testing.T) {
	s := exampleSnapshot()
	var b bytes.Buffer
	if err := Render(context.Background(), &b, s, "pdf"); err != nil {
		t.Fatal(err)
	}
	content := b.String()
	if !strings.HasPrefix(content, "%PDF-1.4") || !strings.Contains(content, "xref") || !strings.Contains(content, "/Subtype /Type0") {
		t.Fatalf("invalid PDF structure: %q", content[:min(len(content), 120)])
	}
	for _, value := range []string{s.ID, "示例系统风险", "CVE-2026-0001", "本次未启用该检测项"} {
		if !strings.Contains(content, strings.Trim(pdfTextHex(value), "<>")) {
			t.Errorf("PDF missing %q", value)
		}
	}
	if strings.Contains(content, "<script>") {
		t.Fatal("PDF retained raw HTML markup")
	}
}
func TestTopLimitsAndDistinctAffectedAssets(t *testing.T) {
	s := exampleSnapshot()
	s.Findings = nil
	for i := 0; i < 120; i++ {
		s.Findings = append(s.Findings, Finding{ID: fmt.Sprintf("item%d", i), Fingerprint: fmt.Sprintf("fp%d", i), RiskType: "web", TemplateOrCVE: fmt.Sprintf("rule%d", i), Target: "192.0.2.10:443", Severity: "HIGH"})
	}
	s = Freeze(s)
	if got := influenceTable(s, "web", 100); len(got.Rows) != 100 || !got.Truncated {
		t.Fatal("top100 missing")
	}
	if len(findingTable(s).Rows) != 120 {
		t.Fatal("full Excel detail was truncated")
	}
	s.Findings = nil
	for i := 1; i <= 12; i++ {
		s.Findings = append(s.Findings, Finding{ID: fmt.Sprint(i), RiskType: "web", TemplateOrCVE: "same-rule", AssetAddress: fmt.Sprintf("192.0.2.%d", i), Severity: "HIGH"})
	}
	tab := influenceTable(s, "web", 100)
	if len(tab.Rows) != 1 || tab.Rows[0][5] != "12" || strings.Count(tab.Rows[0][6], "192.0.2.") != 10 {
		t.Fatalf("asset limit: %+v", tab)
	}
}
func TestTemplateRejectsRemoteLogoAndFreezeIsStable(t *testing.T) {
	tpl := DefaultTemplate()
	tpl.Logo = "https://example.com/logo.png"
	if ValidateTemplate(tpl) == nil {
		t.Fatal("remote logo accepted")
	}
	c := chart(Table{})
	tpl.Logo = "data:image/png;base64," + base64.StdEncoding.EncodeToString(c.PNG)
	if err := ValidateTemplate(tpl); err != nil {
		t.Fatal(err)
	}
	s := exampleSnapshot()
	if again := Freeze(s); again.ID != s.ID {
		t.Fatalf("unstable immutable snapshot: %s != %s", again.ID, s.ID)
	}
	s.Template.Sections["assets"] = false
	if len(BuildDocument(s).Sections) != 7 {
		t.Fatal("section toggle ignored")
	}
}
func TestRenderBoundsCancellationAndUnsupportedSchema(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := Render(ctx, io.Discard, exampleSnapshot(), "html"); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel: %v", err)
	}
	w := boundedWriter{ctx: context.Background(), w: io.Discard, n: MaxFileBytes - 1}
	if _, err := w.Write([]byte("xx")); !errors.Is(err, ErrTooLarge) {
		t.Fatal("size limit ignored")
	}
	s := exampleSnapshot()
	s.SchemaVersion++
	if Render(context.Background(), io.Discard, s, "docx") == nil {
		t.Fatal("future snapshot schema accepted")
	}
}
func TestSpreadsheetFormulaIsText(t *testing.T) {
	s := exampleSnapshot()
	s.Findings[0].Title = "=HYPERLINK(\"https://example.com\")"
	var b bytes.Buffer
	if err := Render(context.Background(), &b, s, "xlsx"); err != nil {
		t.Fatal(err)
	}
	files := unzip(t, b.Bytes())
	value := files["xl/worksheets/sheet6.xml"]
	if strings.Contains(value, "<f>") || !strings.Contains(value, "=HYPERLINK") {
		t.Fatal("formula was evaluated or dropped")
	}
}

func TestCSVAndJSONFormats(t *testing.T) {
	s := exampleSnapshot()
	s.Findings[0].Title = "=SUM(A1:A2)"
	s = Freeze(s)
	var csvOutput bytes.Buffer
	if err := Render(context.Background(), &csvOutput, s, "csv"); err != nil {
		t.Fatal(err)
	}
	records, err := csv.NewReader(bytes.NewReader(csvOutput.Bytes())).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 3 || records[0][0] != "资产" || records[0][2] != "标题" {
		t.Fatalf("unexpected CSV shape: %v", records)
	}
	if records[1][2] != "'=SUM(A1:A2)" {
		t.Fatalf("formula cell was not neutralized: %q", records[1][2])
	}
	var jsonOutput bytes.Buffer
	if err := Render(context.Background(), &jsonOutput, s, "json"); err != nil {
		t.Fatal(err)
	}
	var decoded Snapshot
	if err := json.Unmarshal(jsonOutput.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.ID != s.ID || decoded.SchemaVersion != SchemaVersion || len(decoded.Findings) != len(s.Findings) || decoded.Findings[0].Title != s.Findings[0].Title {
		t.Fatalf("JSON did not preserve frozen snapshot: %+v", decoded)
	}
	for _, format := range []string{"csv", "json", "pdf"} {
		if err := ValidateRequest(Request{Format: format}); err != nil {
			t.Fatalf("%s rejected: %v", format, err)
		}
	}
}

func FuzzTargetHost(f *testing.F) {
	for _, v := range []string{"192.0.2.10:443", "https://192.0.2.10/login", "[2001:db8::10]:443", "example.com"} {
		f.Add(v)
	}
	f.Fuzz(func(t *testing.T, v string) { _ = TargetHost(v) })
}

// TestExportSyntheticReportArtifacts provides an optional offline visual QA fixture.
// It never reads the platform database or connects to its documentation targets.
func TestExportSyntheticReportArtifacts(t *testing.T) {
	base := os.Getenv("REPORT_QA_OUTPUT_DIR")
	if base == "" {
		t.Skip("set REPORT_QA_OUTPUT_DIR for optional offline artifact inspection")
	}
	dir, err := os.MkdirTemp(base, "scanner-report-fixture-")
	if err != nil {
		t.Fatal(err)
	}
	s := exampleSnapshot()
	for _, format := range []string{"html", "xlsx", "docx", "pdf", "csv", "json"} {
		file, err := os.Create(filepath.Join(dir, "example."+format))
		if err != nil {
			t.Fatal(err)
		}
		err = Render(context.Background(), file, s, format)
		closeErr := file.Close()
		if err != nil {
			t.Fatal(err)
		}
		if closeErr != nil {
			t.Fatal(closeErr)
		}
	}
	t.Logf("synthetic artifacts: %s", dir)
}

func TestIncompleteSystemAndInfoOnlyAssessmentIsExplicit(t *testing.T) {
	s := exampleSnapshot()
	s.Tasks = []Task{{ID: "incomplete", Status: "COMPLETED", Engines: []string{"nuclei"}, SystemScanStatus: "未配置 Worker 本地 SSH 采集"}}
	s.Findings = []Finding{{ID: "informational", Fingerprint: "info", RiskType: "web", Target: "192.0.2.10:443", Severity: "INFO"}}
	s = Freeze(s)
	if !strings.Contains(s.Summary.Assessment, "仅信息项") || !strings.Contains(s.Summary.Assessment, "本次系统检测未完成") || s.Summary.SystemDetectionComplete {
		t.Fatalf("misleading assessment: %+v", s.Summary)
	}
	for _, format := range []string{"html", "xlsx", "docx", "pdf"} {
		var b bytes.Buffer
		if err := Render(context.Background(), &b, s, format); err != nil {
			t.Fatal(err)
		}
		if format == "pdf" {
			if !strings.Contains(b.String(), strings.Trim(pdfTextHex("本次系统检测未完成"), "<>")) || !strings.Contains(b.String(), strings.Trim(pdfTextHex("仅信息项"), "<>")) {
				t.Fatalf("%s missing coverage limitation", format)
			}
			continue
		}
		content := b.String()
		if format != "html" {
			content = ""
			for _, v := range unzip(t, b.Bytes()) {
				content += v
			}
		}
		if !strings.Contains(content, "本次系统检测未完成") || !strings.Contains(content, "仅信息项") {
			t.Fatalf("%s missing coverage limitation", format)
		}
	}
}
