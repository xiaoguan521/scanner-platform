// Package reporting renders versioned, immutable report snapshots without network access.
package reporting

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"
	"time"
	"unicode"
)

const SchemaVersion = 1
const MaxFileBytes int64 = 64 << 20
const MaxSnapshotBytes = 32 << 20

var ErrInvalid = errors.New("invalid report request")
var ErrTooLarge = errors.New("报告超过大小上限（64 MiB），请缩小报告范围")

type Scope struct {
	TaskID        string `json:"taskId,omitempty"`
	AssetID       string `json:"assetId,omitempty"`
	BusinessGroup string `json:"businessGroup,omitempty"`
	From          string `json:"from,omitempty"`
	To            string `json:"to,omitempty"`
}
type Request struct {
	TemplateID string `json:"templateId"`
	Format     string `json:"format"`
	Scope      Scope  `json:"scope"`
}
type Template struct {
	ID         string          `json:"id"`
	Name       string          `json:"name"`
	Company    string          `json:"company"`
	Logo       string          `json:"logo,omitempty"`
	Header     string          `json:"header"`
	Footer     string          `json:"footer"`
	RatingText string          `json:"ratingText"`
	Advice     string          `json:"advice"`
	Sections   map[string]bool `json:"sections"`
}
type Job struct {
	ID              string    `json:"id"`
	Name            string    `json:"name"`
	TemplateID      string    `json:"templateId"`
	Format          string    `json:"format"`
	Scope           Scope     `json:"scope"`
	Status          string    `json:"status"`
	Progress        int       `json:"progress"`
	FileName        string    `json:"fileName"`
	FileSize        int64     `json:"fileSize"`
	CreatedBy       string    `json:"createdBy"`
	CreatedAt       time.Time `json:"createdAt"`
	SnapshotVersion int       `json:"snapshotVersion"`
	SnapshotID      string    `json:"snapshotId"`
	Error           string    `json:"error,omitempty"`
	Attempts        int       `json:"attempts"`
	FilePath        string    `json:"-"`
}
type LoginEntry struct {
	Type           string `json:"type"`
	Name           string `json:"name"`
	Port           int    `json:"port"`
	URL            string `json:"url"`
	HTTPS          bool   `json:"https"`
	Captcha        *bool  `json:"captcha,omitempty"`
	AntiBruteForce *bool  `json:"antiBruteForce,omitempty"`
	Evidence       string `json:"evidence"`
}
type Service struct {
	LoginEntries     []LoginEntry `json:"loginEntries"`
	Quarantined      bool         `json:"quarantined"`
	QuarantineReason string       `json:"quarantineReason"`
	Port             int          `json:"port"`
	Protocol         string       `json:"protocol"`
	State            string       `json:"state"`
	Service          string       `json:"service"`
	ServiceName      string       `json:"serviceName"`
	Software         string       `json:"software"`
	Version          string       `json:"version"`
	Middleware       string       `json:"middleware"`
	Language         string       `json:"language"`
	Framework        string       `json:"framework"`
	Database         string       `json:"database"`
	Application      string       `json:"application"`
	URL              string       `json:"url"`
	Title            string       `json:"title"`
	TLS              bool         `json:"tls"`
	Excluded         bool         `json:"excluded"`
	Kind             string       `json:"kind"`
	Scheme           string       `json:"scheme"`
	FirstSeen        string       `json:"firstSeen"`
	LastSeen         string       `json:"lastSeen"`
}
type Asset struct {
	ID                    string       `json:"id"`
	Kind                  string       `json:"kind"`
	Address               string       `json:"address"`
	Name                  string       `json:"name"`
	Core                  bool         `json:"isCore"`
	BusinessGroup         string       `json:"businessGroup"`
	Owner                 string       `json:"owner"`
	Department            string       `json:"department"`
	Phone                 string       `json:"phone"`
	MAC                   string       `json:"mac"`
	OSName                string       `json:"osName"`
	OSFamily              string       `json:"osFamily"`
	DeviceType            string       `json:"deviceType"`
	DeviceSubtype         string       `json:"deviceSubtype"`
	Vendor                string       `json:"vendor"`
	Model                 string       `json:"model"`
	ReachabilityStatus    string       `json:"reachabilityStatus"`
	ReachabilityCheckedAt string       `json:"reachabilityCheckedAt"`
	Alive                 *bool        `json:"alive,omitempty"`
	LastAliveAt           string       `json:"lastAliveAt"`
	Services              []Service    `json:"services"`
	LoginEntries          []LoginEntry `json:"loginEntries"`
	SkippedPorts          []int        `json:"skippedPorts"`
	QuarantinedPorts      []int        `json:"quarantinedPorts"`
	Ports                 []struct {
		Port int    `json:"port"`
		Kind string `json:"kind"`
	} `json:"ports"`
}
type Finding struct {
	ContentLanguage      string              `json:"contentLanguage"`
	ID                   string              `json:"id"`
	TaskID               string              `json:"taskId"`
	Fingerprint          string              `json:"fingerprint"`
	Severity             string              `json:"severity"`
	Title                string              `json:"title"`
	Engine               string              `json:"engine"`
	TemplateOrCVE        string              `json:"templateOrCve"`
	Target               string              `json:"target"`
	Status               string              `json:"status"`
	FirstSeen            time.Time           `json:"firstSeen"`
	LastSeen             time.Time           `json:"lastSeen"`
	BusinessGroup        string              `json:"businessGroup"`
	Owner                string              `json:"owner"`
	Description          string              `json:"description"`
	RiskType             string              `json:"riskType"`
	DetectMethod         string              `json:"detectMethod"`
	Confidence           string              `json:"confidence"`
	CVSSScore            *float64            `json:"cvssScore,omitempty"`
	VulnCategory         string              `json:"vulnCategory"`
	Identifiers          map[string][]string `json:"identifiers"`
	Impact               string              `json:"impact"`
	Solution             string              `json:"solution"`
	References           []string            `json:"references"`
	Evidence             string              `json:"evidence"`
	Port                 int                 `json:"port"`
	Component            string              `json:"component"`
	Package              string              `json:"package"`
	InstalledVersion     string              `json:"installedVersion"`
	FixedVersion         string              `json:"fixedVersion"`
	MatchedPath          string              `json:"matchedPath"`
	Ports                []int               `json:"ports,omitempty"`
	AssetAddress         string              `json:"assetAddress"`
	LoginType            string              `json:"loginType"`
	HTTPS                *bool               `json:"https,omitempty"`
	Captcha              *bool               `json:"captcha,omitempty"`
	BruteForceProtection *bool               `json:"bruteForceProtection,omitempty"`
}
type Profile struct {
	OSName        string `json:"osName"`
	OSFamily      string `json:"osFamily"`
	DeviceType    string `json:"deviceType"`
	DeviceSubtype string `json:"deviceSubtype"`
	Vendor        string `json:"vendor"`
	Model         string `json:"model"`
}
type Task struct {
	Engines             []string `json:"engines"`
	EffectiveExclusions []struct {
		Start int `json:"start"`
		End   int `json:"end"`
	} `json:"effectiveExclusions"`
	PortProbeResults []struct {
		Port int `json:"port"`
	} `json:"portProbeResults"`
	AssetProfile     Profile   `json:"assetProfile"`
	SkippedTargets   []string  `json:"skippedTargets"`
	ID               string    `json:"id"`
	Status           string    `json:"status"`
	ScopeName        string    `json:"scopeName"`
	AssetID          string    `json:"assetId"`
	CreatedAt        time.Time `json:"createdAt"`
	SystemScanStatus string    `json:"systemScanStatus"`
	ServiceResults   []Service `json:"serviceResults"`
	PortProbeConfig  struct {
		ExcludePorts  []int `json:"excludePorts"`
		ExcludedPorts []int `json:"excludedPorts"`
		Exclusions    []struct {
			Start int `json:"start"`
			End   int `json:"end"`
		} `json:"exclusions"`
	} `json:"portProbeConfig"`
	Chunks []struct {
		Targets        []string `json:"targets"`
		CompletedFully bool     `json:"completedFully"`
	} `json:"chunks"`
}
type Summary struct {
	Assessment              string         `json:"assessment"`
	SystemDetectionComplete bool           `json:"systemDetectionComplete"`
	Assets                  int            `json:"assets"`
	AliveAssets             int            `json:"aliveAssets"`
	UnknownAliveAssets      int            `json:"unknownAliveAssets"`
	RiskAssets              int            `json:"riskAssets"`
	SystemVulnerabilities   int            `json:"systemVulnerabilities"`
	WebVulnerabilities      int            `json:"webVulnerabilities"`
	Vulnerabilities         int            `json:"vulnerabilities"`
	LoginEntries            int            `json:"loginEntries"`
	VersionInferences       int            `json:"versionInferences"`
	Verified                int            `json:"verified"`
	Level                   string         `json:"level"`
	Severity                map[string]int `json:"severity"`
}
type Snapshot struct {
	SchemaVersion int       `json:"schemaVersion"`
	ID            string    `json:"id"`
	Name          string    `json:"name"`
	CreatedAt     time.Time `json:"createdAt"`
	Scope         Scope     `json:"scope"`
	Template      Template  `json:"template"`
	Assets        []Asset   `json:"assets"`
	Tasks         []Task    `json:"tasks"`
	Findings      []Finding `json:"findings"`
	Summary       Summary   `json:"summary"`
	Exclusions    []string  `json:"exclusions"`
	Notes         []string  `json:"notes"`
}

func DefaultTemplate() Template {
	return Template{ID: "default", Name: "全面扫描报告", Company: "安全运营中心", Header: "资产安全评估", Footer: "内部资料 · 请妥善保管", RatingText: "单一系统漏洞、单一 Web 漏洞均按 CVSS：9–10 严重；7–<9 高危；4–<7 中危；0–<4 低危。单一资产与总体取范围内最高漏洞等级，顺序为严重 > 高危 > 中危 > 低危 > 安全。登录入口单独统计。", Advice: "优先修复严重和高危漏洞；按责任人制定修复计划并复测。版本推断建议登录主机核查，或使用主机本地扫描。未检出不代表不存在风险。", Sections: map[string]bool{}}
}
func ValidateRequest(r Request) error {
	if r.Format != "html" && r.Format != "xlsx" && r.Format != "docx" && r.Format != "csv" && r.Format != "json" && r.Format != "pdf" {
		return fmt.Errorf("%w: 只支持 HTML、Excel、Word、CSV、JSON 或 PDF", ErrInvalid)
	}
	if len(r.TemplateID) > 100 || len(r.Scope.TaskID) > 200 || len(r.Scope.AssetID) > 200 || len(r.Scope.BusinessGroup) > 200 {
		return ErrInvalid
	}
	for _, v := range []string{r.Scope.From, r.Scope.To} {
		if v != "" {
			if _, err := time.Parse(time.RFC3339Nano, v); err != nil {
				return fmt.Errorf("%w: 时间需为 RFC3339", ErrInvalid)
			}
		}
	}
	if r.Scope.From != "" && r.Scope.To != "" {
		from, _ := time.Parse(time.RFC3339Nano, r.Scope.From)
		to, _ := time.Parse(time.RFC3339Nano, r.Scope.To)
		if from.After(to) {
			return fmt.Errorf("%w: 时间范围顺序无效", ErrInvalid)
		}
	}
	return nil
}
func TargetHost(target string) string {
	if u, err := url.Parse(target); err == nil && u.Host != "" {
		return u.Hostname()
	}
	if h, _, err := net.SplitHostPort(target); err == nil {
		return strings.Trim(h, "[]")
	}
	return strings.Trim(target, "[]")
}
func Severity(score *float64, fallback string) string {
	if score != nil {
		switch {
		case *score >= 9:
			return "CRITICAL"
		case *score >= 7:
			return "HIGH"
		case *score >= 4:
			return "MEDIUM"
		default:
			return "LOW"
		}
	}
	switch strings.ToUpper(fallback) {
	case "CRITICAL", "HIGH", "MEDIUM", "LOW":
		return strings.ToUpper(fallback)
	}
	return "INFO"
}
func Rank(severity string) int {
	return map[string]int{"SAFE": 0, "INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}[severity]
}
func Label(value string) string {
	if v, ok := map[string]string{"SAFE": "安全", "CRITICAL": "严重", "HIGH": "高危", "MEDIUM": "中危", "LOW": "低危", "INFO": "信息", "system": "系统漏洞", "web": "Web 漏洞", "login_entry": "登录入口", "weak_credential": "弱口令", "principle": "原理验证", "version": "版本推断", "configuration": "配置检查", "HIGH_CONFIDENCE": "高", "MEDIUM_CONFIDENCE": "中", "LOW_CONFIDENCE": "低", "unknown": "未知", "original": "原文，待中文化", "zh-CN": "中文", "high": "高", "medium": "中", "low": "低"}[value]; ok {
		return v
	}
	return value
}
func Name(first string, n int, plan string, at time.Time) string {
	if first == "" {
		first = "全部资产"
	}
	raw := fmt.Sprintf("%s等%d个目标_%s_%s", first, n, plan, at.Format("20060102_150405"))
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || strings.ContainsRune(`/\:*?"<>|`, r) {
			return '_'
		}
		return r
	}, raw)
}

// Freeze normalizes finding metadata and deduplicates stable finding fingerprints.
// A vulnerability observed on two ports remains two distinct findings.
func Freeze(s Snapshot) Snapshot {
	s.SchemaVersion = SchemaVersion
	if s.CreatedAt.IsZero() {
		s.CreatedAt = time.Now().UTC()
	}
	s.Summary = Summary{Assets: len(s.Assets), Level: "SAFE", Severity: map[string]int{"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}}
	owners := map[string]Asset{}
	riskAssets := map[string]bool{}
	for _, a := range s.Assets {
		owners[a.Address] = a
		if a.Alive != nil && *a.Alive || a.ReachabilityStatus == "REACHABLE" {
			s.Summary.AliveAssets++
		} else if a.Alive == nil {
			s.Summary.UnknownAliveAssets++
		}
		for _, p := range a.SkippedPorts {
			s.Exclusions = append(s.Exclusions, fmt.Sprintf("%s:%d（资产排除）", a.Address, p))
		}
		for _, p := range a.QuarantinedPorts {
			s.Exclusions = append(s.Exclusions, fmt.Sprintf("%s:%d（隔离）", a.Address, p))
		}
		for _, p := range a.Ports {
			if p.Kind == "EXCLUDED_PROXY" {
				s.Exclusions = append(s.Exclusions, fmt.Sprintf("%s:%d（代理排除）", a.Address, p.Port))
			}
		}
	}
	for _, t := range s.Tasks {
		for _, r := range t.EffectiveExclusions {
			s.Exclusions = append(s.Exclusions, fmt.Sprintf("任务 %s：TCP %d–%d（生效排除）", t.ID, r.Start, r.End))
		}
		for _, r := range t.PortProbeConfig.Exclusions {
			s.Exclusions = append(s.Exclusions, fmt.Sprintf("任务 %s：TCP %d–%d", t.ID, r.Start, r.End))
		}
		for _, target := range t.SkippedTargets {
			s.Exclusions = append(s.Exclusions, target+"（任务跳过）")
		}
	}
	normalized := []Finding{}
	seen := map[string]int{}
	for _, f := range s.Findings {
		if f.RiskType == "weak_credential" {
			continue
		}
		if f.RiskType == "" {
			if strings.Contains(f.Engine, "trivy") {
				f.RiskType = "system"
			} else {
				f.RiskType = "web"
			}
		}
		if f.DetectMethod == "" {
			f.DetectMethod = "未知（历史记录未标注）"
		}
		if f.Confidence == "" {
			f.Confidence = "未知"
		}
		f.Severity = Severity(f.CVSSScore, f.Severity)
		f.AssetAddress = TargetHost(f.Target)
		if a, ok := owners[f.AssetAddress]; ok {
			f.BusinessGroup = a.BusinessGroup
			f.Owner = a.Owner
		}
		if f.Port == 0 {
			if _, p, err := net.SplitHostPort(f.Target); err == nil {
				fmt.Sscanf(p, "%d", &f.Port)
			}
		}
		if f.Port > 0 {
			f.Ports = append(f.Ports, f.Port)
		}
		rule := f.Fingerprint
		if rule == "" {
			rule = f.ID
		}
		if rule == "" {
			rule = f.TemplateOrCVE + "\x00" + f.Target + "\x00" + f.MatchedPath + "\x00" + f.Package
		}
		key := f.AssetAddress + "\x00" + f.RiskType + "\x00" + rule
		if at, ok := seen[key]; ok {
			old := &normalized[at]
			old.Ports = append(old.Ports, f.Ports...)
			if Rank(f.Severity) > Rank(old.Severity) {
				old.Severity = f.Severity
				old.CVSSScore = f.CVSSScore
			}
			continue
		}
		seen[key] = len(normalized)
		normalized = append(normalized, f)
	}
	s.Findings = normalized
	for i := range s.Findings {
		f := &s.Findings[i]
		sort.Ints(f.Ports)
		f.Ports = uniqueInts(f.Ports)
		if f.RiskType == "login_entry" {
			s.Summary.LoginEntries++
			continue
		}
		if f.RiskType != "system" && f.RiskType != "web" {
			continue
		}
		s.Summary.Vulnerabilities++
		if f.RiskType == "system" {
			s.Summary.SystemVulnerabilities++
		} else {
			s.Summary.WebVulnerabilities++
		}
		s.Summary.Severity[f.Severity]++
		riskAssets[f.AssetAddress] = true
		if Rank(f.Severity) > Rank(s.Summary.Level) {
			s.Summary.Level = f.Severity
		}
		if f.DetectMethod == "version" || f.DetectMethod == "版本推断" {
			s.Summary.VersionInferences++
		}
		if f.DetectMethod == "principle" || f.DetectMethod == "configuration" || f.DetectMethod == "原理验证" || f.DetectMethod == "配置检查" {
			s.Summary.Verified++
		}
	}
	s.Summary.SystemDetectionComplete = len(s.Tasks) > 0
	for _, task := range s.Tasks {
		complete := task.Status == "COMPLETED" && task.SystemScanStatus == "已通过 SSH 临时采集并完成本地系统包检查"
		for _, engine := range task.Engines {
			if engine == "trivy" && task.Status == "COMPLETED" {
				complete = true
			}
		}
		if !complete {
			s.Summary.SystemDetectionComplete = false
		}
	}
	s.Summary.Assessment = Label(s.Summary.Level)
	if s.Summary.Level == "SAFE" {
		if s.Summary.Vulnerabilities > 0 {
			s.Summary.Assessment = "仅信息项（不作无风险承诺）"
		} else {
			s.Summary.Assessment = "当前记录未检出漏洞"
		}
	}
	if !s.Summary.SystemDetectionComplete {
		s.Summary.Assessment += "；本次系统检测未完成"
		s.Notes = append(s.Notes, "本次系统检测未完成或范围未充分覆盖；系统漏洞显示 0 条仅表示当前记录未检出，不代表主机系统已验证安全。")
	}
	s.Summary.LoginEntries = len(loginTable(s).Rows)
	s.Summary.RiskAssets = len(riskAssets)
	sort.Slice(s.Assets, func(i, j int) bool { return s.Assets[i].Address < s.Assets[j].Address })
	sort.Slice(s.Findings, func(i, j int) bool {
		a, b := s.Findings[i], s.Findings[j]
		if Rank(a.Severity) != Rank(b.Severity) {
			return Rank(a.Severity) > Rank(b.Severity)
		}
		if a.AssetAddress != b.AssetAddress {
			return a.AssetAddress < b.AssetAddress
		}
		return a.ID < b.ID
	})
	sort.Strings(s.Exclusions)
	s.Exclusions = uniqueStrings(s.Exclusions)
	sort.Strings(s.Notes)
	s.Notes = uniqueStrings(s.Notes)
	first := ""
	if len(s.Assets) > 0 {
		first = s.Assets[0].Address
	}
	s.Name = Name(first, len(s.Assets), s.Template.Name, s.CreatedAt)
	s.ID = ""
	raw, _ := json.Marshal(s)
	sum := sha256.Sum256(raw)
	s.ID = hex.EncodeToString(sum[:])
	return s
}
func uniqueInts(a []int) []int {
	out := []int{}
	for _, v := range a {
		if len(out) == 0 || out[len(out)-1] != v {
			out = append(out, v)
		}
	}
	return out
}
func uniqueStrings(a []string) []string {
	out := []string{}
	for _, v := range a {
		if len(out) == 0 || out[len(out)-1] != v {
			out = append(out, v)
		}
	}
	return out
}
