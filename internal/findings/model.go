// Package findings defines the shared detection and report vocabulary.
package findings

import (
	"fmt"
	"math"
	"net"
	"strconv"
	"strings"

	"scanner-platform/internal/taskflow"
)

type Capability struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Status  string `json:"status"`
	Message string `json:"message"`
}

func Capabilities() []Capability {
	return []Capability{
		{"system", "系统漏洞", "enabled", "根据已采集的软件包或组件版本分析；缺少采集时明确标记未完成"},
		{"web", "Web 漏洞", "enabled", "仅在明确范围内执行只读配置检查"},
		{"login_entry", "登录入口发现", "enabled", "仅识别入口，不尝试登录"},
		{"weak_credential", "弱口令", "disabled", "本次未启用该检测项"},
		{"baseline", "主机基线检查", "unavailable", "未提供该检测项"},
	}
}

type Category struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	CWE  string `json:"cwe"`
}

func Categories() []Category {
	names := []struct{ name, cwe string }{{"信息泄露", "CWE-200"}, {"拒绝服务", "CWE-400"}, {"配置不当", "CWE-16"}, {"未授权访问", "CWE-862"}, {"跨站脚本", "CWE-79"}, {"绕过认证", "CWE-287"}, {"代码注入", "CWE-94"}, {"SQL 注入", "CWE-89"}, {"命令注入", "CWE-78"}, {"路径遍历", "CWE-22"}, {"文件包含", "CWE-98"}, {"任意文件读取", "CWE-552"}, {"任意文件写入", "CWE-73"}, {"不安全反序列化", "CWE-502"}, {"服务端请求伪造", "CWE-918"}, {"跨站请求伪造", "CWE-352"}, {"XML 外部实体", "CWE-611"}, {"不安全重定向", "CWE-601"}, {"权限控制", "CWE-284"}, {"权限提升", "CWE-269"}, {"会话管理", "CWE-384"}, {"加密缺陷", "CWE-327"}, {"证书配置", "CWE-295"}, {"不安全传输", "CWE-319"}, {"安全响应头", "CWE-693"}, {"CORS 配置", "CWE-942"}, {"危险方法启用", "CWE-749"}, {"默认页面暴露", "CWE-1188"}, {"软件版本漏洞", "CWE-1395"}, {"资源管理", "CWE-664"}, {"输入验证", "CWE-20"}, {"其他", "CWE-693"}}
	out := make([]Category, 0, len(names))
	for i, n := range names {
		out = append(out, Category{fmt.Sprintf("CAT-%02d", i+1), n.name, n.cwe})
	}
	return out
}
func SeverityFromCVSS(score float64) string {
	switch {
	case score >= 9:
		return "CRITICAL"
	case score >= 7:
		return "HIGH"
	case score >= 4:
		return "MEDIUM"
	default:
		return "LOW"
	}
}
func ValidMetadata(d taskflow.Detection) bool {
	if d.CVSSScore != nil && (math.IsNaN(*d.CVSSScore) || math.IsInf(*d.CVSSScore, 0) || *d.CVSSScore < 0 || *d.CVSSScore > 10) {
		return false
	}
	if d.RiskType != "" && d.RiskType != "system" && d.RiskType != "web" && d.RiskType != "login_entry" {
		return false
	}
	if d.DetectMethod != "" && d.DetectMethod != "unknown" && d.DetectMethod != "principle" && d.DetectMethod != "version" && d.DetectMethod != "configuration" {
		return false
	}
	if d.Confidence != "" && d.Confidence != "unknown" && d.Confidence != "high" && d.Confidence != "medium" && d.Confidence != "low" {
		return false
	}
	if d.ContentLanguage != "" && d.ContentLanguage != "original" && d.ContentLanguage != "zh-CN" {
		return false
	}
	if d.Port < 0 || d.Port > 65535 || len(d.Impact) > 4000 || len(d.Solution) > 4000 || len(d.Evidence) > 4000 || len(d.Component) > 300 || len(d.VulnCategory) > 200 || len(d.References) > 20 || len(d.Identifiers) > 10 {
		return false
	}
	for _, v := range d.References {
		if len(v) > 2000 {
			return false
		}
	}
	for k, values := range d.Identifiers {
		if len(k) > 30 || len(values) > 20 {
			return false
		}
		for _, v := range values {
			if len(v) > 200 {
				return false
			}
		}
	}
	return true
}
func Normalize(d taskflow.Detection) taskflow.Detection {
	if d.RiskType == "" {
		if d.Engine == "trivy" || d.Engine == "knowledge" {
			d.RiskType = "system"
		} else {
			d.RiskType = "web"
		}
	}
	if d.DetectMethod == "" {
		switch d.Engine {
		case "trivy", "knowledge":
			d.DetectMethod = "version"
		case "nuclei", "zap":
			d.DetectMethod = "configuration"
		default:
			d.DetectMethod = "unknown"
		}
	}
	if d.Confidence == "" {
		switch d.DetectMethod {
		case "version":
			d.Confidence = "medium"
		case "principle", "configuration":
			d.Confidence = "high"
		default:
			d.Confidence = "unknown"
		}
	}
	if d.CVSSScore != nil {
		d.Severity = SeverityFromCVSS(*d.CVSSScore)
	}
	if d.Port == 0 {
		_, p, err := net.SplitHostPort(d.Target)
		if err == nil {
			d.Port, _ = strconv.Atoi(p)
		}
	}
	if d.Component == "" {
		d.Component = strings.TrimSpace(d.Package + " " + d.InstalledVersion)
	}
	if d.Identifiers == nil {
		d.Identifiers = map[string][]string{}
	}
	if strings.HasPrefix(strings.ToUpper(d.TemplateID), "CVE-") {
		d.Identifiers["CVE"] = []string{d.TemplateID}
	}
	if len(d.Identifiers["platform"]) == 0 {
		d.Identifiers["platform"] = []string{d.TemplateID}
	}
	if d.VulnCategory == "" {
		if d.DetectMethod == "version" {
			d.VulnCategory = "软件版本漏洞"
		} else {
			d.VulnCategory = "配置不当"
		}
	}
	if d.Evidence == "" && d.DetectMethod == "version" {
		d.Evidence = fmt.Sprintf("组件：%s；匹配规则：%s。依据版本匹配，未进行原理验证。", d.Component, d.TemplateID)
	}
	if d.ContentLanguage == "" {
		d.ContentLanguage = "original"
	}
	return d
}

// Upgrade does not claim that historical results were principle-verified.
func Upgrade(f taskflow.Finding) taskflow.Finding {
	if f.DetectMethod == "" {
		f.DetectMethod = "unknown"
		f.Confidence = "unknown"
	}
	d := Normalize(taskflow.Detection{Engine: f.Engine, TemplateID: f.TemplateOrCVE, Target: f.Target, Package: f.Package, InstalledVersion: f.InstalledVersion, RiskType: f.RiskType, DetectMethod: f.DetectMethod, Confidence: f.Confidence, CVSSScore: f.CVSSScore, VulnCategory: f.VulnCategory, Identifiers: f.Identifiers, Evidence: f.Evidence, Port: f.Port, Component: f.Component, ContentLanguage: f.ContentLanguage})
	f.RiskType, f.DetectMethod, f.Confidence, f.CVSSScore, f.VulnCategory, f.Identifiers, f.Evidence, f.Port, f.Component, f.ContentLanguage = d.RiskType, d.DetectMethod, d.Confidence, d.CVSSScore, d.VulnCategory, d.Identifiers, d.Evidence, d.Port, d.Component, d.ContentLanguage
	if f.CVSSScore != nil {
		f.Severity = d.Severity
	}
	return f
}
