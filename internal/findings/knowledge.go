package findings

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"scanner-platform/internal/taskflow"
)

type VersionRange struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"lastAffected,omitempty"`
}
type KnowledgeEntry struct {
	ID             string              `json:"id"`
	Identifiers    map[string][]string `json:"identifiers"`
	Title          string              `json:"title"`
	Description    string              `json:"description"`
	Impact         string              `json:"impact"`
	Solution       string              `json:"solution"`
	References     []string            `json:"references"`
	CVSSScore      *float64            `json:"cvssScore,omitempty"`
	Category       string              `json:"category"`
	Component      string              `json:"component"`
	AffectedRanges []VersionRange      `json:"affectedRanges"`
	Source         string              `json:"source"`
	UpdatedAt      string              `json:"updatedAt"`
	Language       string              `json:"language"`
}

var knowledgeID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$`)

func ValidateKnowledge(k KnowledgeEntry) error {
	if !knowledgeID.MatchString(k.ID) || strings.TrimSpace(k.Title) == "" || len(k.Title) > 500 || strings.TrimSpace(k.Component) == "" || len(k.Component) > 200 || strings.TrimSpace(k.Source) == "" || len(k.Source) > 1000 || len(k.AffectedRanges) > 100 {
		return fmt.Errorf("invalid knowledge identity, component or source")
	}
	if !ValidMetadata(taskflow.Detection{CVSSScore: k.CVSSScore, Identifiers: k.Identifiers, Impact: k.Impact, Solution: k.Solution, References: k.References}) || len(k.Description) > 8000 {
		return fmt.Errorf("invalid knowledge content")
	}
	for _, r := range k.AffectedRanges {
		if r.Introduced == "" && r.Fixed == "" && r.LastAffected == "" {
			return fmt.Errorf("empty affected range")
		}
		for _, v := range []string{r.Introduced, r.Fixed, r.LastAffected} {
			if v != "" && v != "0" {
				if _, _, ok := versionParts(v); !ok {
					return fmt.Errorf("unsupported version range")
				}
			}
		}
		if r.Fixed != "" && r.LastAffected != "" {
			return fmt.Errorf("use either fixed or lastAffected")
		}
		if r.Introduced != "" && r.Introduced != "0" && r.Fixed != "" {
			if c, ok := CompareVersion(r.Introduced, r.Fixed); !ok || c >= 0 {
				return fmt.Errorf("invalid version interval")
			}
		}
	}
	return nil
}

var versionPattern = regexp.MustCompile(`^[vV]?([0-9]+(?:\.[0-9]+){0,5})(?:-((?:alpha|beta|rc)[0-9.]*))?$`)

func versionParts(v string) ([]uint64, string, bool) {
	m := versionPattern.FindStringSubmatch(v)
	if m == nil {
		return nil, "", false
	}
	out := []uint64{}
	for _, p := range strings.Split(m[1], ".") {
		n, e := strconv.ParseUint(p, 10, 64)
		if e != nil {
			return nil, "", false
		}
		out = append(out, n)
	}
	return out, m[2], true
}
func CompareVersion(a, b string) (int, bool) {
	aa, ap, ok := versionParts(a)
	if !ok {
		return 0, false
	}
	bb, bp, ok := versionParts(b)
	if !ok {
		return 0, false
	}
	for i := 0; i < max(len(aa), len(bb)); i++ {
		var x, y uint64
		if i < len(aa) {
			x = aa[i]
		}
		if i < len(bb) {
			y = bb[i]
		}
		if x < y {
			return -1, true
		}
		if x > y {
			return 1, true
		}
	}
	if ap == bp {
		return 0, true
	}
	if ap == "" {
		return 1, true
	}
	if bp == "" {
		return -1, true
	}
	return comparePrerelease(ap, bp), true
}
func Affected(version string, ranges []VersionRange) bool {
	for _, r := range ranges {
		if _, _, ok := versionParts(version); !ok {
			return false
		}
		if r.Introduced != "" && r.Introduced != "0" {
			c, ok := CompareVersion(version, r.Introduced)
			if !ok || c < 0 {
				continue
			}
		}
		if r.Fixed != "" {
			c, ok := CompareVersion(version, r.Fixed)
			if !ok || c >= 0 {
				continue
			}
		}
		if r.LastAffected != "" {
			c, ok := CompareVersion(version, r.LastAffected)
			if !ok || c > 0 {
				continue
			}
		}
		return true
	}
	return false
}
func canonicalComponent(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	aliases := map[string]string{"apache tomcat": "tomcat", "apache-tomcat": "tomcat", "postgres": "postgresql", "openssh-server": "openssh", "rabbitmq-server": "rabbitmq", "apache kafka": "kafka"}
	if v, ok := aliases[s]; ok {
		return v
	}
	return s
}
func Match(k KnowledgeEntry, component, version, target string) (taskflow.Detection, bool) {
	if canonicalComponent(k.Component) != canonicalComponent(component) || !Affected(version, k.AffectedRanges) {
		return taskflow.Detection{}, false
	}
	confidence := "medium"
	if strings.Contains(canonicalComponent(component), "ssh") || strings.Contains(canonicalComponent(component), "kernel") {
		confidence = "low"
	}
	d := Normalize(taskflow.Detection{Engine: "knowledge", TemplateID: k.ID, Target: target, Title: k.Title, Severity: "INFO", Package: component, InstalledVersion: version, RiskType: "system", DetectMethod: "version", Confidence: confidence, CVSSScore: k.CVSSScore, VulnCategory: k.Category, Identifiers: k.Identifiers, Description: k.Description, Impact: k.Impact, Solution: k.Solution, References: k.References, ContentLanguage: k.Language, Evidence: fmt.Sprintf("识别组件 %s:%s；规则 %s；来源 %s。仅根据版本范围推断，未进行原理验证；发行版可能已回补安全补丁，建议登录主机核查。", component, version, k.ID, k.Source)})
	return d, true
}
func PrepareKnowledge(k KnowledgeEntry) KnowledgeEntry {
	k.ID = strings.TrimSpace(k.ID)
	k.Component = canonicalComponent(k.Component)
	if k.Language == "" {
		k.Language = "original"
	}
	k.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	return k
}

func comparePrerelease(a, b string) int {
	label := regexp.MustCompile(`^(alpha|beta|rc)([0-9.]*)$`)
	aa, bb := label.FindStringSubmatch(a), label.FindStringSubmatch(b)
	rank := map[string]int{"alpha": 0, "beta": 1, "rc": 2}
	if rank[aa[1]] < rank[bb[1]] {
		return -1
	}
	if rank[aa[1]] > rank[bb[1]] {
		return 1
	}
	ap, bp := strings.Split(aa[2], "."), strings.Split(bb[2], ".")
	for i := 0; i < max(len(ap), len(bp)); i++ {
		var x, y uint64
		if i < len(ap) {
			x, _ = strconv.ParseUint(ap[i], 10, 64)
		}
		if i < len(bp) {
			y, _ = strconv.ParseUint(bp[i], 10, 64)
		}
		if x < y {
			return -1
		}
		if x > y {
			return 1
		}
	}
	return 0
}
