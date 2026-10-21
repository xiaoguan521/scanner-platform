package reporting

import (
	"bytes"
	"fmt"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"sort"
	"strconv"
	"strings"
)

type Table struct {
	Title     string
	Headers   []string
	Rows      [][]string
	Truncated bool
}
type Section struct {
	ID         string
	Title      string
	Paragraphs []string
	Tables     []Table
	Charts     []Chart
}
type Chart struct {
	Title  string
	Labels []string
	Counts []int
	PNG    []byte
}
type Document struct {
	Name     string
	Sections []Section
}

func text(v string) string {
	if v == "" {
		return "未采集"
	}
	return v
}
func number(v int) string { return strconv.Itoa(v) }
func boolText(v *bool) string {
	if v == nil {
		return "未知"
	}
	if *v {
		return "是"
	}
	return "否"
}
func ports(v []int) string {
	a := []string{}
	for _, p := range v {
		a = append(a, number(p))
	}
	return strings.Join(a, ", ")
}
func levelRows(s Summary) [][]string {
	rows := [][]string{}
	for _, k := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"} {
		rows = append(rows, []string{Label(k), number(s.Severity[k])})
	}
	return rows
}
func limit(t Table, max int) Table {
	if max > 0 && len(t.Rows) > max {
		t.Rows = t.Rows[:max]
		t.Truncated = true
	}
	return t
}
func newTable(title string, headers ...string) Table {
	return Table{Title: title, Headers: headers, Rows: [][]string{}}
}
func isVulnerability(f Finding) bool { return f.RiskType == "system" || f.RiskType == "web" }
func findingTable(s Snapshot) Table {
	t := newTable("漏洞详情", "资产", "风险等级", "标题", "平台编号 / CVE", "CNNVD", "CNVD", "Bugtraq", "风险端口", "风险类型", "漏洞分类", "检测方式", "置信度", "风险值", "组件", "风险描述", "风险影响", "解决方案", "风险举证", "参考资料", "状态", "内容语言")
	for _, f := range s.Findings {
		if !isVulnerability(f) {
			continue
		}
		id := f.TemplateOrCVE
		if x := strings.Join(f.Identifiers["platform"], ", "); x != "" {
			id = x + " / " + id
		}
		if x := strings.Join(f.Identifiers["cve"], ", "); x != "" && !strings.Contains(id, x) {
			id += " / " + x
		}
		component := f.Component
		if f.Package != "" {
			component += " " + f.Package
		}
		if f.InstalledVersion != "" {
			component += ":" + f.InstalledVersion
		}
		score := "未知"
		if f.CVSSScore != nil {
			score = strconv.FormatFloat(*f.CVSSScore, 'f', 1, 64)
		}
		t.Rows = append(t.Rows, []string{f.AssetAddress, Label(f.Severity), f.Title, text(id), text(strings.Join(f.Identifiers["cnnvd"], ", ")), text(strings.Join(f.Identifiers["cnvd"], ", ")), text(strings.Join(f.Identifiers["bugtraq"], ", ")), ports(f.Ports), Label(f.RiskType), text(f.VulnCategory), Label(f.DetectMethod), Label(f.Confidence), score, text(component), text(f.Description), text(f.Impact), text(f.Solution), text(f.Evidence), text(strings.Join(f.References, "\n")), text(f.Status), Label(text(f.ContentLanguage))})
	}
	return t
}
func loginTable(s Snapshot) Table {
	t := newTable("登录入口详情", "资产", "类型", "名称", "端口", "URL", "HTTPS", "验证码", "防爆破机制", "举证")
	seen := map[string]bool{}
	for _, a := range s.Assets {
		entries := append([]LoginEntry{}, a.LoginEntries...)
		for _, service := range a.Services {
			entries = append(entries, service.LoginEntries...)
		}
		for _, e := range entries {
			key := a.Address + "\x00" + e.Type + "\x00" + number(e.Port) + "\x00" + e.URL
			if seen[key] {
				continue
			}
			seen[key] = true
			t.Rows = append(t.Rows, []string{a.Address, text(e.Type), text(e.Name), number(e.Port), text(e.URL), strconv.FormatBool(e.HTTPS), boolText(e.Captcha), boolText(e.AntiBruteForce), text(e.Evidence)})
		}
	}
	for _, f := range s.Findings {
		if f.RiskType != "login_entry" {
			continue
		}
		key := f.AssetAddress + "\x00" + f.LoginType + "\x00" + number(f.Port) + "\x00" + f.MatchedPath
		if seen[key] {
			continue
		}
		seen[key] = true
		t.Rows = append(t.Rows, []string{f.AssetAddress, text(f.LoginType), f.Title, ports(f.Ports), text(f.MatchedPath), boolText(f.HTTPS), boolText(f.Captcha), boolText(f.BruteForceProtection), text(f.Evidence)})
	}
	return t
}
func assetTable(s Snapshot) Table {
	t := newTable("资产基本信息", "IP / 资产", "名称", "核心资产", "业务组", "责任人", "部门", "联系电话", "MAC", "操作系统", "系统族", "设备类型", "设备小类", "厂商", "型号", "SSH 运行态服务/容器", "存活状态", "最近存活时间")
	for _, a := range s.Assets {
		alive := "未知"
		if a.Alive != nil {
			alive = boolText(a.Alive)
		} else if a.ReachabilityStatus == "REACHABLE" {
			alive = "可达"
		} else if a.ReachabilityStatus == "NO_RESPONSE" {
			alive = "ICMP 无响应，不能判定离线"
		}
		lastAlive := a.LastAliveAt
		if lastAlive == "" && a.ReachabilityStatus == "REACHABLE" {
			lastAlive = a.ReachabilityCheckedAt
		}
		runtime := make([]string, 0, len(a.RuntimeServices))
		for _, service := range a.RuntimeServices {
			label := service.Manager + ":" + service.Name
			if service.Runtime != "" {
				label += " [" + service.Runtime + "]"
			}
			if service.Image != "" {
				label += " " + service.Image
			}
			runtime = append(runtime, label+" ("+service.State+")")
		}
		t.Rows = append(t.Rows, []string{a.Address, text(a.Name), strconv.FormatBool(a.Core), text(a.BusinessGroup), text(a.Owner), text(a.Department), text(a.Phone), text(a.MAC), text(a.OSName), text(a.OSFamily), text(a.DeviceType), text(a.DeviceSubtype), text(a.Vendor), text(a.Model), text(strings.Join(runtime, "；")), alive, text(lastAlive)})
	}
	return t
}
func serviceTable(s Snapshot, web bool) Table {
	t := newTable("资产端口信息", "资产", "端口数", "端口", "协议", "状态", "服务", "软件", "版本", "中间件", "开发语言", "框架", "数据库", "应用或服务", "网站 URL", "网站标题", "TLS", "排除", "首次发现", "最近发现")
	for _, a := range s.Assets {
		services := a.Services
		if len(services) == 0 {
			for _, p := range a.Ports {
				services = append(services, Service{Port: p.Port, Kind: p.Kind, Excluded: p.Kind == "EXCLUDED_PROXY"})
			}
		}
		for _, v := range services {
			if web && v.URL == "" && v.Kind != "WEB" && v.Kind != "http" && v.Kind != "https" {
				continue
			}
			service := v.ServiceName
			if service == "" {
				service = v.Service
			}
			t.Rows = append(t.Rows, []string{a.Address, number(len(services)), number(v.Port), text(v.Protocol), text(v.State), text(service), text(v.Software), text(v.Version), text(v.Middleware), text(v.Language), text(v.Framework), text(v.Database), text(v.Application), text(v.URL), text(v.Title), strconv.FormatBool(v.TLS), strconv.FormatBool(v.Excluded), text(v.FirstSeen), text(v.LastSeen)})
		}
	}
	return t
}
func assetRiskTable(s Snapshot) Table {
	t := newTable("资产风险统计", "资产", "最高漏洞等级", "系统漏洞", "Web 漏洞", "漏洞总数", "弱口令", "登录入口")
	for _, a := range s.Assets {
		sys, web, login := 0, 0, 0
		level := "SAFE"
		for _, f := range s.Findings {
			if f.AssetAddress != a.Address {
				continue
			}
			switch f.RiskType {
			case "system":
				sys++
			case "web":
				web++
			}
			if isVulnerability(f) && Rank(f.Severity) > Rank(level) {
				level = f.Severity
			}
		}
		one := s
		one.Assets = []Asset{a}
		one.Findings = nil
		login = len(loginTable(one).Rows)
		t.Rows = append(t.Rows, []string{a.Address, Label(level), number(sys), number(web), number(sys + web), "本次未启用该检测项", number(login)})
	}
	return t
}

type influence struct {
	key, title, kind, severity string
	count                      int
	assets                     map[string]bool
}

func influenceTable(s Snapshot, kind string, max int) Table {
	t := newTable("漏洞影响统计", "规则 / CVE", "漏洞名称", "风险类型", "最高等级", "出现次数", "影响资产数", "影响资产（最多 10 个）")
	groups := map[string]*influence{}
	for _, f := range s.Findings {
		if !isVulnerability(f) || (kind != "" && f.RiskType != kind) {
			continue
		}
		key := f.RiskType + "\x00" + f.TemplateOrCVE
		if f.TemplateOrCVE == "" {
			key = f.RiskType + "\x00" + f.Title
		}
		g := groups[key]
		if g == nil {
			g = &influence{key: f.TemplateOrCVE, title: f.Title, kind: f.RiskType, severity: f.Severity, assets: map[string]bool{}}
			groups[key] = g
		}
		g.count++
		g.assets[f.AssetAddress] = true
		if Rank(f.Severity) > Rank(g.severity) {
			g.severity = f.Severity
		}
	}
	items := []*influence{}
	for _, g := range groups {
		items = append(items, g)
	}
	sort.Slice(items, func(i, j int) bool {
		a, b := items[i], items[j]
		if Rank(a.severity) != Rank(b.severity) {
			return Rank(a.severity) > Rank(b.severity)
		}
		if len(a.assets) != len(b.assets) {
			return len(a.assets) > len(b.assets)
		}
		return a.key < b.key
	})
	for _, g := range items {
		a := []string{}
		for v := range g.assets {
			a = append(a, v)
		}
		sort.Strings(a)
		count := len(a)
		suffix := ""
		if len(a) > 10 {
			a = a[:10]
			suffix = "；更多信息请在平台查看或下载 Excel"
		}
		t.Rows = append(t.Rows, []string{text(g.key), g.title, Label(g.kind), Label(g.severity), number(g.count), number(count), strings.Join(a, ", ") + suffix})
	}
	return limit(t, max)
}
func countsTable(title string, counts map[string]int, n int) Table {
	t := newTable(title, "项目", "数量")
	keys := []string{}
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if counts[keys[i]] != counts[keys[j]] {
			return counts[keys[i]] > counts[keys[j]]
		}
		return keys[i] < keys[j]
	})
	for _, k := range keys {
		t.Rows = append(t.Rows, []string{text(k), number(counts[k])})
	}
	return limit(t, n)
}
func chart(t Table) Chart {
	c := Chart{Title: t.Title}
	for _, r := range t.Rows {
		c.Labels = append(c.Labels, r[0])
		n, _ := strconv.Atoi(r[1])
		c.Counts = append(c.Counts, n)
	}
	im := image.NewRGBA(image.Rect(0, 0, 800, 260))
	draw.Draw(im, im.Bounds(), &image.Uniform{color.RGBA{247, 249, 252, 255}}, image.Point{}, draw.Src)
	max := 1
	for _, v := range c.Counts {
		if v > max {
			max = v
		}
	}
	for i, v := range c.Counts {
		h := v * 210 / max
		w := 650 / (len(c.Counts) + 1)
		x := 55 + i*w
		draw.Draw(im, image.Rect(x, 230-h, x+w*2/3, 230), &image.Uniform{color.RGBA{37, 99, 235, 255}}, image.Point{}, draw.Src)
	}
	for i, v := range c.Counts {
		width := 650 / (len(c.Counts) + 1)
		xpos := 55 + i*width
		h := v * 210 / max
		chartDigits(im, xpos, 235, number(i+1), color.RGBA{55, 65, 81, 255})
		chartDigits(im, xpos, 210-h, number(v), color.RGBA{15, 23, 42, 255})
	}
	var b bytes.Buffer
	_ = png.Encode(&b, im)
	c.PNG = b.Bytes()
	return c
}
func BuildDocument(s Snapshot) Document {
	d := Document{Name: s.Name}
	sections := []Section{{ID: "cover", Title: "1. 封面", Paragraphs: []string{s.Template.Company, s.Name, "生成时间：" + s.CreatedAt.Format("2006-01-02 15:04:05 UTC"), fmt.Sprintf("数据快照：v%d / %s", s.SchemaVersion, s.ID)}}, {ID: "overview", Title: "2. 综述"}, {ID: "assets", Title: "3. 资产统计"}, {ID: "asset-risks", Title: "4. 资产风险信息"}, {ID: "asset-details", Title: "5. 资产详情"}, {ID: "risk-statistics", Title: "6. 风险统计"}, {ID: "risk-details", Title: "7. 风险详情"}, {ID: "appendix", Title: "8. 附录"}}
	sum := s.Summary
	overview := newTable("综述", "指标", "结果")
	overview.Rows = [][]string{{"总体安全等级与覆盖说明", sum.Assessment}, {"资产数", number(sum.Assets)}, {"存活资产数", number(sum.AliveAssets)}, {"存活状态未知", number(sum.UnknownAliveAssets)}, {"风险资产数", number(sum.RiskAssets)}, {"漏洞总数", number(sum.Vulnerabilities)}, {"系统漏洞", number(sum.SystemVulnerabilities)}, {"Web 漏洞", number(sum.WebVulnerabilities)}, {"弱口令", "本次未启用该检测项"}, {"登录入口（单独统计）", number(sum.LoginEntries)}, {"版本推断（未验证）", number(sum.VersionInferences)}, {"原理验证与配置检查", number(sum.Verified)}}
	sections[1].Tables = []Table{overview, {Title: "漏洞等级分布", Headers: []string{"等级", "漏洞数"}, Rows: levelRows(sum)}}
	sections[1].Paragraphs = append([]string{"漏洞总数 = 系统漏洞 + Web 漏洞；登录入口单独统计。漏洞按稳定发现项指纹去重，影响资产数按主机去重。版本推断未进行漏洞原理验证。未知 CVSS 不写为 0；历史记录未知检测方式保持未知。"}, s.Notes...)
	for _, task := range s.Tasks {
		sections[1].Paragraphs = append(sections[1].Paragraphs, "任务 "+task.ID+"："+task.Status+"；系统采集："+text(task.SystemScanStatus))
	}
	devices, osCounts, portCounts := map[string]int{}, map[string]int{}, map[string]int{}
	for _, a := range s.Assets {
		devices[text(a.DeviceType)]++
		osCounts[text(a.OSName)]++
		seen := map[int]bool{}
		for _, v := range a.Services {
			seen[v.Port] = true
		}
		for _, p := range a.Ports {
			seen[p.Port] = true
		}
		for p := range seen {
			portCounts[number(p)]++
		}
	}
	sections[2].Tables = []Table{countsTable("设备类型分布", devices, 0), countsTable("操作系统 TOP5", osCounts, 5), countsTable("端口 TOP5", portCounts, 5), limit(assetTable(s), 100), limit(serviceTable(s, false), 100)}
	for _, t := range sections[2].Tables[:3] {
		sections[2].Charts = append(sections[2].Charts, chart(t))
	}
	sections[2].Paragraphs = append(sections[2].Paragraphs, "本次已排除端口："+strings.Join(s.Exclusions, "；"))
	if len(s.Exclusions) == 0 {
		sections[2].Paragraphs = append(sections[2].Paragraphs, "快照中没有记录排除端口。")
	}
	sections[3].Tables = []Table{limit(assetRiskTable(s), 100), {Title: "弱口令", Headers: []string{"检测状态"}, Rows: [][]string{{"本次未启用该检测项"}}}, limit(loginTable(s), 100)}
	for _, a := range s.Assets {
		one := s
		one.Assets = []Asset{a}
		sections[4].Tables = append(sections[4].Tables, assetTable(one), serviceTable(one, false), assetRiskTable(one))
	}
	for _, kind := range []string{"system", "web", "login_entry"} {
		severity, affected, occurrences, categories := map[string]int{}, map[string]int{}, map[string]int{}, map[string]int{}
		for _, f := range s.Findings {
			if f.RiskType != kind {
				continue
			}
			severity[Label(f.Severity)]++
			affected[f.AssetAddress]++
			occurrences[f.Title]++
			categories[text(f.VulnCategory)]++
		}
		if kind == "login_entry" {
			severity = map[string]int{}
			affected = map[string]int{}
			occurrences = map[string]int{}
			categories = map[string]int{}
			for _, row := range loginTable(s).Rows {
				severity["未评定（单独统计）"]++
				affected[row[0]]++
				occurrences[row[2]]++
				categories[row[1]]++
			}
		}
		for _, t := range []Table{countsTable(Label(kind)+"等级分布", severity, 0), countsTable(Label(kind)+"影响资产 TOP5", affected, 5), countsTable(Label(kind)+"出现次数 TOP5", occurrences, 5), countsTable(Label(kind)+"类别统计", categories, 0)} {
			sections[5].Tables = append(sections[5].Tables, t)
			if len(t.Rows) > 0 && !strings.Contains(t.Title, "类别统计") {
				sections[5].Charts = append(sections[5].Charts, chart(t))
			}
		}
		if kind == "login_entry" {
			sections[5].Tables = append(sections[5].Tables, limit(loginTable(s), 100))
		} else {
			top := influenceTable(s, kind, 100)
			top.Title = Label(kind) + " TOP100"
			sections[5].Tables = append(sections[5].Tables, top)
		}
	}
	sections[5].Paragraphs = []string{"弱口令：本次未启用该检测项。登录入口的等级只展示记录标签，不影响资产与总体漏洞等级。"}
	details := findingTable(s)
	for _, row := range details.Rows {
		card := newTable(row[0]+" · "+row[2], "字段", "内容")
		for i, h := range details.Headers {
			card.Rows = append(card.Rows, []string{h, row[i]})
		}
		sections[6].Tables = append(sections[6].Tables, card)
	}
	sections[6].Tables = append(sections[6].Tables, loginTable(s))
	sections[7].Paragraphs = []string{s.Template.RatingText, s.Template.Advice, "更多信息请在平台查看或下载 Excel。TOP 表最多 100 项，每个漏洞最多列出 10 个影响资产。图表均由服务端生成，柱形顺序与紧随的表格一致。"}
	for _, section := range sections {
		if enabled, ok := s.Template.Sections[section.ID]; ok && !enabled {
			continue
		}
		d.Sections = append(d.Sections, section)
	}
	return d
}

// Workbook keeps the complete detail rows; presentation TOP tables use bounded views.
func Workbook(s Snapshot) []Table {
	full := s
	full.Template.Sections = nil
	d := BuildDocument(full)
	overview := newTable("综述", "指标", "结果")
	for _, section := range d.Sections {
		if section.ID == "overview" {
			overview = section.Tables[0]
		}
	}
	overview.Title = "综述"
	for _, row := range levelRows(s.Summary) {
		overview.Rows = append(overview.Rows, []string{row[0] + "漏洞数", row[1]})
	}
	for _, note := range s.Notes {
		overview.Rows = append(overview.Rows, []string{"检测覆盖说明", note})
	}
	overview.Rows = append(overview.Rows, []string{"报告名称", s.Name}, []string{"公司名称", s.Template.Company}, []string{"页眉", s.Template.Header}, []string{"页脚", s.Template.Footer}, []string{"快照版本", number(s.SchemaVersion)}, []string{"快照 ID", s.ID}, []string{"评定标准", s.Template.RatingText}, []string{"安全建议", s.Template.Advice}, []string{"本次已排除端口", strings.Join(s.Exclusions, "；")})
	a := assetRiskTable(s)
	a.Title = "资产风险统计"
	impact := influenceTable(s, "", 0)
	impact.Title = "漏洞影响统计"
	hosts := hostDetailsTable(s)
	hosts.Title = "主机资产详情"
	sites := serviceTable(s, true)
	sites.Title = "网站资产详情"
	return []Table{overview, a, impact, hosts, sites, findingTable(s), {Title: "弱口令详情", Headers: []string{"检测状态"}, Rows: [][]string{{"未启用该检测项"}}}, loginTable(s)}
}

func hostDetailsTable(s Snapshot) Table {
	base := assetTable(s)
	services := serviceTable(s, false)
	out := Table{Title: "主机资产详情", Headers: append(append([]string{}, base.Headers...), services.Headers[1:]...)}
	for _, asset := range base.Rows {
		found := false
		for _, service := range services.Rows {
			if service[0] != asset[0] {
				continue
			}
			out.Rows = append(out.Rows, append(append([]string{}, asset...), service[1:]...))
			found = true
		}
		if !found {
			row := append([]string{}, asset...)
			for range services.Headers[1:] {
				row = append(row, "未采集")
			}
			out.Rows = append(out.Rows, row)
		}
	}
	return out
}

func chartDigits(im *image.RGBA, xpos, ypos int, value string, ink color.Color) {
	glyphs := map[rune][]string{'0': {"111", "101", "101", "101", "111"}, '1': {"010", "110", "010", "010", "111"}, '2': {"111", "001", "111", "100", "111"}, '3': {"111", "001", "111", "001", "111"}, '4': {"101", "101", "111", "001", "001"}, '5': {"111", "100", "111", "001", "111"}, '6': {"111", "100", "111", "101", "111"}, '7': {"111", "001", "010", "010", "010"}, '8': {"111", "101", "111", "101", "111"}, '9': {"111", "101", "111", "001", "111"}}
	for _, r := range value {
		for row, line := range glyphs[r] {
			for col, pixel := range line {
				if pixel == '1' {
					draw.Draw(im, image.Rect(xpos+col*2, ypos+row*2, xpos+col*2+2, ypos+row*2+2), &image.Uniform{ink}, image.Point{}, draw.Src)
				}
			}
		}
		xpos += 9
	}
}
