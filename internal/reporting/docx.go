package reporting

import (
	"archive/zip"
	"encoding/base64"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
)

// The Word report follows a conventional assessment-report layout: a cover,
// numbered chapters, bordered tables with a shaded header row and one detail
// table per finding. Sections with nothing to report say "无" instead of
// padding the document with explanations.

const (
	docxShade      = "DAE3F3"
	docxTableWidth = 5000 // column widths are given as shares of this total
	docxTextWidth  = 8306 // A4 text width in twips with 1800-twip side margins
	docxNone       = "无"
)

type docxWriter struct {
	b       strings.Builder
	chapter int
	sub     int
	subsub  int
}

func orNone(v string) string {
	if strings.TrimSpace(v) == "" {
		return docxNone
	}
	return v
}

func (d *docxWriter) run(v string, bold bool, size int) string {
	// Fonts come from the paragraph style so headings and body text differ.
	pr := ""
	if bold {
		pr += `<w:b/>`
	}
	if size > 0 {
		pr += fmt.Sprintf(`<w:sz w:val="%d"/><w:szCs w:val="%d"/>`, size, size)
	}
	lines := strings.Split(v, "\n")
	out := `<w:r><w:rPr>` + pr + `</w:rPr>`
	for i, line := range lines {
		if i > 0 {
			out += `<w:br/>`
		}
		out += `<w:t xml:space="preserve">` + x(line) + `</w:t>`
	}
	return out + `</w:r>`
}

func (d *docxWriter) para(v, style, align string, bold bool, size int) {
	pr := ""
	if style != "" {
		pr += `<w:pStyle w:val="` + style + `"/>`
	}
	if align != "" {
		pr += `<w:jc w:val="` + align + `"/>`
	}
	if pr != "" {
		pr = `<w:pPr>` + pr + `</w:pPr>`
	}
	d.b.WriteString(`<w:p>` + pr + d.run(v, bold, size) + `</w:p>`)
}

func (d *docxWriter) text(v string) { d.para(v, "", "", false, 0) }

// heading writes a numbered heading; level 1 starts a new chapter.
func (d *docxWriter) heading(level int, v string) {
	switch level {
	case 1:
		d.chapter++
		d.sub, d.subsub = 0, 0
		d.para(fmt.Sprintf("%d %s", d.chapter, v), "Heading1", "", false, 0)
	case 2:
		d.sub++
		d.subsub = 0
		d.para(fmt.Sprintf("%d.%d %s", d.chapter, d.sub, v), "Heading2", "", false, 0)
	default:
		d.subsub++
		d.para(fmt.Sprintf("%d.%d.%d %s", d.chapter, d.sub, d.subsub, v), "Heading3", "", false, 0)
	}
}

func (d *docxWriter) cell(v string, width int, shaded, bold bool, merge string) string {
	pr := fmt.Sprintf(`<w:tcW w:w="%d" w:type="dxa"/>`, width*docxTextWidth/docxTableWidth)
	if merge != "" {
		pr += `<w:vMerge w:val="` + merge + `"/>`
		if merge == "continue" {
			pr = fmt.Sprintf(`<w:tcW w:w="%d" w:type="dxa"/><w:vMerge/>`, width*docxTextWidth/docxTableWidth)
		}
	}
	if shaded {
		pr += `<w:shd w:val="clear" w:color="auto" w:fill="` + docxShade + `"/>`
	}
	pr += `<w:vAlign w:val="center"/>`
	body := `<w:p><w:pPr><w:pStyle w:val="TableText"/></w:pPr></w:p>`
	if merge != "continue" {
		body = `<w:p><w:pPr><w:pStyle w:val="TableText"/></w:pPr>` + d.tableRun(v, bold) + `</w:p>`
	}
	return `<w:tc><w:tcPr>` + pr + `</w:tcPr>` + body + `</w:tc>`
}

func (d *docxWriter) tableRun(v string, bold bool) string {
	pr := `<w:rFonts w:ascii="黑体" w:hAnsi="黑体" w:eastAsia="黑体" w:hint="eastAsia"/>`
	if bold {
		pr += `<w:b/>`
	}
	out := `<w:r><w:rPr>` + pr + `</w:rPr>`
	for i, line := range strings.Split(v, "\n") {
		if i > 0 {
			out += `<w:br/>`
		}
		out += `<w:t xml:space="preserve">` + x(line) + `</w:t>`
	}
	return out + `</w:r>`
}

func (d *docxWriter) tableStart(widths []int) {
	d.b.WriteString(`<w:tbl><w:tblPr><w:tblW w:w="` + strconv.Itoa(docxTextWidth) + `" w:type="dxa"/><w:jc w:val="center"/><w:tblBorders>`)
	for _, side := range []string{"top", "left", "bottom", "right", "insideH", "insideV"} {
		d.b.WriteString(`<w:` + side + ` w:val="single" w:color="auto" w:sz="4" w:space="0"/>`)
	}
	d.b.WriteString(`</w:tblBorders><w:tblLayout w:type="fixed"/><w:tblCellMar><w:top w:w="40" w:type="dxa"/><w:left w:w="108" w:type="dxa"/><w:bottom w:w="40" w:type="dxa"/><w:right w:w="108" w:type="dxa"/></w:tblCellMar></w:tblPr><w:tblGrid>`)
	for _, w := range widths {
		d.b.WriteString(fmt.Sprintf(`<w:gridCol w:w="%d"/>`, w*docxTextWidth/docxTableWidth))
	}
	d.b.WriteString(`</w:tblGrid>`)
}

// grid writes a list table. mergeCols lists leading columns whose repeated
// values in consecutive rows are merged vertically (for example an asset's
// address over its ports).
func (d *docxWriter) grid(headers []string, widths []int, rows [][]string, mergeCols int) {
	d.tableStart(widths)
	d.b.WriteString(`<w:tr><w:trPr><w:tblHeader/><w:cantSplit/></w:trPr>`)
	for i, h := range headers {
		d.b.WriteString(d.cell(h, widths[i], true, true, ""))
	}
	d.b.WriteString(`</w:tr>`)
	for r, row := range rows {
		d.b.WriteString(`<w:tr><w:trPr><w:cantSplit/></w:trPr>`)
		for i, v := range row {
			merge := ""
			if i < mergeCols {
				sameAsPrev := r > 0 && rows[r-1][i] == v
				sameAsNext := r+1 < len(rows) && rows[r+1][i] == v
				if sameAsPrev {
					merge = "continue"
				} else if sameAsNext {
					merge = "restart"
				}
			}
			d.b.WriteString(d.cell(orNone(v), widths[i], false, false, merge))
		}
		d.b.WriteString(`</w:tr>`)
	}
	d.b.WriteString(`</w:tbl>`)
	d.spacer()
}

// fields writes a two-column label/value table; an optional title row is shaded.
func (d *docxWriter) fields(title []string, rows [][2]string) {
	widths := []int{1100, 3900}
	d.tableStart(widths)
	if len(title) == 2 {
		d.b.WriteString(`<w:tr><w:trPr><w:cantSplit/></w:trPr>` + d.cell(title[0], widths[0], true, true, "") + d.cell(title[1], widths[1], true, true, "") + `</w:tr>`)
	}
	for _, row := range rows {
		d.b.WriteString(`<w:tr><w:trPr><w:cantSplit/></w:trPr>` + d.cell(row[0], widths[0], true, false, "") + d.cell(orNone(row[1]), widths[1], false, false, "") + `</w:tr>`)
	}
	d.b.WriteString(`</w:tbl>`)
	d.spacer()
}

func (d *docxWriter) spacer() {
	d.b.WriteString(`<w:p><w:pPr><w:spacing w:before="0" w:after="0"/></w:pPr></w:p>`)
}

func sectionEnabled(s Snapshot, id string) bool {
	enabled, ok := s.Template.Sections[id]
	return !ok || enabled
}

func severityCounts(findings []Finding, kind string) map[string]int {
	counts := map[string]int{}
	for _, f := range findings {
		if f.RiskType == kind || (kind == "" && isVulnerability(f)) {
			counts[f.Severity]++
		}
	}
	return counts
}

var reportSeverities = []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}

func severityLine(counts map[string]int) string {
	parts := []string{}
	total := 0
	for _, k := range reportSeverities {
		parts = append(parts, fmt.Sprintf("%s %d 个", Label(k), counts[k]))
		total += counts[k]
	}
	return fmt.Sprintf("共 %d 个，其中%s", total, strings.Join(parts, "、"))
}

func severityRow(label string, counts map[string]int) []string {
	row := []string{label}
	total := 0
	for _, k := range reportSeverities {
		row = append(row, number(counts[k]))
		total += counts[k]
	}
	return append(row, number(total))
}

func assetServices(a Asset) []Service {
	if len(a.Services) > 0 {
		return a.Services
	}
	out := []Service{}
	for _, p := range a.Ports {
		out = append(out, Service{Port: p.Port, Kind: p.Kind, Protocol: "tcp"})
	}
	return out
}

func serviceLabel(v Service) string {
	if v.ServiceName != "" {
		return v.ServiceName
	}
	if v.Service != "" {
		return v.Service
	}
	return v.Kind
}

func softwareLabel(v Service) string {
	return strings.TrimSpace(strings.Join([]string{v.Software, v.Version}, " "))
}

func findingIDs(f Finding) string {
	ids := []string{}
	add := func(v string) {
		if v != "" && !strings.Contains(strings.Join(ids, " "), v) {
			ids = append(ids, v)
		}
	}
	add(f.TemplateOrCVE)
	for _, v := range f.Identifiers["cve"] {
		add(v)
	}
	return strings.Join(ids, " / ")
}

func findingComponent(f Finding) string {
	name := strings.TrimSpace(strings.Join([]string{f.Component, f.Package}, " "))
	if f.InstalledVersion != "" {
		name += " " + f.InstalledVersion
	}
	if f.FixedVersion != "" {
		name += "（修复版本 " + f.FixedVersion + "）"
	}
	return strings.TrimSpace(name)
}

func findingPorts(f Finding) string {
	if len(f.Ports) > 0 {
		return ports(f.Ports)
	}
	if f.Port > 0 {
		return number(f.Port)
	}
	return ""
}

func renderDOCX(w io.Writer, s Snapshot) error {
	z := zip.NewWriter(w)
	rels := rel("header", "header", "header1.xml") + rel("footer", "footer", "footer1.xml") + rel("styles", "styles", "styles.xml")
	var logo []byte
	if s.Template.Logo != "" {
		logo, _ = base64.StdEncoding.DecodeString(strings.TrimPrefix(s.Template.Logo, "data:image/png;base64,"))
		rels += rel("logo", "image", "media/logo.png")
		if err := zipBytes(z, "word/media/logo.png", logo); err != nil {
			return err
		}
	}
	types := `<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/><Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/><Override PartName="/word/header1.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.header+xml"/><Override PartName="/word/footer1.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.footer+xml"/>`
	header := s.Template.Header
	if header == "" {
		header = s.Template.Company
	}
	footer := `<w:p><w:pPr><w:jc w:val="center"/></w:pPr>`
	if s.Template.Footer != "" {
		footer += `<w:r><w:rPr><w:sz w:val="18"/></w:rPr><w:t xml:space="preserve">` + x(s.Template.Footer) + `    </w:t></w:r>`
	}
	footer += `<w:r><w:rPr><w:sz w:val="18"/></w:rPr><w:t xml:space="preserve">- </w:t></w:r><w:r><w:fldChar w:fldCharType="begin"/></w:r><w:r><w:instrText xml:space="preserve"> PAGE </w:instrText></w:r><w:r><w:fldChar w:fldCharType="end"/></w:r><w:r><w:rPr><w:sz w:val="18"/></w:rPr><w:t xml:space="preserve"> -</w:t></w:r></w:p>`
	for _, entry := range []struct{ name, body string }{
		{"[Content_Types].xml", contentTypes(types)},
		{"_rels/.rels", `<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">` + rel("rId1", "officeDocument", "word/document.xml") + `</Relationships>`},
		{"word/_rels/document.xml.rels", `<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">` + rels + `</Relationships>`},
		{"word/styles.xml", docxStyles},
		{"word/header1.xml", `<w:hdr xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:p><w:pPr><w:pBdr><w:bottom w:val="single" w:sz="4" w:space="1" w:color="auto"/></w:pBdr><w:jc w:val="right"/></w:pPr><w:r><w:rPr><w:sz w:val="18"/></w:rPr><w:t xml:space="preserve">` + x(header) + `</w:t></w:r></w:p></w:hdr>`},
		{"word/footer1.xml", `<w:ftr xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">` + footer + `</w:ftr>`},
	} {
		if err := zipString(z, entry.name, entry.body); err != nil {
			return err
		}
	}
	d := &docxWriter{}
	writeDOCXBody(d, s, logo)
	dw, err := z.Create("word/document.xml")
	if err != nil {
		return err
	}
	if err := write(dw, xmlHeader+`<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><w:body>`); err != nil {
		return err
	}
	if err := write(dw, d.b.String()); err != nil {
		return err
	}
	if err := write(dw, `<w:sectPr><w:headerReference w:type="default" r:id="header"/><w:footerReference w:type="default" r:id="footer"/><w:pgSz w:w="11906" w:h="16838"/><w:pgMar w:top="1440" w:right="1800" w:bottom="1440" w:left="1800" w:header="851" w:footer="992" w:gutter="0"/><w:titlePg/></w:sectPr></w:body></w:document>`); err != nil {
		return err
	}
	return z.Close()
}

func writeDOCXBody(d *docxWriter, s Snapshot, logo []byte) {
	sum := s.Summary
	byAsset := map[string][]Finding{}
	for _, f := range s.Findings {
		byAsset[f.AssetAddress] = append(byAsset[f.AssetAddress], f)
	}
	loginsFor := func(a Asset) [][]string {
		one := s
		one.Assets = []Asset{a}
		one.Findings = byAsset[a.Address]
		return loginTable(one).Rows
	}

	// Cover.
	if sectionEnabled(s, "cover") {
		for range 6 {
			d.spacer()
		}
		if len(logo) > 0 {
			cx, cy := logoSize(logo)
			d.b.WriteString(fmt.Sprintf(`<w:p><w:pPr><w:jc w:val="center"/></w:pPr><w:r><w:drawing><wp:inline xmlns:wp="http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing"><wp:extent cx="%d" cy="%d"/><wp:docPr id="1" name="公司 Logo"/><a:graphic xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"><a:graphicData uri="http://schemas.openxmlformats.org/drawingml/2006/picture"><pic:pic xmlns:pic="http://schemas.openxmlformats.org/drawingml/2006/picture"><pic:nvPicPr><pic:cNvPr id="0" name="logo"/><pic:cNvPicPr/></pic:nvPicPr><pic:blipFill><a:blip r:embed="logo"/><a:stretch><a:fillRect/></a:stretch></pic:blipFill><pic:spPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="%d" cy="%d"/></a:xfrm><a:prstGeom prst="rect"><a:avLst/></a:prstGeom></pic:spPr></pic:pic></a:graphicData></a:graphic></wp:inline></w:drawing></w:r></w:p>`, cx, cy, cx, cy))
		}
		if s.Template.Company != "" {
			d.para(s.Template.Company, "CoverTitle", "center", true, 0)
		}
		d.para(orNone(s.Template.Name), "CoverSubtitle", "center", true, 0)
		for range 4 {
			d.spacer()
		}
		targets := []string{}
		for i, a := range s.Assets {
			if i >= 5 {
				break
			}
			targets = append(targets, a.Address)
		}
		scope := strings.Join(targets, "、")
		if len(s.Assets) > len(targets) {
			scope += fmt.Sprintf(" 等 %d 个目标", len(s.Assets))
		}
		d.fields(nil, [][2]string{
			{"报告名称", s.Name},
			{"扫描目标", scope},
			{"报告生成时间", s.CreatedAt.Local().Format("2006-01-02 15:04:05")},
			{"数据快照", fmt.Sprintf("v%d / %s", s.SchemaVersion, s.ID)},
		})
	}

	// 综述
	if sectionEnabled(s, "overview") {
		d.heading(1, "综述")
		d.text("本次评估的总体安全等级为" + sum.Assessment + "。")
		d.text(fmt.Sprintf("资产情况：共 %d 个资产，存活 %d 个（存活状态未知 %d 个），存在风险的资产 %d 个。", sum.Assets, sum.AliveAssets, sum.UnknownAliveAssets, sum.RiskAssets))
		d.text(fmt.Sprintf("漏洞情况：%s；系统漏洞 %d 个，Web 漏洞 %d 个，其中版本推断（未验证）%d 个，原理验证与配置检查 %d 个。", severityLine(severityCounts(s.Findings, "")), sum.SystemVulnerabilities, sum.WebVulnerabilities, sum.VersionInferences, sum.Verified))
		d.text("弱口令：本次未启用该检测项。")
		web, system := 0, 0
		for _, row := range loginTable(s).Rows {
			if row[1] == "web" {
				web++
			} else {
				system++
			}
		}
		d.text(fmt.Sprintf("登录入口：共 %d 个，其中 Web 登录入口 %d 个，系统登录入口 %d 个。", sum.LoginEntries, web, system))
		if sum.Severity["CRITICAL"]+sum.Severity["HIGH"] > 0 {
			d.text("存在严重或高危漏洞，建议优先处理。")
		}
		for _, note := range s.Notes {
			d.text(note)
		}
	}

	// 资产统计
	if sectionEnabled(s, "assets") {
		d.heading(1, "资产统计")
		d.heading(2, "资产基本信息")
		devices, systems := map[string]int{}, map[string]int{}
		for _, a := range s.Assets {
			devices[orNone(a.DeviceType)]++
			systems[orNone(a.OSName)]++
		}
		d.text(fmt.Sprintf("本次共检测资产 %d 个。设备类型：%s。操作系统：%s。", len(s.Assets), countText(devices), countText(systems)))
		rows := [][]string{}
		for i, a := range s.Assets {
			core := "否"
			if a.Core {
				core = "是"
			}
			rows = append(rows, []string{number(i + 1), a.Address, a.DeviceType, a.OSName, a.Name, core, a.Owner, a.BusinessGroup})
		}
		if len(rows) == 0 {
			d.text(docxNone)
		} else {
			d.grid([]string{"序号", "IP/URL", "设备类型", "操作系统", "资产名称", "是否核心", "责任人", "业务组"}, []int{350, 900, 600, 750, 750, 450, 600, 600}, rows, 0)
		}

		d.heading(2, "资产端口信息")
		portRows, portAssets := [][]string{}, 0
		portCount := map[string]int{}
		for _, a := range s.Assets {
			services := assetServices(a)
			if len(services) > 0 {
				portAssets++
			}
			for _, v := range services {
				portCount[number(v.Port)+"("+orNone(v.Protocol)+")"]++
				portRows = append(portRows, []string{a.Address, number(len(services)), number(v.Port), v.Protocol, serviceLabel(v), softwareLabel(v)})
			}
		}
		if len(portRows) == 0 {
			d.text(docxNone)
		} else {
			d.text(fmt.Sprintf("存在开放端口的资产共 %d 个，开放最多的端口为 %s。", portAssets, topKey(portCount)))
			d.grid([]string{"IP/URL", "端口数", "端口", "协议", "服务", "软件"}, []int{1000, 550, 550, 500, 1000, 1400}, portRows, 2)
		}

		if sectionEnabled(s, "asset-risks") {
			d.heading(2, "资产风险信息")
			d.heading(3, "漏洞")
			vulnRows := [][]string{}
			for _, a := range s.Assets {
				counts := severityCounts(byAsset[a.Address], "")
				row := severityRow(a.Address, counts)
				if row[len(row)-1] != "0" {
					vulnRows = append(vulnRows, append([]string{number(len(vulnRows) + 1)}, row...))
				}
			}
			if len(vulnRows) == 0 {
				d.text(docxNone)
			} else {
				d.text(fmt.Sprintf("存在漏洞风险的资产共 %d 个。", len(vulnRows)))
				d.grid([]string{"序号", "IP/URL", "严重", "高危", "中危", "低危", "信息", "总计"}, []int{400, 1300, 550, 550, 550, 550, 550, 550}, vulnRows, 0)
			}
			d.heading(3, "弱口令")
			d.text("本次未启用该检测项。")
			d.heading(3, "登录入口")
			loginRows := [][]string{}
			for _, a := range s.Assets {
				web, system := 0, 0
				for _, row := range loginsFor(a) {
					if row[1] == "web" {
						web++
					} else {
						system++
					}
				}
				if web+system > 0 {
					loginRows = append(loginRows, []string{number(len(loginRows) + 1), a.Address, number(web), number(system), number(web + system)})
				}
			}
			if len(loginRows) == 0 {
				d.text(docxNone)
			} else {
				d.grid([]string{"序号", "IP/URL", "Web 登录入口", "系统登录入口", "总计"}, []int{500, 1600, 1000, 1000, 900}, loginRows, 0)
			}
		}
	}

	// 资产详情
	if sectionEnabled(s, "asset-details") {
		d.heading(1, "资产详情")
		if len(s.Assets) == 0 {
			d.text(docxNone)
		}
		for _, a := range s.Assets {
			d.heading(2, a.Address)
			d.heading(3, "资产基本信息")
			runtime := []string{}
			for _, service := range a.RuntimeServices {
				label := service.Name
				if service.Image != "" {
					label += " (" + service.Image + ")"
				}
				runtime = append(runtime, label+" · "+service.State)
			}
			core := "否"
			if a.Core {
				core = "是"
			}
			d.fields([]string{"资产", a.Address}, [][2]string{
				{"是否核心", core}, {"资产名称", a.Name}, {"业务组", a.BusinessGroup}, {"责任人", a.Owner}, {"所属部门", a.Department}, {"联系电话", a.Phone}, {"MAC 地址", a.MAC},
				{"操作系统", a.OSName}, {"设备类型", a.DeviceType}, {"设备小类", a.DeviceSubtype}, {"厂商和型号", strings.TrimSpace(a.Vendor + " " + a.Model)}, {"运行态服务 / 容器", strings.Join(runtime, "\n")},
			})
			d.heading(3, "资产端口信息")
			rows := [][]string{}
			for i, v := range assetServices(a) {
				rows = append(rows, []string{number(i + 1), number(v.Port), v.Protocol, serviceLabel(v), softwareLabel(v), v.URL, v.Title})
			}
			if len(rows) == 0 {
				d.text(docxNone)
			} else {
				d.grid([]string{"序号", "开放端口", "协议", "开放服务", "软件信息", "网站 URL", "网站标题"}, []int{400, 550, 450, 750, 950, 1150, 750}, rows, 0)
			}
			d.heading(3, "资产风险信息")
			level := "SAFE"
			for _, f := range byAsset[a.Address] {
				if isVulnerability(f) && Rank(f.Severity) > Rank(level) {
					level = f.Severity
				}
			}
			d.text("该资产总体安全等级为" + Label(level) + "，风险分布如下：")
			logins := len(loginsFor(a))
			d.grid([]string{"风险类型", "严重", "高危", "中危", "低危", "信息", "总计"}, []int{1100, 650, 650, 650, 650, 650, 650}, [][]string{
				severityRow("系统漏洞", severityCounts(byAsset[a.Address], "system")),
				severityRow("Web 漏洞", severityCounts(byAsset[a.Address], "web")),
				{"弱口令", "—", "—", "—", "—", "—", "未启用"},
				{"登录入口", "—", "—", "—", "—", "—", number(logins)},
			}, 0)
		}
	}

	// 风险统计
	if sectionEnabled(s, "risk-statistics") {
		d.heading(1, "风险统计")
		for _, kind := range []string{"system", "web"} {
			name := Label(kind)
			d.heading(2, name+"影响分析")
			counts := severityCounts(s.Findings, kind)
			top := influenceTable(s, kind, 100)
			if len(top.Rows) == 0 {
				d.text(docxNone)
				continue
			}
			d.text(name + severityLine(counts) + "。")
			rows := [][]string{}
			for i, r := range top.Rows {
				title := r[1]
				if r[0] != "" && r[0] != "未采集" && !strings.Contains(title, r[0]) {
					title += "\n" + r[0]
				}
				rows = append(rows, []string{number(i + 1), title, r[3], r[6], r[5], r[4]})
			}
			d.grid([]string{"序号", name + "名称", "风险等级", "影响资产（最多展示 10 个）", "影响资产数", "出现次数"}, []int{400, 1700, 600, 1300, 500, 500}, rows, 0)
			if top.Truncated {
				d.text("注：仅展示前 100 项，完整列表请在平台查看或导出 Excel。")
			}
		}
		d.heading(2, "弱口令影响分析")
		d.text("本次未启用该检测项。")
		d.heading(2, "登录入口影响分析")
		logins := loginTable(s).Rows
		if len(logins) == 0 {
			d.text(docxNone)
		} else {
			rows := [][]string{}
			for i, r := range logins {
				rows = append(rows, []string{number(i + 1), r[2], loginKind(r[1]), r[0], r[3], r[4]})
			}
			d.grid([]string{"序号", "登录入口名称", "类型", "影响资产", "端口", "URL"}, []int{400, 1100, 600, 1000, 500, 1400}, rows, 0)
		}
	}

	// 风险详情
	if sectionEnabled(s, "risk-details") {
		d.heading(1, "风险详情")
		if len(s.Assets) == 0 {
			d.text(docxNone)
		}
		for _, a := range s.Assets {
			d.heading(2, a.Address)
			for _, kind := range []string{"system", "web"} {
				d.heading(3, Label(kind))
				n := 0
				for _, f := range byAsset[a.Address] {
					if f.RiskType != kind {
						continue
					}
					n++
					score := ""
					if f.CVSSScore != nil {
						score = "（CVSS " + strconv.FormatFloat(*f.CVSSScore, 'f', 1, 64) + "）"
					}
					d.fields([]string{number(n), f.Title}, [][2]string{
						{"风险等级", Label(f.Severity) + score},
						{"漏洞编号", findingIDs(f)},
						{"CNNVD 编号", strings.Join(f.Identifiers["cnnvd"], ", ")},
						{"CNVD 编号", strings.Join(f.Identifiers["cnvd"], ", ")},
						{"风险端口", findingPorts(f)},
						{"检测方式", Label(orNone(f.DetectMethod))},
						{"置信度", Label(orNone(f.Confidence))},
						{"影响组件", findingComponent(f)},
						{"风险描述", f.Description},
						{"风险影响", f.Impact},
						{"解决方案", f.Solution},
						{"风险举证", f.Evidence},
						{"参考资料", strings.Join(f.References, "\n")},
					})
				}
				if n == 0 {
					d.text(docxNone)
				}
			}
			d.heading(3, "弱口令")
			d.text("本次未启用该检测项。")
			d.heading(3, "登录入口")
			logins := loginsFor(a)
			if len(logins) == 0 {
				d.text(docxNone)
			} else {
				rows := [][]string{}
				for i, r := range logins {
					rows = append(rows, []string{number(i + 1), r[2], loginKind(r[1]), r[3], r[4], yesNo(r[5]), r[6], r[7]})
				}
				d.grid([]string{"序号", "登录入口名称", "类型", "端口", "URL", "HTTPS", "验证码", "防爆破"}, []int{400, 1000, 500, 450, 1250, 450, 450, 500}, rows, 0)
			}
		}
	}

	// 附录
	if sectionEnabled(s, "appendix") && (s.Template.RatingText != "" || s.Template.Advice != "") {
		d.heading(1, "附录")
		if s.Template.RatingText != "" {
			d.heading(2, "评定标准")
			d.text(s.Template.RatingText)
		}
		if s.Template.Advice != "" {
			d.heading(2, "安全建议")
			d.text(s.Template.Advice)
		}
	}
}

func yesNo(v string) string {
	switch v {
	case "true":
		return "是"
	case "false":
		return "否"
	}
	return v
}

func loginKind(v string) string {
	if v == "web" {
		return "Web"
	}
	if v == "" || v == "未采集" {
		return docxNone
	}
	return "系统"
}

func countText(counts map[string]int) string {
	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if counts[keys[i]] != counts[keys[j]] {
			return counts[keys[i]] > counts[keys[j]]
		}
		return keys[i] < keys[j]
	})
	if len(keys) > 5 {
		keys = keys[:5]
	}
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s %d 个", k, counts[k]))
	}
	if len(parts) == 0 {
		return docxNone
	}
	return strings.Join(parts, "、")
}

func topKey(counts map[string]int) string {
	best, n := "", -1
	for k, v := range counts {
		if v > n || (v == n && k < best) {
			best, n = k, v
		}
	}
	return orNone(best)
}

const docxStyles = `<w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">` +
	`<w:docDefaults><w:rPrDefault><w:rPr><w:rFonts w:ascii="Times New Roman" w:hAnsi="Times New Roman" w:eastAsia="宋体" w:cs="Times New Roman"/><w:sz w:val="21"/><w:szCs w:val="21"/><w:lang w:val="en-US" w:eastAsia="zh-CN"/></w:rPr></w:rPrDefault><w:pPrDefault><w:pPr><w:spacing w:after="60" w:line="360" w:lineRule="auto"/></w:pPr></w:pPrDefault></w:docDefaults>` +
	`<w:style w:type="paragraph" w:default="1" w:styleId="Normal"><w:name w:val="Normal"/><w:pPr><w:jc w:val="both"/></w:pPr></w:style>` +
	`<w:style w:type="paragraph" w:styleId="TableText"><w:name w:val="Table Text"/><w:basedOn w:val="Normal"/><w:pPr><w:spacing w:before="0" w:after="0" w:line="276" w:lineRule="auto"/><w:jc w:val="left"/></w:pPr><w:rPr><w:rFonts w:ascii="黑体" w:hAnsi="黑体" w:eastAsia="黑体"/><w:sz w:val="18"/><w:szCs w:val="18"/></w:rPr></w:style>` +
	`<w:style w:type="paragraph" w:styleId="CoverTitle"><w:name w:val="Cover Title"/><w:basedOn w:val="Normal"/><w:pPr><w:jc w:val="center"/><w:spacing w:after="240"/></w:pPr><w:rPr><w:rFonts w:ascii="黑体" w:hAnsi="黑体" w:eastAsia="黑体"/><w:b/><w:sz w:val="56"/><w:szCs w:val="56"/></w:rPr></w:style>` +
	`<w:style w:type="paragraph" w:styleId="CoverSubtitle"><w:name w:val="Cover Subtitle"/><w:basedOn w:val="Normal"/><w:pPr><w:jc w:val="center"/></w:pPr><w:rPr><w:rFonts w:ascii="黑体" w:hAnsi="黑体" w:eastAsia="黑体"/><w:b/><w:sz w:val="44"/><w:szCs w:val="44"/></w:rPr></w:style>` +
	`<w:style w:type="paragraph" w:styleId="Heading1"><w:name w:val="heading 1"/><w:basedOn w:val="Normal"/><w:next w:val="Normal"/><w:pPr><w:keepNext/><w:keepLines/><w:pageBreakBefore/><w:spacing w:before="340" w:after="330" w:line="400" w:lineRule="auto"/><w:jc w:val="left"/><w:outlineLvl w:val="0"/></w:pPr><w:rPr><w:rFonts w:ascii="黑体" w:hAnsi="黑体" w:eastAsia="黑体"/><w:b/><w:sz w:val="36"/><w:szCs w:val="36"/></w:rPr></w:style>` +
	`<w:style w:type="paragraph" w:styleId="Heading2"><w:name w:val="heading 2"/><w:basedOn w:val="Normal"/><w:next w:val="Normal"/><w:pPr><w:keepNext/><w:keepLines/><w:spacing w:before="260" w:after="200" w:line="360" w:lineRule="auto"/><w:jc w:val="left"/><w:outlineLvl w:val="1"/></w:pPr><w:rPr><w:rFonts w:ascii="黑体" w:hAnsi="黑体" w:eastAsia="黑体"/><w:b/><w:sz w:val="30"/><w:szCs w:val="30"/></w:rPr></w:style>` +
	`<w:style w:type="paragraph" w:styleId="Heading3"><w:name w:val="heading 3"/><w:basedOn w:val="Normal"/><w:next w:val="Normal"/><w:pPr><w:keepNext/><w:keepLines/><w:spacing w:before="200" w:after="120" w:line="360" w:lineRule="auto"/><w:jc w:val="left"/><w:outlineLvl w:val="2"/></w:pPr><w:rPr><w:rFonts w:ascii="黑体" w:hAnsi="黑体" w:eastAsia="黑体"/><w:b/><w:sz w:val="26"/><w:szCs w:val="26"/></w:rPr></w:style>` +
	`</w:styles>`
