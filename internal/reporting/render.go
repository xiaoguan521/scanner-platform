package reporting

import (
	"archive/zip"
	"context"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"html"
	"image/png"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"
)

func ValidateTemplate(t Template) error {
	if t.ID == "" || len(t.ID) > 100 || len(t.Name) > 200 || len(t.Company) > 200 || len(t.Header) > 500 || len(t.Footer) > 500 || len(t.RatingText) > 20000 || len(t.Advice) > 20000 {
		return fmt.Errorf("%w: 模板字段长度无效", ErrInvalid)
	}
	allowed := map[string]bool{"cover": true, "overview": true, "assets": true, "asset-risks": true, "asset-details": true, "risk-statistics": true, "risk-details": true, "appendix": true}
	for k := range t.Sections {
		if !allowed[k] {
			return fmt.Errorf("%w: 未知章节", ErrInvalid)
		}
	}
	if t.Logo != "" {
		if !strings.HasPrefix(t.Logo, "data:image/png;base64,") || len(t.Logo) > 1400000 {
			return fmt.Errorf("%w: Logo 仅支持不超过 1 MiB 的 PNG data URL", ErrInvalid)
		}
		data, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(t.Logo, "data:image/png;base64,"))
		if err != nil {
			return ErrInvalid
		}
		cfg, err := png.DecodeConfig(strings.NewReader(string(data)))
		if err != nil || cfg.Width > 2048 || cfg.Height > 2048 || cfg.Width < 1 || cfg.Height < 1 {
			return fmt.Errorf("%w: Logo PNG 尺寸无效", ErrInvalid)
		}
		if _, err := png.Decode(strings.NewReader(string(data))); err != nil {
			return fmt.Errorf("%w: Logo PNG 内容无效", ErrInvalid)
		}
	}
	return nil
}

type boundedWriter struct {
	ctx context.Context
	w   io.Writer
	n   int64
}

func (w *boundedWriter) Write(p []byte) (int, error) {
	if err := w.ctx.Err(); err != nil {
		return 0, err
	}
	if w.n+int64(len(p)) > MaxFileBytes {
		return 0, ErrTooLarge
	}
	n, err := w.w.Write(p)
	w.n += int64(n)
	return n, err
}
func Render(ctx context.Context, w io.Writer, s Snapshot, format string) error {
	if s.SchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported snapshot schema %d", s.SchemaVersion)
	}
	bw := &boundedWriter{ctx: ctx, w: w}
	switch format {
	case "html":
		return renderHTML(bw, s)
	case "xlsx":
		return renderXLSX(bw, s)
	case "docx":
		return renderDOCX(bw, s)
	case "csv":
		return renderCSV(bw, s)
	case "json":
		return renderJSON(bw, s)
	default:
		return ErrInvalid
	}
}

// renderJSON writes the complete immutable snapshot for machine processing.
// Snapshot fields intentionally exclude report job storage paths and credentials.
func renderJSON(w io.Writer, s Snapshot) error {
	data, err := json.Marshal(s)
	if err != nil {
		return err
	}
	if err := write(w, string(data)); err != nil {
		return err
	}
	return write(w, "\n")
}

// renderCSV exports the same vulnerability detail table used by the report
// document. JSON remains the lossless machine-readable snapshot; CSV is a
// flat vulnerability detail export suitable for spreadsheet workflows.
func renderCSV(w io.Writer, s Snapshot) error {
	writer := csv.NewWriter(w)
	table := findingTable(s)
	if err := writer.Write(table.Headers); err != nil {
		return err
	}
	for _, row := range table.Rows {
		cells := make([]string, len(row))
		for i, value := range row {
			cells[i] = csvCell(value)
		}
		if err := writer.Write(cells); err != nil {
			return err
		}
	}
	writer.Flush()
	return writer.Error()
}

// csvCell prevents spreadsheet applications from treating exported evidence
// or titles as formulas. The apostrophe is part of the CSV safety encoding.
func csvCell(value string) string {
	if value != "" && strings.ContainsRune("=+-@", rune(value[0])) {
		return "'" + value
	}
	return value
}

func esc(v string) string { return html.EscapeString(v) }
func x(v string) string {
	var b strings.Builder
	clean := strings.Map(func(r rune) rune {
		if r == 9 || r == 10 || r == 13 || r >= 32 && r <= 0xD7FF || r >= 0xE000 && r <= 0xFFFD || r >= 0x10000 && r <= 0x10FFFF {
			return r
		}
		return -1
	}, v)
	_ = xml.EscapeText(&b, []byte(clean))
	return b.String()
}
func write(w io.Writer, v string) error { _, err := io.WriteString(w, v); return err }
func renderHTML(w io.Writer, s Snapshot) error {
	if err := write(w, `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src data:; style-src 'unsafe-inline'"><title>`+esc(s.Name)+`</title><style>body{font:14px/1.65 system-ui,sans-serif;color:#172033;margin:36px auto;max-width:1200px;padding:0 24px}h1,h2{color:#12396c}h2{border-bottom:2px solid #dbeafe;padding-top:28px}table{border-collapse:collapse;width:100%;margin:12px 0 24px;font-size:12px;table-layout:auto}th,td{border:1px solid #d7dfe9;padding:8px;text-align:left;overflow-wrap:anywhere;white-space:pre-wrap}th{background:#eff6ff}img{max-width:100%;height:auto}footer{color:#64748b}p{white-space:pre-wrap}.muted{color:#64748b}@media print{h2{break-before:page}tr{break-inside:avoid}}</style></head><body><header>`+esc(s.Template.Header)+`</header>`); err != nil {
		return err
	}
	if s.Template.Logo != "" {
		if err := write(w, `<img alt="公司 Logo" width="160" src="`+esc(s.Template.Logo)+`">`); err != nil {
			return err
		}
	}
	for _, sec := range BuildDocument(s).Sections {
		if err := write(w, "<section><h2>"+esc(sec.Title)+"</h2>"); err != nil {
			return err
		}
		for _, p := range sec.Paragraphs {
			if err := write(w, "<p>"+esc(p)+"</p>"); err != nil {
				return err
			}
		}
		for _, t := range sec.Tables {
			for _, c := range sec.Charts {
				if c.Title == t.Title {
					if err := write(w, "<h3>"+esc(c.Title)+`</h3><img alt="`+esc(c.Title)+`，序号与下表顺序一致" src="data:image/png;base64,`+base64.StdEncoding.EncodeToString(c.PNG)+`">`); err != nil {
						return err
					}
				}
			}

			if err := htmlTable(w, t); err != nil {
				return err
			}
		}
		if err := write(w, "</section>"); err != nil {
			return err
		}
	}
	return write(w, "<footer>"+esc(s.Template.Footer)+"</footer></body></html>")
}
func htmlTable(w io.Writer, t Table) error {
	if err := write(w, "<h3>"+esc(t.Title)+"</h3><table><thead><tr>"); err != nil {
		return err
	}
	for _, h := range t.Headers {
		if err := write(w, "<th>"+esc(h)+"</th>"); err != nil {
			return err
		}
	}
	if err := write(w, "</tr></thead><tbody>"); err != nil {
		return err
	}
	if len(t.Rows) == 0 {
		if err := write(w, fmt.Sprintf(`<tr><td colspan="%d">该范围未记录数据；不代表已验证安全。</td></tr>`, len(t.Headers))); err != nil {
			return err
		}
	}
	for _, r := range t.Rows {
		if err := write(w, "<tr>"); err != nil {
			return err
		}
		for _, v := range r {
			if err := write(w, "<td>"+esc(v)+"</td>"); err != nil {
				return err
			}
		}
		if err := write(w, "</tr>"); err != nil {
			return err
		}
	}
	if err := write(w, "</tbody></table>"); err != nil {
		return err
	}
	if t.Truncated {
		return write(w, "<p class=\"muted\">仅展示 TOP100 或 TOP5；更多信息请在平台查看或下载 Excel。</p>")
	}
	return nil
}

const xmlHeader = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>`

func zipString(z *zip.Writer, name, body string) error {
	w, err := z.Create(name)
	if err != nil {
		return err
	}
	return write(w, xmlHeader+body)
}
func zipBytes(z *zip.Writer, name string, data []byte) error {
	w, err := z.Create(name)
	if err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}
func rel(id, typ, target string) string {
	return `<Relationship Id="` + id + `" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/` + typ + `" Target="` + target + `"/>`
}
func contentTypes(extra string) string {
	return `<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Default Extension="png" ContentType="image/png"/>` + extra + `</Types>`
}
func colName(n int) string {
	s := ""
	for n > 0 {
		n--
		s = string(rune('A'+n%26)) + s
		n /= 26
	}
	return s
}
func renderXLSX(w io.Writer, s Snapshot) error {
	z := zip.NewWriter(w)
	tables := Workbook(s)
	types := `<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/><Override PartName="/xl/drawings/drawing1.xml" ContentType="application/vnd.openxmlformats-officedocument.drawing+xml"/>`
	sheets, rels := "", ""
	for i, t := range tables {
		n := strconv.Itoa(i + 1)
		types += `<Override PartName="/xl/worksheets/sheet` + n + `.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>`
		sheets += `<sheet name="` + x(t.Title) + `" sheetId="` + n + `" r:id="rId` + n + `"/>`
		rels += rel("rId"+n, "worksheet", "worksheets/sheet"+n+".xml")
	}
	rels += rel("styles", "styles", "styles.xml")
	for _, entry := range []struct{ name, body string }{{"[Content_Types].xml", contentTypes(types)}, {"_rels/.rels", `<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">` + rel("rId1", "officeDocument", "xl/workbook.xml") + `</Relationships>`}, {"xl/workbook.xml", `<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets>` + sheets + `</sheets></workbook>`}, {"xl/_rels/workbook.xml.rels", `<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">` + rels + `</Relationships>`}, {"xl/styles.xml", `<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><fonts count="2"><font><sz val="11"/><name val="Arial"/></font><font><b/><sz val="11"/><name val="Calibri"/></font></fonts><fills count="2"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill></fills><borders count="1"><border/></borders><cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs><cellXfs count="2"><xf fontId="0"/><xf fontId="1" applyFont="1"/></cellXfs><cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles></styleSheet>`}} {
		if err := zipString(z, entry.name, entry.body); err != nil {
			return err
		}
	}
	for i, t := range tables {
		if len(t.Rows) > 1048575 {
			return ErrTooLarge
		}
		sw, err := z.Create(fmt.Sprintf("xl/worksheets/sheet%d.xml", i+1))
		if err != nil {
			return err
		}
		if err := write(sw, xmlHeader+`<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheetViews><sheetView workbookViewId="0"><pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/></sheetView></sheetViews><sheetFormatPr defaultRowHeight="18"/><cols><col min="1" max="30" width="24" customWidth="1"/></cols><sheetData>`); err != nil {
			return err
		}
		for ri := 0; ri <= len(t.Rows); ri++ {
			row := t.Headers
			if ri > 0 {
				row = t.Rows[ri-1]
			}
			if err := write(sw, fmt.Sprintf(`<row r="%d">`, ri+1)); err != nil {
				return err
			}
			for ci, v := range row {
				if utf8.RuneCountInString(v) > 32767 {
					v = string([]rune(v)[:32740]) + "…（内容过长，平台查看）"
				}
				style := ""
				if ri == 0 {
					style = ` s="1"`
				}
				if err := write(sw, fmt.Sprintf(`<c r="%s%d" t="inlineStr"%s><is><t xml:space="preserve">%s</t></is></c>`, colName(ci+1), ri+1, style, x(v))); err != nil {
					return err
				}
			}
			if err := write(sw, `</row>`); err != nil {
				return err
			}
		}
		if err := write(sw, `</sheetData><autoFilter ref="A1:`+colName(len(t.Headers))+strconv.Itoa(len(t.Rows)+1)+`"/>`); err != nil {
			return err
		}
		if i == 0 {
			if err := write(sw, `<drawing r:id="chartImage"/>`); err != nil {
				return err
			}
		}
		if err := write(sw, `</worksheet>`); err != nil {
			return err
		}
	}
	if err := zipString(z, "xl/worksheets/_rels/sheet1.xml.rels", `<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">`+rel("chartImage", "drawing", "../drawings/drawing1.xml")+`</Relationships>`); err != nil {
		return err
	}
	chartImage := chart(Table{Title: "漏洞严重度", Rows: levelRows(s.Summary)})
	if err := zipBytes(z, "xl/media/chart1.png", chartImage.PNG); err != nil {
		return err
	}
	drawingRels := rel("image1", "image", "../media/chart1.png")
	drawing := xlsxPicture("image1", 1, 4, 1, 6096000, 1981200, "漏洞严重度：严重、高危、中危、低危、信息")
	if s.Template.Logo != "" {
		logo, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(s.Template.Logo, "data:image/png;base64,"))
		if err := zipBytes(z, "xl/media/logo.png", logo); err != nil {
			return err
		}
		drawingRels += rel("logo", "image", "../media/logo.png")
		cx, cy := logoSize(logo)
		drawing += xlsxPicture("logo", 2, 4, 15, cx, cy, "公司 Logo")
	}
	if err := zipString(z, "xl/drawings/_rels/drawing1.xml.rels", `<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">`+drawingRels+`</Relationships>`); err != nil {
		return err
	}
	if err := zipString(z, "xl/drawings/drawing1.xml", `<xdr:wsDr xmlns:xdr="http://schemas.openxmlformats.org/drawingml/2006/spreadsheetDrawing" xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main">`+drawing+`</xdr:wsDr>`); err != nil {
		return err
	}
	return z.Close()
}
func wordP(v, style string) string {
	pr := ""
	if style != "" {
		pr = `<w:pPr><w:pStyle w:val="` + style + `"/>`
		if style == "TableTextKeep" {
			pr += `<w:keepNext w:val="1"/>`
		}
		pr += `</w:pPr>`
	}
	return `<w:p>` + pr + `<w:r><w:rPr><w:rFonts w:ascii="Arial" w:hAnsi="Arial" w:eastAsia="Arial Unicode MS" w:hint="eastAsia"/><w:lang w:val="en-US" w:eastAsia="zh-CN"/></w:rPr><w:t xml:space="preserve">` + x(v) + `</w:t></w:r></w:p>`
}
func wordPicture(id string, n int) string { return wordPictureSize(id, n, 5486400, 1783080) }
func wordPictureSize(id string, n, cx, cy int) string {
	return fmt.Sprintf(`<w:p><w:pPr><w:keepNext w:val="1"/><w:keepLines/></w:pPr><w:r><w:drawing><wp:inline xmlns:wp="http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing"><wp:extent cx="%d" cy="%d"/><wp:docPr id="%d" name="服务端统计图"/><a:graphic xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"><a:graphicData uri="http://schemas.openxmlformats.org/drawingml/2006/picture"><pic:pic xmlns:pic="http://schemas.openxmlformats.org/drawingml/2006/picture"><pic:nvPicPr><pic:cNvPr id="0" name="统计图"/><pic:cNvPicPr/></pic:nvPicPr><pic:blipFill><a:blip r:embed="%s"/><a:stretch><a:fillRect/></a:stretch></pic:blipFill><pic:spPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="%d" cy="%d"/></a:xfrm><a:prstGeom prst="rect"><a:avLst/></a:prstGeom></pic:spPr></pic:pic></a:graphicData></a:graphic></wp:inline></w:drawing></w:r></w:p>`, cx, cy, n, id, cx, cy)
}
func renderDOCX(w io.Writer, s Snapshot) error {
	z := zip.NewWriter(w)
	d := BuildDocument(s)
	rels := rel("header", "header", "header1.xml") + rel("footer", "footer", "footer1.xml") + rel("styles", "styles", "styles.xml")
	images := []Chart{}
	for _, sec := range d.Sections {
		images = append(images, sec.Charts...)
	}
	for i, c := range images {
		id := strconv.Itoa(i + 1)
		rels += rel("image"+id, "image", "media/chart"+id+".png")
		if err := zipBytes(z, "word/media/chart"+id+".png", c.PNG); err != nil {
			return err
		}
	}
	if s.Template.Logo != "" {
		data, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(s.Template.Logo, "data:image/png;base64,"))
		rels += rel("logo", "image", "media/logo.png")
		if err := zipBytes(z, "word/media/logo.png", data); err != nil {
			return err
		}
	}
	types := `<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/><Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/><Override PartName="/word/header1.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.header+xml"/><Override PartName="/word/footer1.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.footer+xml"/>`
	for _, entry := range []struct{ name, body string }{{"[Content_Types].xml", contentTypes(types)}, {"_rels/.rels", `<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">` + rel("rId1", "officeDocument", "word/document.xml") + `</Relationships>`}, {"word/_rels/document.xml.rels", `<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">` + rels + `</Relationships>`}, {"word/styles.xml", `<w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:docDefaults><w:rPrDefault><w:rPr><w:rFonts w:ascii="Arial" w:hAnsi="Arial" w:eastAsia="Arial Unicode MS"/><w:lang w:val="en-US" w:eastAsia="zh-CN"/><w:sz w:val="22"/></w:rPr></w:rPrDefault></w:docDefaults><w:style w:type="paragraph" w:default="1" w:styleId="Normal"><w:name w:val="Normal"/><w:pPr><w:spacing w:after="100" w:line="276" w:lineRule="auto"/></w:pPr></w:style><w:style w:type="paragraph" w:styleId="TableText"><w:name w:val="Table Text"/><w:basedOn w:val="Normal"/><w:pPr><w:spacing w:before="0" w:after="0" w:line="240" w:lineRule="auto"/></w:pPr><w:rPr><w:sz w:val="20"/></w:rPr></w:style><w:style w:type="paragraph" w:styleId="TableTextKeep"><w:name w:val="Table Text Keep"/><w:basedOn w:val="TableText"/><w:pPr><w:keepNext/></w:pPr></w:style><w:style w:type="paragraph" w:styleId="Title"><w:name w:val="Title"/><w:rPr><w:b/><w:sz w:val="44"/></w:rPr></w:style><w:style w:type="paragraph" w:styleId="Heading1"><w:name w:val="heading 1"/><w:pPr><w:pageBreakBefore/><w:keepNext/></w:pPr><w:rPr><w:b/><w:sz w:val="30"/></w:rPr></w:style><w:style w:type="paragraph" w:styleId="Heading2"><w:name w:val="heading 2"/><w:pPr><w:keepNext/></w:pPr><w:rPr><w:b/><w:sz w:val="24"/></w:rPr></w:style></w:styles>`}, {"word/header1.xml", `<w:hdr xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">` + wordP(s.Template.Header, "") + `</w:hdr>`}, {"word/footer1.xml", `<w:ftr xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">` + wordP(s.Template.Footer, "") + `<w:p><w:r><w:fldChar w:fldCharType="begin"/></w:r><w:r><w:instrText>PAGE</w:instrText></w:r><w:r><w:fldChar w:fldCharType="end"/></w:r></w:p></w:ftr>`}} {
		if err := zipString(z, entry.name, entry.body); err != nil {
			return err
		}
	}
	dw, err := z.Create("word/document.xml")
	if err != nil {
		return err
	}
	if err := write(dw, xmlHeader+`<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><w:body>`); err != nil {
		return err
	}
	if s.Template.Logo != "" {
		logo, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(s.Template.Logo, "data:image/png;base64,"))
		cx, cy := logoSize(logo)
		if err := write(dw, wordPictureSize("logo", 10000, cx, cy)); err != nil {
			return err
		}
	}
	imageID := 0
	for _, sec := range d.Sections {
		style := "Heading1"
		if sec.ID == "cover" {
			style = "Title"
		}
		title := sec.Title
		if sec.ID == "cover" {
			title = s.Template.Name
		}
		if err := write(dw, wordP(title, style)); err != nil {
			return err
		}
		for _, p := range sec.Paragraphs {
			if sec.ID == "cover" && p == s.Name {
				targets := []string{}
				for i, a := range s.Assets {
					if i >= 10 {
						break
					}
					targets = append(targets, a.Address)
				}
				p = fmt.Sprintf("目标范围：%s；共 %d 个目标", strings.Join(targets, "、"), len(s.Assets))
			}
			if err := write(dw, wordP(p, "")); err != nil {
				return err
			}
		}
		for _, original := range sec.Tables {
			pairedChart := false
			for ci, c := range sec.Charts {
				if c.Title == original.Title {
					pairedChart = true
					id := imageID + ci + 1
					if err := write(dw, wordP(c.Title, "Heading2")+wordPicture("image"+strconv.Itoa(id), id)); err != nil {
						return err
					}
				}
			}

			for _, t := range wordTables(original) {
				caption := wordP(t.Title, "Heading2")
				if pairedChart && t.Title == original.Title {
					caption = ""
				}
				if err := write(dw, caption+`<w:tbl><w:tblPr><w:tblW w:w="10206" w:type="dxa"/><w:tblLayout w:type="fixed"/><w:tblBorders><w:top w:val="single" w:sz="4" w:color="D9D9D9"/><w:left w:val="single" w:sz="4" w:color="D9D9D9"/><w:bottom w:val="single" w:sz="4" w:color="D9D9D9"/><w:right w:val="single" w:sz="4" w:color="D9D9D9"/><w:insideH w:val="single" w:sz="4" w:color="D9D9D9"/><w:insideV w:val="single" w:sz="4" w:color="D9D9D9"/></w:tblBorders><w:tblCellMar><w:top w:w="50" w:type="dxa"/><w:left w:w="90" w:type="dxa"/><w:bottom w:w="50" w:type="dxa"/><w:right w:w="90" w:type="dxa"/></w:tblCellMar></w:tblPr>`); err != nil {
					return err
				}
				grid := `<w:tblGrid>`
				for ci := range t.Headers {
					width := 10206 / len(t.Headers)
					if len(t.Headers) == 2 {
						if ci == 0 {
							width = 2300
						} else {
							width = 7906
						}
					}
					grid += fmt.Sprintf(`<w:gridCol w:w="%d"/>`, width)
				}
				grid += `</w:tblGrid>`
				if err := write(dw, grid); err != nil {
					return err
				}
				for ri := -1; ri < len(t.Rows); ri++ {
					row := t.Headers
					if ri >= 0 {
						row = t.Rows[ri]
					}
					if err := write(dw, `<w:tr>`); err != nil {
						return err
					}
					if ri == -1 {
						if err := write(dw, `<w:trPr><w:tblHeader w:val="1"/><w:cantSplit/></w:trPr>`); err != nil {
							return err
						}
					} else {
						if err := write(dw, `<w:trPr><w:cantSplit/></w:trPr>`); err != nil {
							return err
						}
					}
					for ci, v := range row {
						width := 10206 / len(row)
						if len(row) == 2 {
							if ci == 0 {
								width = 2300
							} else {
								width = 7906
							}
						}
						properties := fmt.Sprintf(`<w:tcPr><w:tcW w:w="%d" w:type="dxa"/><w:vAlign w:val="center"/>`, width)
						if ri == -1 {
							properties += `<w:shd w:fill="EFF6FF"/>`
						}
						properties += `</w:tcPr>`
						style := "TableText"
						if len(t.Rows) <= 25 && ri < len(t.Rows)-1 {
							style = "TableTextKeep"
						}
						if err := write(dw, `<w:tc>`+properties+wordP(v, style)+`</w:tc>`); err != nil {
							return err
						}
					}
					if err := write(dw, `</w:tr>`); err != nil {
						return err
					}
				}
				if err := write(dw, `</w:tbl>`); err != nil {
					return err
				}
				if t.Truncated {
					if err := write(dw, wordP("更多信息请在平台查看或下载 Excel。", "")); err != nil {
						return err
					}
				}
			}
		}
		imageID += len(sec.Charts)
	}
	if err := write(dw, `<w:sectPr><w:headerReference w:type="default" r:id="header"/><w:footerReference w:type="default" r:id="footer"/><w:pgSz w:w="11906" w:h="16838"/><w:pgMar w:top="1134" w:right="850" w:bottom="1134" w:left="850"/></w:sectPr></w:body></w:document>`); err != nil {
		return err
	}
	return z.Close()
}

// Wide asset and service rows become vertical cards so Word remains readable on A4.
func wordTables(t Table) []Table {
	if len(t.Headers) <= 8 {
		return []Table{t}
	}
	out := []Table{}
	for _, row := range t.Rows {
		title := t.Title
		if len(row) > 0 {
			title += " · " + row[0]
		}
		card := newTable(title, "字段", "内容")
		for i, h := range t.Headers {
			if i < len(row) {
				card.Rows = append(card.Rows, []string{h, row[i]})
			}
		}
		out = append(out, card)
	}
	if len(out) == 0 {
		return []Table{newTable(t.Title, "字段", "内容")}
	}
	out[len(out)-1].Truncated = t.Truncated
	return out
}

func logoSize(data []byte) (int, int) {
	cfg, err := png.DecodeConfig(strings.NewReader(string(data)))
	if err != nil || cfg.Width < 1 || cfg.Height < 1 {
		return 1600200, 685800
	}
	cx := 1600200
	cy := cx * cfg.Height / cfg.Width
	if cy > 685800 {
		cy = 685800
		cx = cy * cfg.Width / cfg.Height
	}
	return cx, cy
}
func xlsxPicture(id string, n, col, row, cx, cy int, name string) string {
	return fmt.Sprintf(`<xdr:oneCellAnchor><xdr:from><xdr:col>%d</xdr:col><xdr:colOff>0</xdr:colOff><xdr:row>%d</xdr:row><xdr:rowOff>0</xdr:rowOff></xdr:from><xdr:ext cx="%d" cy="%d"/><xdr:pic><xdr:nvPicPr><xdr:cNvPr id="%d" name="%s"/><xdr:cNvPicPr/></xdr:nvPicPr><xdr:blipFill><a:blip xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" r:embed="%s"/><a:stretch><a:fillRect/></a:stretch></xdr:blipFill><xdr:spPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="%d" cy="%d"/></a:xfrm><a:prstGeom prst="rect"><a:avLst/></a:prstGeom></xdr:spPr></xdr:pic><xdr:clientData/></xdr:oneCellAnchor>`, col, row, cx, cy, n, x(name), id, cx, cy)
}
