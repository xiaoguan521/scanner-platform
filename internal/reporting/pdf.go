package reporting

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	"unicode"
)

// The PDF renderer intentionally uses the PDF standard's built-in Simplified
// Chinese CID font. This keeps the artifact deterministic and avoids shipping
// a third-party font or making a network request while still preserving the
// Chinese report text in ordinary PDF viewers.
const (
	pdfCatalogObject = 1
	pdfPagesObject   = 2
	pdfFontObject    = 3
	pdfCIDObject     = 4
	pdfFirstPage     = 5
)

type pdfLine struct {
	text    string
	size    int
	leading int
}

type pdfPage struct {
	lines []pdfLine
}

func renderPDF(w io.Writer, s Snapshot) error {
	pages := paginatePDF(s)
	if len(pages) == 0 {
		pages = []pdfPage{{lines: []pdfLine{{text: "暂无报告内容", size: 12, leading: 16}}}}
	}

	objects := make([][]byte, pdfFirstPage+len(pages)*2)
	objects[pdfCatalogObject] = []byte("<< /Type /Catalog /Pages 2 0 R /Lang (zh-CN) >>")
	objects[pdfFontObject] = []byte("<< /Type /Font /Subtype /Type0 /BaseFont /STSong-Light /Encoding /UniGB-UCS2-H /DescendantFonts [4 0 R] >>")
	objects[pdfCIDObject] = []byte("<< /Type /Font /Subtype /CIDFontType0 /BaseFont /STSong-Light /CIDSystemInfo << /Registry (Adobe) /Ordering (GB1) /Supplement 4 >> /DW 1000 >>")

	kids := make([]string, 0, len(pages))
	for i, page := range pages {
		pageObject := pdfFirstPage + i*2
		contentObject := pageObject + 1
		kids = append(kids, fmt.Sprintf("%d 0 R", pageObject))
		content := pdfPageContent(s, page, i+1, len(pages))
		objects[pageObject] = []byte(fmt.Sprintf("<< /Type /Page /Parent %d 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 %d 0 R >> >> /Contents %d 0 R >>", pdfPagesObject, pdfFontObject, contentObject))
		objects[contentObject] = pdfStream(content)
	}
	objects[pdfPagesObject] = []byte(fmt.Sprintf("<< /Type /Pages /Kids [%s] /Count %d >>", strings.Join(kids, " "), len(pages)))

	return writePDF(w, objects)
}

func paginatePDF(s Snapshot) []pdfPage {
	document := BuildDocument(s)
	pages := []pdfPage{}
	page := pdfPage{}
	remainingHeight := 736
	startPage := func() {
		if len(page.lines) > 0 {
			pages = append(pages, page)
		}
		page = pdfPage{}
		remainingHeight = 736
	}
	add := func(text string, size, leading int, forceNewPage bool) {
		if forceNewPage && len(page.lines) > 0 {
			startPage()
		}
		wrapped := wrapPDFText(text, 86)
		if len(wrapped) == 0 {
			wrapped = []string{""}
		}
		for _, line := range wrapped {
			if remainingHeight < leading {
				startPage()
			}
			page.lines = append(page.lines, pdfLine{text: line, size: size, leading: leading})
			remainingHeight -= leading
		}
	}
	for sectionIndex, section := range document.Sections {
		add(section.Title, 15, 20, sectionIndex > 0)
		for _, paragraph := range section.Paragraphs {
			add(paragraph, 9, 13, false)
		}
		for _, table := range section.Tables {
			add(table.Title, 11, 15, false)
			add(strings.Join(table.Headers, " | "), 8, 12, false)
			for _, row := range table.Rows {
				add(strings.Join(row, " | "), 8, 12, false)
			}
			if table.Truncated {
				add("更多信息请在平台查看或下载 Excel。", 8, 12, false)
			}
		}
	}
	if len(page.lines) > 0 {
		pages = append(pages, page)
	}
	return pages
}

func wrapPDFText(value string, width int) []string {
	value = strings.Map(func(r rune) rune {
		if r == '\t' || r == '\n' || r == '\r' || !unicode.IsControl(r) {
			return r
		}
		return -1
	}, value)
	parts := strings.Split(value, "\n")
	lines := []string{}
	for _, part := range parts {
		runes := []rune(part)
		if len(runes) == 0 {
			lines = append(lines, "")
			continue
		}
		for len(runes) > width {
			lines = append(lines, string(runes[:width]))
			runes = runes[width:]
		}
		lines = append(lines, string(runes))
	}
	return lines
}

func pdfPageContent(s Snapshot, page pdfPage, pageNumber, pageCount int) []byte {
	var b strings.Builder
	writePDFText(&b, 8, 50, 820, s.Template.Header)
	if len(page.lines) > 0 {
		b.WriteString("BT\n/F1 ")
		b.WriteString(fmt.Sprint(page.lines[0].size))
		b.WriteString(" Tf 50 790 Td ")
		b.WriteString(pdfTextHex(page.lines[0].text))
		b.WriteString(" Tj\n")
		for _, line := range page.lines[1:] {
			b.WriteString("/F1 ")
			b.WriteString(fmt.Sprint(line.size))
			b.WriteString(" Tf 0 -")
			b.WriteString(fmt.Sprint(line.leading))
			b.WriteString(" Td ")
			b.WriteString(pdfTextHex(line.text))
			b.WriteString(" Tj\n")
		}
		b.WriteString("ET\n")
	}
	writePDFText(&b, 8, 50, 28, fmt.Sprintf("%s · 第 %d/%d 页", s.Template.Footer, pageNumber, pageCount))
	return []byte(b.String())
}

func writePDFText(b *strings.Builder, size, x, y int, text string) {
	b.WriteString("BT\n/F1 ")
	b.WriteString(fmt.Sprint(size))
	b.WriteString(" Tf ")
	b.WriteString(fmt.Sprintf("%d %d Td ", x, y))
	b.WriteString(pdfTextHex(text))
	b.WriteString(" Tj\nET\n")
}

func pdfTextHex(value string) string {
	var b strings.Builder
	b.WriteByte('<')
	for _, r := range value {
		if r == '\n' || r == '\r' || r == '\t' || unicode.IsControl(r) {
			continue
		}
		if r <= 0xffff {
			fmt.Fprintf(&b, "%04X", r)
			continue
		}
		r -= 0x10000
		fmt.Fprintf(&b, "%04X%04X", 0xd800+(r>>10), 0xdc00+(r&0x3ff))
	}
	b.WriteByte('>')
	return b.String()
}

func pdfStream(content []byte) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "<< /Length %d >>\nstream\n", len(content))
	b.Write(content)
	b.WriteString("\nendstream")
	return b.Bytes()
}

func writePDF(w io.Writer, objects [][]byte) error {
	var out bytes.Buffer
	out.WriteString("%PDF-1.4\n%\xE2\xE3\xCF\xD3\n")
	offsets := make([]int, len(objects))
	for id := 1; id < len(objects); id++ {
		offsets[id] = out.Len()
		fmt.Fprintf(&out, "%d 0 obj\n", id)
		out.Write(objects[id])
		out.WriteString("\nendobj\n")
	}
	xref := out.Len()
	fmt.Fprintf(&out, "xref\n0 %d\n0000000000 65535 f \n", len(objects))
	for id := 1; id < len(objects); id++ {
		fmt.Fprintf(&out, "%010d 00000 n \n", offsets[id])
	}
	fmt.Fprintf(&out, "trailer\n<< /Size %d /Root %d 0 R >>\nstartxref\n%d\n%%%%EOF\n", len(objects), pdfCatalogObject, xref)
	_, err := w.Write(out.Bytes())
	return err
}
