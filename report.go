package main

import (
	"archive/zip"
	"fmt"
	"html"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	pageWidth  = 12240
	pageHeight = 15840
	margin     = 1440
	contentW   = 9360
)

func writeDOCX(path string, report scanReport, includeEvidence bool, maxSamples int) error {
	if maxSamples < 1 {
		maxSamples = defaultMaxSamples
	}
	dir := filepath.Dir(path)
	if dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	tmp, err := os.CreateTemp(dir, ".piiscan-report-*.docx")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := buildDOCX(tmp, report, includeEvidence, maxSamples); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}

func buildDOCX(file *os.File, report scanReport, includeEvidence bool, maxSamples int) error {
	archive := zip.NewWriter(file)
	parts := map[string]string{
		"[Content_Types].xml":          contentTypesXML(),
		"_rels/.rels":                  rootRelationshipsXML(),
		"docProps/core.xml":            corePropertiesXML(),
		"docProps/app.xml":             appPropertiesXML(),
		"word/document.xml":            documentXML(report, includeEvidence, maxSamples),
		"word/styles.xml":              stylesXML(),
		"word/numbering.xml":           numberingXML(),
		"word/settings.xml":            settingsXML(),
		"word/header1.xml":             headerXML(),
		"word/footer1.xml":             footerXML(),
		"word/_rels/document.xml.rels": documentRelationshipsXML(),
	}
	keys := make([]string, 0, len(parts))
	for key := range parts {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, name := range keys {
		entry, err := archive.Create(name)
		if err != nil {
			_ = archive.Close()
			return err
		}
		if _, err := entry.Write([]byte(parts[name])); err != nil {
			_ = archive.Close()
			return err
		}
	}
	return archive.Close()
}

func documentXML(report scanReport, includeEvidence bool, maxSamples int) string {
	var body strings.Builder
	body.WriteString(paragraph("PII Scan Incident Response Report", "Title", "", false, false))
	body.WriteString(paragraph("Automated triage report - suspected findings require analyst validation", "Subtitle", "666666", false, false))
	body.WriteString(paragraph(fmt.Sprintf("Generated: %s UTC", report.Stats.Finished.Format(time.RFC3339)), "Metadata", "666666", false, false))
	body.WriteString(paragraph(fmt.Sprintf("Target: %s", report.Root), "Metadata", "666666", false, false))
	body.WriteString(paragraph(fmt.Sprintf("Scanner version: %s | Physical files: %d | Logical documents: %d", version, report.Stats.PhysicalFiles, report.Stats.LogicalFiles), "Metadata", "666666", false, false))

	body.WriteString(heading("Executive summary", 1))
	high, medium, low := 0, 0, 0
	for _, finding := range report.Findings {
		switch {
		case finding.Score >= 85:
			high++
		case finding.Score >= 65:
			medium++
		default:
			if finding.Score > 0 {
				low++
			}
		}
	}
	body.WriteString(paragraph(fmt.Sprintf("The scan identified %d suspected logical documents across %d physical files. Risk-ranked results: %d high confidence, %d medium confidence, and %d lower confidence. %d extractor or access warnings were recorded.", report.Stats.Suspected, report.Stats.PhysicalFiles, high, medium, low, report.Stats.Warnings), "Normal", "", false, false))
	body.WriteString(paragraph("Confidence is an explainable triage score, not a probability. It reflects detector specificity, validation checks, corroborating categories, and repeated signals. Analysts should validate the source, business context, legal basis, and containment requirements before acting.", "Callout", "7A5A00", false, false))

	body.WriteString(heading("Findings", 1))
	if len(report.Findings) == 0 {
		body.WriteString(paragraph("No findings met the configured confidence threshold.", "Normal", "", false, false))
	} else {
		headers := []string{"Score", "File or logical source", "Format", "Categories", "Warnings"}
		rows := make([][]string, 0, len(report.Findings))
		for _, finding := range report.Findings {
			if finding.Score == 0 && len(finding.Warnings) == 0 {
				continue
			}
			warnings := strings.Join(finding.Warnings, "; ")
			rows = append(rows, []string{fmt.Sprintf("%d%%", finding.Score), finding.Name, finding.Format, categoryText(finding.Categories), warnings})
		}
		body.WriteString(table(headers, rows, []int{900, 3600, 1100, 2460, 1300}))
	}

	body.WriteString(heading("Review priorities", 1))
	priorities := []string{
		"Start with high-confidence rows and preserve the original files and hashes before remediation.",
		"Validate each detector signal against the source context; do not treat a confidence percentage as proof of a regulated data element.",
		"For confirmed exposure, identify the data owner, access path, retention basis, and containment or notification obligations.",
	}
	for _, item := range priorities {
		body.WriteString(listItem(item, 2))
	}

	body.WriteString(heading("Methodology and coverage", 1))
	for _, item := range []string{
		"A shared detector runs over extracted text and structured values rather than using a file-extension-specific pattern list. It validates high-risk candidates such as SSNs, payment cards, dates, IBANs, and phone numbers before scoring.",
		"Text, CSV/TSV, JSON/JSONL, SQL, XML/HTML, YAML, RTF, logs, source files, and email messages are scanned directly. ZIP/TAR/GZIP containers are inspected with bounded decompression, and common DOCX/XLSX/PPTX and ODT/ODS/ODP packages are decoded through their XML parts.",
		"SQLite databases are opened read-only and scanned table by table. PDFs with an embedded text layer are extracted; scanned-image PDFs, encrypted documents, and OCR are reported as coverage limitations. Legacy DOC/XLS/PPT files use best-effort printable-string extraction.",
	} {
		body.WriteString(listItem(item, 1))
	}

	if includeEvidence {
		body.WriteString(heading("Redacted evidence", 1))
		body.WriteString(paragraph("Evidence is intentionally redacted. The report never writes raw identifier values unless the caller separately handles the source data.", "Normal", "", false, false))
		for _, finding := range report.Findings {
			if finding.Score == 0 {
				continue
			}
			body.WriteString(heading(finding.Name, 2))
			count := 0
			for _, item := range finding.Evidence {
				if count >= maxSamples {
					break
				}
				body.WriteString(listItem(fmt.Sprintf("%s: %s", item.Kind, redactEvidence(item)), 1))
				count++
			}
		}
	}

	body.WriteString(heading("Incident response checklist", 1))
	for _, item := range []string{
		"Preserve the report, source files, and relevant file-system or database metadata as evidence.",
		"Confirm whether each suspected item is live, replicated, backed up, or externally shared.",
		"Classify confirmed data under the organization’s privacy and breach-response policy.",
		"Record containment, owner, decision, and follow-up evidence in the incident case.",
	} {
		body.WriteString(listItem(item, 3))
	}

	body.WriteString(heading("Warnings and limitations", 1))
	if report.Stats.Warnings == 0 {
		body.WriteString(paragraph("No extractor warnings were recorded.", "Normal", "", false, false))
	} else {
		for _, finding := range report.Findings {
			for _, warning := range finding.Warnings {
				body.WriteString(listItem(fmt.Sprintf("%s: %s", finding.Name, warning), 1))
			}
		}
	}

	return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
		`<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">` +
		`<w:body>` + body.String() +
		`<w:sectPr><w:headerReference w:type="default" r:id="rId3"/><w:footerReference w:type="default" r:id="rId4"/>` +
		fmt.Sprintf(`<w:pgSz w:w="%d" w:h="%d"/><w:pgMar w:top="%d" w:right="%d" w:bottom="%d" w:left="%d" w:header="708" w:footer="708" w:gutter="0"/>`, pageWidth, pageHeight, margin, margin, margin, margin) +
		`</w:sectPr></w:body></w:document>`
}

func paragraph(text, style, color string, bold, italic bool) string {
	run := `<w:r>`
	if color != "" || bold || italic {
		run += `<w:rPr>`
		if color != "" {
			run += `<w:color w:val="` + xmlEscape(color) + `"/>`
		}
		if bold {
			run += `<w:b/>`
		}
		if italic {
			run += `<w:i/>`
		}
		run += `</w:rPr>`
	}
	run += `<w:t xml:space="preserve">` + xmlEscape(text) + `</w:t></w:r>`
	return `<w:p><w:pPr><w:pStyle w:val="` + xmlEscape(style) + `"/></w:pPr>` + run + `</w:p>`
}

func heading(text string, level int) string {
	style := fmt.Sprintf("Heading%d", level)
	return paragraph(text, style, "", true, false)
}

func listItem(text string, numID int) string {
	return `<w:p><w:pPr><w:pStyle w:val="ListParagraph"/><w:numPr><w:ilvl w:val="0"/><w:numId w:val="` + fmt.Sprint(numID) + `"/></w:numPr></w:pPr><w:r><w:t xml:space="preserve">` + xmlEscape(text) + `</w:t></w:r></w:p>`
}

func table(headers []string, rows [][]string, widths []int) string {
	var out strings.Builder
	out.WriteString(`<w:tbl><w:tblPr><w:tblW w:w="9360" w:type="dxa"/><w:tblInd w:w="120" w:type="dxa"/><w:tblLayout w:type="fixed"/><w:tblCellMar><w:top w:w="80" w:type="dxa"/><w:left w:w="120" w:type="dxa"/><w:bottom w:w="80" w:type="dxa"/><w:right w:w="120" w:type="dxa"/></w:tblCellMar><w:tblBorders><w:top w:val="single" w:sz="4" w:color="B7C3D0"/><w:left w:val="single" w:sz="4" w:color="B7C3D0"/><w:bottom w:val="single" w:sz="4" w:color="B7C3D0"/><w:right w:val="single" w:sz="4" w:color="B7C3D0"/><w:insideH w:val="single" w:sz="4" w:color="D8DEE6"/><w:insideV w:val="single" w:sz="4" w:color="D8DEE6"/></w:tblBorders></w:tblPr><w:tblGrid>`)
	for _, width := range widths {
		out.WriteString(fmt.Sprintf(`<w:gridCol w:w="%d"/>`, width))
	}
	out.WriteString(`</w:tblGrid>`)
	out.WriteString(tableRow(headers, widths, true))
	for _, row := range rows {
		out.WriteString(tableRow(row, widths, false))
	}
	out.WriteString(`</w:tbl>`)
	return out.String()
}

func tableRow(values []string, widths []int, header bool) string {
	var out strings.Builder
	out.WriteString(`<w:tr>`)
	if header {
		out.WriteString(`<w:trPr><w:tblHeader/></w:trPr>`)
	}
	for i, width := range widths {
		value := ""
		if i < len(values) {
			value = values[i]
		}
		out.WriteString(fmt.Sprintf(`<w:tc><w:tcPr><w:tcW w:w="%d" w:type="dxa"/>`, width))
		if header {
			out.WriteString(`<w:shd w:val="clear" w:fill="F2F4F7"/>`)
		}
		out.WriteString(`</w:tcPr><w:p><w:pPr><w:pStyle w:val="TableText"/></w:pPr><w:r>`)
		if header {
			out.WriteString(`<w:rPr><w:b/></w:rPr>`)
		}
		out.WriteString(`<w:t xml:space="preserve">` + xmlEscape(value) + `</w:t></w:r></w:p></w:tc>`)
	}
	out.WriteString(`</w:tr>`)
	return out.String()
}

func xmlEscape(value string) string {
	return html.EscapeString(strings.ReplaceAll(strings.ReplaceAll(value, "\r", " "), "\x00", ""))
}

func contentTypesXML() string {
	return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/><Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/><Override PartName="/word/numbering.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.numbering+xml"/><Override PartName="/word/settings.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.settings+xml"/><Override PartName="/word/header1.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.header+xml"/><Override PartName="/word/footer1.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.footer+xml"/><Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/><Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/></Types>`
}

func rootRelationshipsXML() string {
	return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/><Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties" Target="docProps/app.xml"/></Relationships>`
}

func documentRelationshipsXML() string {
	return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/numbering" Target="numbering.xml"/><Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/header" Target="header1.xml"/><Relationship Id="rId4" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/footer" Target="footer1.xml"/><Relationship Id="rId5" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/settings" Target="settings.xml"/></Relationships>`
}

func corePropertiesXML() string {
	return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:title>PII Scan Incident Response Report</dc:title><dc:creator>piiscan</dc:creator><cp:lastModifiedBy>piiscan</cp:lastModifiedBy></cp:coreProperties>`
}

func appPropertiesXML() string {
	return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties"><Application>piiscan</Application></Properties>`
}

func settingsXML() string {
	return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:settings xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:zoom w:percent="100"/><w:themeFontLang w:val="en-US"/></w:settings>`
}

func headerXML() string {
	return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:hdr xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:p><w:pPr><w:pStyle w:val="Header"/></w:pPr><w:r><w:t>piiscan | Incident response report</w:t></w:r></w:p></w:hdr>`
}

func footerXML() string {
	return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:ftr xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:p><w:pPr><w:jc w:val="right"/><w:pStyle w:val="Footer"/></w:pPr><w:r><w:t>Page </w:t></w:r><w:r><w:fldChar w:fldCharType="begin"/><w:instrText xml:space="preserve"> PAGE </w:instrText><w:fldChar w:fldCharType="end"/></w:r></w:p></w:ftr>`
}

func stylesXML() string {
	return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:docDefaults><w:rPrDefault><w:rPr><w:rFonts w:ascii="Calibri" w:hAnsi="Calibri"/><w:sz w:val="22"/><w:lang w:val="en-US"/></w:rPr></w:rPrDefault><w:pPrDefault><w:pPr><w:spacing w:after="120" w:line="264" w:lineRule="auto"/></w:pPr></w:pPrDefault></w:docDefaults><w:style w:type="paragraph" w:default="1" w:styleId="Normal"><w:name w:val="Normal"/><w:rPr><w:rFonts w:ascii="Calibri" w:hAnsi="Calibri"/><w:sz w:val="22"/></w:rPr></w:style><w:style w:type="paragraph" w:styleId="Title"><w:name w:val="Title"/><w:pPr><w:spacing w:before="0" w:after="80"/></w:pPr><w:rPr><w:rFonts w:ascii="Calibri" w:hAnsi="Calibri"/><w:sz w:val="48"/><w:b/><w:color w:val="0B2545"/></w:rPr></w:style><w:style w:type="paragraph" w:styleId="Subtitle"><w:name w:val="Subtitle"/><w:pPr><w:spacing w:before="0" w:after="180"/></w:pPr><w:rPr><w:rFonts w:ascii="Calibri" w:hAnsi="Calibri"/><w:sz w:val="28"/><w:color w:val="666666"/></w:rPr></w:style><w:style w:type="paragraph" w:styleId="Metadata"><w:name w:val="Metadata"/><w:pPr><w:spacing w:before="0" w:after="40"/></w:pPr><w:rPr><w:rFonts w:ascii="Calibri" w:hAnsi="Calibri"/><w:sz w:val="20"/><w:color w:val="666666"/></w:rPr></w:style><w:style w:type="paragraph" w:styleId="Heading1"><w:name w:val="heading 1"/><w:basedOn w:val="Normal"/><w:next w:val="Normal"/><w:uiPriority w:val="9"/><w:qFormat/><w:pPr><w:keepNext/><w:spacing w:before="320" w:after="160"/><w:outlineLvl w:val="0"/></w:pPr><w:rPr><w:rFonts w:ascii="Calibri" w:hAnsi="Calibri"/><w:sz w:val="32"/><w:b/><w:color w:val="2E74B5"/></w:rPr></w:style><w:style w:type="paragraph" w:styleId="Heading2"><w:name w:val="heading 2"/><w:basedOn w:val="Normal"/><w:next w:val="Normal"/><w:uiPriority w:val="9"/><w:pPr><w:keepNext/><w:spacing w:before="240" w:after="120"/><w:outlineLvl w:val="1"/></w:pPr><w:rPr><w:rFonts w:ascii="Calibri" w:hAnsi="Calibri"/><w:sz w:val="26"/><w:b/><w:color w:val="2E74B5"/></w:rPr></w:style><w:style w:type="paragraph" w:styleId="Callout"><w:name w:val="Callout"/><w:basedOn w:val="Normal"/><w:pPr><w:spacing w:before="120" w:after="160"/><w:shd w:val="clear" w:fill="F4F6F9"/><w:ind w:left="120" w:right="120"/></w:pPr><w:rPr><w:rFonts w:ascii="Calibri" w:hAnsi="Calibri"/><w:sz w:val="22"/><w:color w:val="7A5A00"/></w:rPr></w:style><w:style w:type="paragraph" w:styleId="ListParagraph"><w:name w:val="List Paragraph"/><w:basedOn w:val="Normal"/><w:pPr><w:ind w:left="720" w:hanging="360"/><w:spacing w:after="80"/></w:pPr></w:style><w:style w:type="paragraph" w:styleId="TableText"><w:name w:val="Table Text"/><w:basedOn w:val="Normal"/><w:pPr><w:spacing w:before="0" w:after="40"/><w:widowControl/></w:pPr><w:rPr><w:rFonts w:ascii="Calibri" w:hAnsi="Calibri"/><w:sz w:val="18"/></w:rPr></w:style><w:style w:type="paragraph" w:styleId="Header"><w:name w:val="header"/><w:rPr><w:rFonts w:ascii="Calibri" w:hAnsi="Calibri"/><w:sz w:val="18"/><w:color w:val="666666"/></w:rPr></w:style><w:style w:type="paragraph" w:styleId="Footer"><w:name w:val="footer"/><w:rPr><w:rFonts w:ascii="Calibri" w:hAnsi="Calibri"/><w:sz w:val="18"/><w:color w:val="666666"/></w:rPr></w:style></w:styles>`
}

func numberingXML() string {
	return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:numbering xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:abstractNum w:abstractNumId="0"><w:multiLevelType w:val="singleLevel"/><w:lvl w:ilvl="0"><w:start w:val="1"/><w:numFmt w:val="bullet"/><w:lvlText w:val="•"/><w:lvlJc w:val="left"/><w:pPr><w:tabs><w:tab w:val="num" w:pos="720"/></w:tabs><w:ind w:left="720" w:hanging="360"/></w:pPr><w:rPr><w:rFonts w:ascii="Symbol" w:hAnsi="Symbol"/></w:rPr></w:lvl></w:abstractNum><w:abstractNum w:abstractNumId="1"><w:multiLevelType w:val="singleLevel"/><w:lvl w:ilvl="0"><w:start w:val="1"/><w:numFmt w:val="decimal"/><w:lvlText w:val="%1."/><w:lvlJc w:val="left"/><w:pPr><w:tabs><w:tab w:val="num" w:pos="720"/></w:tabs><w:ind w:left="720" w:hanging="360"/></w:pPr></w:lvl></w:abstractNum><w:abstractNum w:abstractNumId="2"><w:multiLevelType w:val="singleLevel"/><w:lvl w:ilvl="0"><w:start w:val="1"/><w:numFmt w:val="bullet"/><w:lvlText w:val="☐"/><w:lvlJc w:val="left"/><w:pPr><w:tabs><w:tab w:val="num" w:pos="720"/></w:tabs><w:ind w:left="720" w:hanging="360"/></w:pPr></w:lvl></w:abstractNum><w:num w:numId="1"><w:abstractNumId w:val="0"/></w:num><w:num w:numId="2"><w:abstractNumId w:val="1"/></w:num><w:num w:numId="3"><w:abstractNumId w:val="2"/></w:num></w:numbering>`
}
