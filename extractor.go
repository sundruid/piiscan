package main

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"bytes"
	"compress/gzip"
	"database/sql"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/mail"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/ledongthuc/pdf"
	_ "modernc.org/sqlite"
)

const (
	maxInputBytes        int64 = 128 << 20
	maxArchiveEntryBytes int64 = 32 << 20
	maxArchiveBytes      int64 = 256 << 20
	maxArchiveDepth            = 3
)

type extractedDocument struct {
	Name     string
	Format   string
	Texts    []string
	Fields   []string
	Warnings []string
}

var (
	legacyPrintable = regexp.MustCompile(`[ -~]{5,}`)
	zipOfficeExts   = map[string]bool{".docx": true, ".xlsx": true, ".pptx": true, ".odt": true, ".ods": true, ".odp": true}
	textExts        = map[string]bool{
		".txt": true, ".text": true, ".log": true, ".csv": true, ".tsv": true,
		".json": true, ".jsonl": true, ".ndjson": true, ".sql": true, ".xml": true,
		".html": true, ".htm": true, ".yaml": true, ".yml": true, ".md": true,
		".rtf": true, ".eml": true, ".ics": true, ".ini": true, ".conf": true,
	}
)

func extractPath(path string) ([]extractedDocument, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	ext := strings.ToLower(filepath.Ext(path))
	if ext == ".sqlite" || ext == ".sqlite3" || ext == ".db" {
		return extractSQLite(path)
	}
	if info.Size() > maxInputBytes && info.Mode().IsRegular() {
		return nil, fmt.Errorf("file exceeds %d MiB safety limit", maxInputBytes>>20)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return extractData(filepath.Base(path), path, data, 0, maxArchiveDepth)
}

func extractData(name, displayName string, data []byte, depth, remainingDepth int) ([]extractedDocument, error) {
	ext := strings.ToLower(filepath.Ext(name))
	if zipOfficeExts[ext] || isZip(data) {
		if zipOfficeExts[ext] {
			return extractOffice(name, displayName, data)
		}
		return extractZip(name, displayName, data, depth, remainingDepth)
	}
	if ext == ".gz" || ext == ".tgz" {
		return extractGzip(name, displayName, data, depth, remainingDepth)
	}
	if ext == ".tar" || strings.HasSuffix(strings.ToLower(name), ".tar.gz") {
		return extractTar(name, displayName, data, depth, remainingDepth)
	}
	if ext == ".sqlite" || ext == ".sqlite3" || ext == ".db" || bytes.HasPrefix(data, []byte("SQLite format 3\x00")) {
		return extractSQLiteData(displayName, data)
	}
	if ext == ".pdf" || bytes.HasPrefix(data, []byte("%PDF-")) {
		return extractPDF(name, displayName, data)
	}
	if ext == ".eml" || bytes.Contains(data, []byte("Content-Type:")) && bytes.Contains(data, []byte("MIME-Version:")) {
		return extractEmail(name, displayName, data)
	}
	if isTextData(name, data) {
		return []extractedDocument{extractText(name, displayName, data)}, nil
	}
	if isLegacyOffice(ext) {
		return []extractedDocument{{Name: displayName, Format: "legacy Office (best effort)", Texts: printableStrings(data), Warnings: []string{"legacy Office binary parsed with printable-string extraction; embedded and encoded text may be missed"}}}, nil
	}
	return nil, nil
}

func extractText(name, displayName string, data []byte) extractedDocument {
	doc := extractedDocument{Name: displayName, Format: formatName(name), Texts: []string{string(data)}}
	ext := strings.ToLower(filepath.Ext(name))
	if ext == ".json" || ext == ".jsonl" || ext == ".ndjson" {
		values, fields, warnings := extractJSONStrings(data, ext != ".json")
		doc.Texts = append(doc.Texts, values...)
		doc.Fields = append(doc.Fields, fields...)
		doc.Warnings = append(doc.Warnings, warnings...)
	}
	if ext == ".sql" {
		doc.Fields = append(doc.Fields, sensitiveSQLFields(string(data))...)
	}
	return doc
}

func extractJSONStrings(data []byte, lineDelimited bool) (values, fields, warnings []string) {
	decode := func(raw []byte) {
		var value any
		if err := jsonUnmarshal(raw, &value); err != nil {
			warnings = append(warnings, err.Error())
			return
		}
		walkJSON(value, &values, &fields)
	}
	if lineDelimited {
		scanner := bufio.NewScanner(bytes.NewReader(data))
		scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
		line := 0
		for scanner.Scan() {
			line++
			if strings.TrimSpace(scanner.Text()) == "" {
				continue
			}
			before := len(warnings)
			decode(scanner.Bytes())
			if len(warnings) > before {
				warnings[len(warnings)-1] = fmt.Sprintf("JSONL line %d: %s", line, warnings[len(warnings)-1])
			}
		}
		if err := scanner.Err(); err != nil {
			warnings = append(warnings, err.Error())
		}
	} else {
		decoder := json.NewDecoder(bytes.NewReader(data))
		valueNumber := 0
		for {
			var value any
			err := decoder.Decode(&value)
			if errors.Is(err, io.EOF) {
				break
			}
			valueNumber++
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("JSON value %d: %v", valueNumber, err))
				break
			}
			walkJSON(value, &values, &fields)
		}
	}
	return
}

// jsonUnmarshal is kept behind a small seam so scanner tests can exercise malformed input.
var jsonUnmarshal = func(data []byte, value any) error {
	return json.Unmarshal(data, value)
}

func walkJSON(value any, values, fields *[]string) {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			*fields = append(*fields, key)
			walkJSON(child, values, fields)
		}
	case []any:
		for _, child := range typed {
			walkJSON(child, values, fields)
		}
	case string:
		*values = append(*values, typed)
	case float64, bool, nil:
		// Numeric and boolean JSON values remain present in the raw JSON input.
	}
}

func sensitiveSQLFields(data string) []string {
	matches := piiFieldCandidatePattern.FindAllString(data, -1)
	return matches
}

func extractOffice(name, displayName string, data []byte) ([]extractedDocument, error) {
	reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, fmt.Errorf("open Office/OpenDocument package: %w", err)
	}
	var text strings.Builder
	var warnings []string
	for _, entry := range reader.File {
		if entry.FileInfo().IsDir() || !strings.HasSuffix(strings.ToLower(entry.Name), ".xml") {
			continue
		}
		if int64(entry.UncompressedSize64) > maxArchiveEntryBytes {
			warnings = append(warnings, fmt.Sprintf("skipped oversized package part %s", entry.Name))
			continue
		}
		file, err := entry.Open()
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("open package part %s: %v", entry.Name, err))
			continue
		}
		part, readErr := io.ReadAll(io.LimitReader(file, maxArchiveEntryBytes+1))
		_ = file.Close()
		if readErr != nil {
			warnings = append(warnings, fmt.Sprintf("read package part %s: %v", entry.Name, readErr))
			continue
		}
		if int64(len(part)) > maxArchiveEntryBytes {
			warnings = append(warnings, fmt.Sprintf("truncated package part %s", entry.Name))
			continue
		}
		partText, parseErr := extractXMLText(part)
		if parseErr != nil {
			warnings = append(warnings, fmt.Sprintf("parse package part %s: %v", entry.Name, parseErr))
			continue
		}
		if partText != "" {
			text.WriteString(partText)
			text.WriteByte('\n')
		}
	}
	return []extractedDocument{{Name: displayName, Format: formatName(name), Texts: []string{text.String()}, Warnings: warnings}}, nil
}

func extractXMLText(data []byte) (string, error) {
	decoder := xml.NewDecoder(bytes.NewReader(data))
	var out strings.Builder
	var stack []string
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			return strings.TrimSpace(out.String()), nil
		}
		if err != nil {
			return "", err
		}
		switch typed := token.(type) {
		case xml.StartElement:
			stack = append(stack, strings.ToLower(typed.Name.Local))
		case xml.CharData:
			out.Write([]byte(typed))
		case xml.EndElement:
			local := strings.ToLower(typed.Name.Local)
			if local == "p" || local == "para" || local == "c" || local == "cell" || local == "tr" || local == "row" || local == "si" {
				out.WriteByte('\n')
			}
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
		}
	}
}

func extractZip(name, displayName string, data []byte, depth, remainingDepth int) ([]extractedDocument, error) {
	if remainingDepth <= 0 {
		return []extractedDocument{{Name: displayName, Format: "ZIP archive", Warnings: []string{"archive nesting limit reached"}}}, nil
	}
	reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, fmt.Errorf("open ZIP archive: %w", err)
	}
	var docs []extractedDocument
	var total int64
	for _, entry := range reader.File {
		if entry.FileInfo().IsDir() {
			continue
		}
		if entry.UncompressedSize64 > uint64(maxArchiveEntryBytes) || total+int64(entry.UncompressedSize64) > maxArchiveBytes {
			continue
		}
		file, err := entry.Open()
		if err != nil {
			continue
		}
		entryData, readErr := io.ReadAll(io.LimitReader(file, maxArchiveEntryBytes+1))
		_ = file.Close()
		if readErr != nil || int64(len(entryData)) > maxArchiveEntryBytes {
			continue
		}
		total += int64(len(entryData))
		entryName := displayName + "::" + filepath.ToSlash(entry.Name)
		children, childErr := extractData(entry.Name, entryName, entryData, depth+1, remainingDepth-1)
		if childErr != nil {
			docs = append(docs, extractedDocument{Name: entryName, Format: formatName(entry.Name), Warnings: []string{childErr.Error()}})
			continue
		}
		docs = append(docs, children...)
	}
	if len(docs) == 0 {
		return []extractedDocument{{Name: displayName, Format: "ZIP archive"}}, nil
	}
	return docs, nil
}

func extractGzip(name, displayName string, data []byte, depth, remainingDepth int) ([]extractedDocument, error) {
	reader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	decompressed, err := io.ReadAll(io.LimitReader(reader, maxArchiveBytes+1))
	_ = reader.Close()
	if err != nil {
		return nil, err
	}
	if int64(len(decompressed)) > maxArchiveBytes {
		return []extractedDocument{{Name: displayName, Format: "gzip", Warnings: []string{"decompressed content exceeds safety limit"}}}, nil
	}
	lowerName := strings.ToLower(name)
	childName := name
	switch {
	case strings.HasSuffix(lowerName, ".tar.gz"):
		childName = name[:len(name)-len(".gz")]
	case strings.HasSuffix(lowerName, ".tgz"):
		childName = name[:len(name)-len(".tgz")]
	case strings.HasSuffix(lowerName, ".gz"):
		childName = name[:len(name)-len(".gz")]
	}
	return extractData(childName, displayName+"::"+childName, decompressed, depth+1, remainingDepth-1)
}

func extractTar(name, displayName string, data []byte, depth, remainingDepth int) ([]extractedDocument, error) {
	if remainingDepth <= 0 {
		return []extractedDocument{{Name: displayName, Format: "TAR archive", Warnings: []string{"archive nesting limit reached"}}}, nil
	}
	reader := tar.NewReader(bytes.NewReader(data))
	var docs []extractedDocument
	var total int64
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		if header.Typeflag != tar.TypeReg || header.Size < 0 || header.Size > maxArchiveEntryBytes || total+header.Size > maxArchiveBytes {
			continue
		}
		entryData, err := io.ReadAll(io.LimitReader(reader, maxArchiveEntryBytes+1))
		if err != nil || int64(len(entryData)) > maxArchiveEntryBytes {
			continue
		}
		total += int64(len(entryData))
		entryName := displayName + "::" + filepath.ToSlash(header.Name)
		children, childErr := extractData(header.Name, entryName, entryData, depth+1, remainingDepth-1)
		if childErr == nil {
			docs = append(docs, children...)
		}
	}
	return docs, nil
}

func extractPDF(name, displayName string, data []byte) ([]extractedDocument, error) {
	tmp, err := os.CreateTemp("", "piiscan-*.pdf")
	if err != nil {
		return nil, err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return nil, err
	}
	if err := tmp.Close(); err != nil {
		return nil, err
	}
	file, reader, err := pdf.Open(tmpName)
	if err != nil {
		return []extractedDocument{{Name: displayName, Format: formatName(name), Warnings: []string{fmt.Sprintf("PDF text extraction failed: %v", err)}}}, nil
	}
	defer file.Close()
	content, err := reader.GetPlainText()
	if err != nil {
		return []extractedDocument{{Name: displayName, Format: formatName(name), Warnings: []string{fmt.Sprintf("PDF text extraction failed: %v", err)}}}, nil
	}
	text, err := io.ReadAll(content)
	if err != nil {
		return nil, err
	}
	return []extractedDocument{{Name: displayName, Format: "PDF", Texts: []string{string(text)}}}, nil
}

func extractEmail(name, displayName string, data []byte) ([]extractedDocument, error) {
	message, err := mail.ReadMessage(bytes.NewReader(data))
	if err != nil {
		return []extractedDocument{{Name: displayName, Format: "email", Texts: []string{string(data)}, Warnings: []string{"MIME parse failed; scanned raw message"}}}, nil
	}
	body, err := io.ReadAll(io.LimitReader(message.Body, maxInputBytes))
	if err != nil {
		return nil, err
	}
	fields := []string{"From", "To", "Cc", "Reply-To"}
	var texts []string
	for _, key := range fields {
		if value := message.Header.Get(key); value != "" {
			texts = append(texts, value)
		}
	}
	texts = append(texts, string(body))
	return []extractedDocument{{Name: displayName, Format: "email", Texts: texts, Fields: fields}}, nil
}

func extractSQLite(path string) ([]extractedDocument, error) {
	dsn := (&url.URL{Scheme: "file", Path: path, RawQuery: "mode=ro&immutable=1"}).String()
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	rows, err := db.Query(`SELECT name FROM sqlite_schema WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("list SQLite tables: %w", err)
	}
	var tables []string
	for rows.Next() {
		var table string
		if err := rows.Scan(&table); err != nil {
			_ = rows.Close()
			return nil, err
		}
		tables = append(tables, table)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, err
	}
	_ = rows.Close()
	var docs []extractedDocument
	for _, table := range tables {
		doc, err := extractSQLiteTable(db, path, table)
		if err != nil {
			docs = append(docs, extractedDocument{Name: path + "::" + table, Format: "SQLite table", Warnings: []string{err.Error()}})
			continue
		}
		docs = append(docs, doc)
	}
	if len(docs) == 0 {
		docs = append(docs, extractedDocument{Name: path, Format: "SQLite database", Warnings: []string{"no user tables found"}})
	}
	return docs, nil
}

func extractSQLiteData(displayName string, data []byte) ([]extractedDocument, error) {
	tmp, err := os.CreateTemp("", "piiscan-*.sqlite")
	if err != nil {
		return nil, err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return nil, err
	}
	if err := tmp.Close(); err != nil {
		return nil, err
	}
	docs, err := extractSQLite(tmpPath)
	for i := range docs {
		if marker := strings.Index(docs[i].Name, "::"); marker >= 0 {
			docs[i].Name = displayName + docs[i].Name[marker:]
		} else {
			docs[i].Name = displayName
		}
	}
	return docs, err
}

func extractSQLiteTable(db *sql.DB, path, table string) (extractedDocument, error) {
	quoted := `"` + strings.ReplaceAll(table, `"`, `""`) + `"`
	rows, err := db.Query("SELECT * FROM " + quoted)
	if err != nil {
		return extractedDocument{}, err
	}
	defer rows.Close()
	columns, err := rows.Columns()
	if err != nil {
		return extractedDocument{}, err
	}
	var values []string
	var size int64
	for rows.Next() {
		cells := make([]any, len(columns))
		pointers := make([]any, len(columns))
		for i := range cells {
			pointers[i] = &cells[i]
		}
		if err := rows.Scan(pointers...); err != nil {
			return extractedDocument{}, err
		}
		for _, cell := range cells {
			value := fmt.Sprint(cell)
			if raw, ok := cell.([]byte); ok {
				value = string(raw)
			}
			if value == "<nil>" {
				continue
			}
			size += int64(len(value))
			if size > maxArchiveBytes {
				return extractedDocument{Name: path + "::" + table, Format: "SQLite table", Texts: values, Fields: columns, Warnings: []string{"table text truncated at safety limit"}}, nil
			}
			values = append(values, value)
		}
	}
	return extractedDocument{Name: path + "::" + table, Format: "SQLite table", Texts: values, Fields: columns}, rows.Err()
}

func isZip(data []byte) bool {
	return len(data) >= 4 && data[0] == 'P' && data[1] == 'K' &&
		((data[2] == 3 && data[3] == 4) || (data[2] == 5 && data[3] == 6) || (data[2] == 7 && data[3] == 8))
}

func isTextData(name string, data []byte) bool {
	if textExts[strings.ToLower(filepath.Ext(name))] {
		return true
	}
	limit := len(data)
	if limit > 512 {
		limit = 512
	}
	return !bytes.Contains(data[:limit], []byte{0}) && httpDetectContentType(data[:limit]) == "text"
}

var httpDetectContentType = func(data []byte) string {
	contentType := http.DetectContentType(data)
	if i := strings.IndexByte(contentType, ';'); i >= 0 {
		contentType = contentType[:i]
	}
	if strings.HasPrefix(contentType, "text/") {
		return "text"
	}
	return contentType
}

func isLegacyOffice(ext string) bool {
	return ext == ".doc" || ext == ".xls" || ext == ".ppt" || ext == ".msg"
}

func printableStrings(data []byte) []string {
	var values []string
	for _, match := range legacyPrintable.FindAll(data, -1) {
		values = append(values, string(match))
	}
	for i := 0; i+1 < len(data); i += 2 {
		if data[i+1] == 0 && data[i] >= 0x20 && data[i] < 0x7f {
			start := i
			for i+1 < len(data) && data[i+1] == 0 && data[i] >= 0x20 && data[i] < 0x7f {
				i += 2
			}
			if i-start >= 10 {
				var b strings.Builder
				for j := start; j < i; j += 2 {
					b.WriteByte(data[j])
				}
				values = append(values, b.String())
			}
		}
	}
	return values
}

func formatName(name string) string {
	ext := strings.ToLower(filepath.Ext(name))
	if ext == "" {
		return "text"
	}
	formats := map[string]string{
		".jsonl": "JSON Lines", ".ndjson": "JSON Lines", ".json": "JSON", ".sql": "SQL",
		".csv": "CSV", ".tsv": "TSV", ".xml": "XML", ".html": "HTML", ".htm": "HTML",
		".docx": "DOCX", ".xlsx": "XLSX", ".pptx": "PPTX", ".odt": "ODT", ".ods": "ODS", ".odp": "ODP",
		".rtf": "RTF", ".eml": "email", ".txt": "text", ".log": "log", ".yaml": "YAML", ".yml": "YAML",
	}
	if value := formats[ext]; value != "" {
		return value
	}
	return strings.TrimPrefix(strings.ToUpper(ext), ".") + " / text"
}
