package main

import (
	"archive/zip"
	"bytes"
	"database/sql"
	"encoding/json"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

func TestExtractJSONAndJSONLValuesAndFields(t *testing.T) {
	data := []byte(`[{"profile":{"email":"person@example.com","ssn":"123-45-6789"}},{"creditCard":"4111 1111 1111 1111"}]`)
	doc := extractText("sample.json", "/tmp/sample.json", data)
	items := detectPII(doc.Texts, doc.Fields)
	if !containsKind(items, "email address") || !containsKind(items, "US Social Security number") || !containsKind(items, "payment card") {
		t.Fatalf("JSON values were not scanned: %#v", items)
	}
	if !containsKind(items, "payment card field") {
		t.Fatalf("JSON fields were not scanned: %#v", items)
	}

	jsonl := []byte("{\"email\":\"one@example.com\"}\n{\"email\":\"two@example.com\"}\n")
	values, fields, warnings := extractJSONStrings(jsonl, true)
	if len(warnings) != 0 || len(values) != 2 || len(fields) != 2 {
		t.Fatalf("JSONL extraction = values=%#v fields=%#v warnings=%#v", values, fields, warnings)
	}

	concatenated := []byte("{\"email\":\"one@example.com\"}\n{\"email\":\"two@example.com\"}\n")
	values, fields, warnings = extractJSONStrings(concatenated, false)
	if len(warnings) != 0 || len(values) != 2 || len(fields) != 2 {
		t.Fatalf("concatenated JSON extraction = values=%#v fields=%#v warnings=%#v", values, fields, warnings)
	}
}

func TestExtractOfficeXMLJoinsSplitRuns(t *testing.T) {
	var buffer bytes.Buffer
	archive := zip.NewWriter(&buffer)
	entry, err := archive.Create("word/document.xml")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = entry.Write([]byte(`<w:document xmlns:w="urn"><w:body><w:p><w:r><w:t>person@</w:t></w:r><w:r><w:t>example.com</w:t></w:r></w:p></w:body></w:document>`))
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	docs, err := extractOffice("sample.docx", "/tmp/sample.docx", buffer.Bytes())
	if err != nil || len(docs) != 1 {
		t.Fatalf("extractOffice error=%v docs=%#v", err, docs)
	}
	if !containsKind(detectPII(docs[0].Texts, nil), "email address") {
		t.Fatalf("split XML text was not joined: %#v", docs[0].Texts)
	}
}

func TestExtractSQLiteTable(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "records.sqlite")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE people (email TEXT, ssn TEXT); INSERT INTO people VALUES ('person@example.com', '123-45-6789')`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	docs, err := extractSQLite(dbPath)
	if err != nil || len(docs) != 1 {
		t.Fatalf("extractSQLite error=%v docs=%#v", err, docs)
	}
	items := detectPII(docs[0].Texts, docs[0].Fields)
	if !containsKind(items, "email address") || !containsKind(items, "US Social Security number") {
		t.Fatalf("SQLite values were not scanned: %#v", items)
	}
}

func TestExtractArchiveBounded(t *testing.T) {
	var buffer bytes.Buffer
	archive := zip.NewWriter(&buffer)
	entry, err := archive.Create("nested.txt")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = entry.Write([]byte("person@example.com"))
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	docs, err := extractZip("sample.zip", "/tmp/sample.zip", buffer.Bytes(), 0, maxArchiveDepth)
	if err != nil || len(docs) != 1 {
		t.Fatalf("extractZip error=%v docs=%#v", err, docs)
	}
	if !containsKind(detectPII(docs[0].Texts, docs[0].Fields), "email address") {
		t.Fatalf("archive entry was not scanned: %#v", docs)
	}
}

func TestJSONMarshalFixture(t *testing.T) {
	data, err := json.Marshal(map[string]string{"email": "person@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 {
		t.Fatal("empty JSON fixture")
	}
}
