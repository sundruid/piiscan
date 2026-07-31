package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestLargeSQLPathUsesStreaming(t *testing.T) {
	path := filepath.Join(t.TempDir(), "customer-export.sql")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(maxInputBytes + 1); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	stream, format, warnings, err := streamablePath(path)
	if err != nil {
		t.Fatal(err)
	}
	if !stream || format != "SQL" || len(warnings) != 0 {
		t.Fatalf("large SQL routing = stream=%v format=%q warnings=%#v", stream, format, warnings)
	}
}

func TestStreamScannerFindsPIIAcrossChunkBoundary(t *testing.T) {
	prefix := bytes.Repeat([]byte("x"), streamChunkBytes-8)
	data := append(prefix, []byte("person@example.com and SSN 123-45-6789")...)
	finding, err := scanTextReader(bytes.NewReader(data), "boundary.sql", "SQL", 3)
	if err != nil {
		t.Fatal(err)
	}
	if !containsCategory(finding.Categories, "email address") || !containsCategory(finding.Categories, "US Social Security number") {
		t.Fatalf("boundary finding = %#v", finding)
	}
}

func TestMajorVendorPlainTextDumps(t *testing.T) {
	root := t.TempDir()
	fixtures := map[string]string{
		"mysql.sql":      "-- MySQL dump\nINSERT INTO `customers` VALUES (1,'mysql@example.com','123-45-6789');\n",
		"mariadb.sql":    "-- MariaDB dump\nINSERT INTO `customers` VALUES (1,'maria@example.com','234-56-7890');\n",
		"postgresql.sql": "-- PostgreSQL database dump\nCOPY public.customers (email, ssn) FROM stdin;\npostgres@example.com\\t345-67-8901\n\\.\n",
		"sqlserver.sql":  "-- Microsoft SQL Server generated script\nINSERT [dbo].[Customers] ([Email],[SSN]) VALUES (N'sqlserver@example.com',N'456-78-9012');\nGO\n",
		"oracle.sql":     "-- Oracle SQL export\nInsert into CUSTOMERS (EMAIL,SSN) values ('oracle@example.com','567-89-0123');\nCOMMIT;\n",
	}
	for name, contents := range fixtures {
		if err := os.WriteFile(filepath.Join(root, name), []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	report, err := scanRoot(root, scanOptions{Workers: 2, MinConfidence: 40, MaxSamples: 3})
	if err != nil {
		t.Fatal(err)
	}
	if report.Stats.Suspected != len(fixtures) || report.Stats.Warnings != 0 {
		t.Fatalf("vendor dump report stats = %#v", report.Stats)
	}
	for _, finding := range report.Findings {
		if finding.Format != "SQL" || !containsCategory(finding.Categories, "email address") {
			t.Fatalf("vendor dump finding = %#v", finding)
		}
	}
}

func TestConcatenatedJSONStreamsWithoutWarning(t *testing.T) {
	data := strings.NewReader("{\"email\":\"one@example.com\",\"birthday\":\"1984-07-12\"}\n{\"email\":\"two@example.com\"}\n")
	finding, err := scanTextReader(data, "records.json", "JSON", 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(finding.Warnings) != 0 || !containsCategory(finding.Categories, "email address") || !containsCategory(finding.Categories, "date of birth field") || !containsCategory(finding.Categories, "possible birthdate") {
		t.Fatalf("concatenated JSON finding = %#v", finding)
	}
}

func TestProprietaryBackupGetsBestEffortStreaming(t *testing.T) {
	path := filepath.Join(t.TempDir(), "database.bak")
	if err := os.WriteFile(path, []byte{'B', 0, 'A', 0, 'K'}, 0o600); err != nil {
		t.Fatal(err)
	}
	stream, format, warnings, err := streamablePath(path)
	if err != nil {
		t.Fatal(err)
	}
	if !stream || format != "database backup (best effort)" || len(warnings) != 1 {
		t.Fatalf("backup routing = stream=%v format=%q warnings=%#v", stream, format, warnings)
	}
}

func TestSparseContentMatchesAreRatedLow(t *testing.T) {
	var data strings.Builder
	for line := 0; line < 1500; line++ {
		if line < 22 {
			data.WriteString("contact")
			data.WriteString(strconv.Itoa(line))
			data.WriteString("@example.com\n")
		} else {
			data.WriteString("ordinary non-sensitive record\n")
		}
	}
	finding, err := scanTextReader(strings.NewReader(data.String()), "sparse.txt", "text", 3)
	if err != nil {
		t.Fatal(err)
	}
	if finding.TotalLines != 1500 || finding.PIILines != 22 || finding.Score > 25 {
		t.Fatalf("sparse recurrence finding = %#v", finding)
	}
}

func TestDatabaseFieldOverridesSparseFileDensity(t *testing.T) {
	var data strings.Builder
	data.WriteString("CREATE TABLE private_customers (id bigint, dob date, mobile varchar(40), address varchar(255));\n")
	for line := 1; line < 1500; line++ {
		data.WriteString("INSERT INTO audit_log VALUES (1, 'ordinary event');\n")
	}
	finding, err := scanTextReader(strings.NewReader(data.String()), "database.sql", "SQL", 3)
	if err != nil {
		t.Fatal(err)
	}
	if finding.TotalLines != 1500 || finding.PIILines != 1 {
		t.Fatalf("database recurrence = %d/%d, want 1/1500", finding.PIILines, finding.TotalLines)
	}
	if !containsCategory(finding.Categories, "date of birth field") || !containsCategory(finding.Categories, "phone field") || !containsCategory(finding.Categories, "address field") {
		t.Fatalf("database fields = %#v", finding.Categories)
	}
	if finding.Score < 85 {
		t.Fatalf("schema-led score = %d, want at least 85", finding.Score)
	}
}

func TestStrongSecretOverridesSparseFileDensity(t *testing.T) {
	var data strings.Builder
	data.WriteString("api_key = A7kP3mQ9xT2vN8cR5jL4sW6z\n")
	for line := 1; line < 1500; line++ {
		data.WriteString("ordinary non-sensitive record\n")
	}
	finding, err := scanTextReader(strings.NewReader(data.String()), "settings.log", "log", 3)
	if err != nil {
		t.Fatal(err)
	}
	if finding.PIILines != 1 || finding.Score < 90 {
		t.Fatalf("sparse secret finding = %#v", finding)
	}
}

func containsCategory(categories []categorySummary, kind string) bool {
	for _, category := range categories {
		if category.Kind == kind {
			return true
		}
	}
	return false
}
