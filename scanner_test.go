package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestScanRootProducesDeterministicFileCentricResults(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "a.json"), []byte(`{"email":"person@example.com"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "b.txt"), []byte("no sensitive content"), 0o600); err != nil {
		t.Fatal(err)
	}
	report, err := scanRoot(root, scanOptions{Workers: 2, MinConfidence: 40, MaxSamples: 3})
	if err != nil {
		t.Fatal(err)
	}
	if report.Stats.PhysicalFiles != 2 || report.Stats.Suspected != 1 || len(report.Findings) != 1 {
		t.Fatalf("unexpected report: %#v", report)
	}
	if !strings.HasSuffix(report.Findings[0].Name, "a.json") || report.Findings[0].Score < 80 {
		t.Fatalf("unexpected finding: %#v", report.Findings[0])
	}
	var output bytes.Buffer
	printConsoleReport(&output, report, false, 3)
	if strings.Contains(output.String(), "person@example.com") || !strings.Contains(output.String(), "email address") {
		t.Fatalf("console report leaked or omitted expected content: %s", output.String())
	}
}

func TestRunWritesDOCX(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "data.txt"), []byte("SSN 123-45-6789"), 0o600); err != nil {
		t.Fatal(err)
	}
	reportPath := filepath.Join(root, "report.docx")
	var stdout, stderr bytes.Buffer
	code := run([]string{"-filesystem", root, "-report", reportPath}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run returned %d, stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
	info, err := os.Stat(reportPath)
	if err != nil || info.Size() < 1000 {
		t.Fatalf("report was not written: info=%v", err)
	}
}
