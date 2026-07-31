package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("piiscan", flag.ContinueOnError)
	flags.SetOutput(stderr)
	filesystem := flags.String("filesystem", "", "root directory to scan (required)")
	reportPath := flags.String("report", defaultReportName, "DOCX incident-response report path")
	workers := flags.Int("workers", runtime.GOMAXPROCS(0), "maximum concurrent file scanners")
	minConfidence := flags.Int("min-confidence", defaultMinConfidence, "minimum confidence score to include (0-99)")
	includeEvidence := flags.Bool("include-evidence", false, "include redacted evidence samples in console output and the DOCX report")
	maxSamples := flags.Int("max-samples", defaultMaxSamples, "maximum redacted evidence samples per finding")
	showVersion := flags.Bool("version", false, "print the scanner version")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *showVersion {
		fmt.Fprintf(stdout, "piiscan v%s\n", version)
		return 0
	}
	if *filesystem == "" {
		fmt.Fprintln(stderr, "-filesystem is required")
		flags.PrintDefaults()
		return 2
	}
	if *workers < 1 || *maxSamples < 1 || *minConfidence < 0 || *minConfidence > 99 {
		fmt.Fprintln(stderr, "workers and max-samples must be positive; min-confidence must be between 0 and 99")
		return 2
	}
	report, err := scanRoot(*filesystem, scanOptions{Workers: *workers, MinConfidence: *minConfidence, MaxSamples: *maxSamples, IncludeEvidence: *includeEvidence, ExcludePath: *reportPath})
	if err != nil {
		fmt.Fprintf(stderr, "scan failed: %v\n", err)
		return 1
	}
	printConsoleReport(stdout, report, *includeEvidence, *maxSamples)
	if err := writeDOCX(*reportPath, report, *includeEvidence, *maxSamples); err != nil {
		fmt.Fprintf(stderr, "write report %s: %v\n", *reportPath, err)
		return 1
	}
	fmt.Fprintf(stdout, "Report written to %s\n", *reportPath)
	return 0
}
