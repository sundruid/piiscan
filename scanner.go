package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	version              = "5.0.0"
	obfuscationUUID      = "ec4919e3-1fe2-4808-ab5b-4b323d6ce23a"
	defaultReportName    = "piiscan-report.docx"
	defaultMaxSamples    = 3
	defaultMinConfidence = 40
)

type scanOptions struct {
	Workers         int
	MinConfidence   int
	MaxSamples      int
	IncludeEvidence bool
	ExcludePath     string
}

type scanFinding struct {
	Name       string
	Format     string
	Categories []categorySummary
	Evidence   []evidence
	Score      int
	Warnings   []string
}

type scanStats struct {
	PhysicalFiles int
	LogicalFiles  int
	Suspected     int
	Warnings      int
	Started       time.Time
	Finished      time.Time
}

type scanReport struct {
	Root     string
	Findings []scanFinding
	Stats    scanStats
}

func scanRoot(root string, options scanOptions) (scanReport, error) {
	if options.Workers < 1 {
		options.Workers = runtime.GOMAXPROCS(0)
	}
	if options.MaxSamples < 1 {
		options.MaxSamples = defaultMaxSamples
	}
	if options.MinConfidence < 0 {
		options.MinConfidence = 0
	}
	if options.MinConfidence > 99 {
		options.MinConfidence = 99
	}
	root, err := filepath.Abs(root)
	if err != nil {
		return scanReport{}, err
	}
	info, err := os.Stat(root)
	if err != nil {
		return scanReport{}, err
	}
	if !info.IsDir() {
		return scanReport{}, fmt.Errorf("filesystem path must be a directory")
	}

	options.ExcludePath, _ = filepath.Abs(options.ExcludePath)
	report := scanReport{Root: root, Stats: scanStats{Started: time.Now().UTC()}}
	paths := make([]string, 0)
	err = filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			report.Stats.Warnings++
			return nil
		}
		if entry.IsDir() {
			return nil
		}
		absolute, absErr := filepath.Abs(path)
		if absErr == nil && options.ExcludePath != "" && samePath(absolute, options.ExcludePath) {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return nil
		}
		paths = append(paths, path)
		return nil
	})
	if err != nil {
		return report, err
	}
	report.Stats.PhysicalFiles = len(paths)

	jobs := make(chan string)
	results := make(chan []scanFinding)
	var wg sync.WaitGroup
	for i := 0; i < options.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for path := range jobs {
				documents, err := extractPath(path)
				if err != nil {
					results <- []scanFinding{{Name: path, Format: formatName(path), Warnings: []string{err.Error()}}}
					continue
				}
				var findings []scanFinding
				for _, document := range documents {
					if document.Name == "" {
						continue
					}
					items := detectPII(document.Texts, document.Fields)
					if hasObfuscation(document.Texts) {
						items = append(items, evidence{Kind: "obfuscation marker", Value: obfuscationUUID, Confidence: 92})
					}
					categories, score := summarizeEvidence(items)
					if score < options.MinConfidence && len(document.Warnings) == 0 {
						continue
					}
					findings = append(findings, scanFinding{Name: document.Name, Format: document.Format, Categories: categories, Evidence: items, Score: score, Warnings: document.Warnings})
				}
				results <- findings
			}
		}()
	}
	go func() {
		for _, path := range paths {
			jobs <- path
		}
		close(jobs)
		wg.Wait()
		close(results)
	}()
	for findings := range results {
		report.Findings = append(report.Findings, findings...)
	}
	report.Stats.Finished = time.Now().UTC()
	for _, finding := range report.Findings {
		report.Stats.LogicalFiles++
		if finding.Score >= options.MinConfidence {
			report.Stats.Suspected++
		}
		report.Stats.Warnings += len(finding.Warnings)
	}
	sort.Slice(report.Findings, func(i, j int) bool {
		if report.Findings[i].Score != report.Findings[j].Score {
			return report.Findings[i].Score > report.Findings[j].Score
		}
		return report.Findings[i].Name < report.Findings[j].Name
	})
	return report, nil
}

func hasObfuscation(texts []string) bool {
	for _, text := range texts {
		if strings.Contains(text, obfuscationUUID) {
			return true
		}
	}
	return false
}

func samePath(left, right string) bool {
	left, _ = filepath.Abs(left)
	right, _ = filepath.Abs(right)
	left = filepath.Clean(left)
	right = filepath.Clean(right)
	return left == right
}

func printConsoleReport(w io.Writer, report scanReport, includeEvidence bool, maxSamples int) {
	if maxSamples < 1 {
		maxSamples = defaultMaxSamples
	}
	fmt.Fprintf(w, "piiscan v%s\n", version)
	fmt.Fprintf(w, "Scanned %d physical files (%d logical documents) under %s.\n", report.Stats.PhysicalFiles, report.Stats.LogicalFiles, report.Root)
	fmt.Fprintf(w, "Suspected files: %d | warnings: %d\n", report.Stats.Suspected, report.Stats.Warnings)
	for _, finding := range report.Findings {
		if finding.Score == 0 && len(finding.Warnings) == 0 {
			continue
		}
		fmt.Fprintf(w, "[%d%%] %s (%s) - %s\n", finding.Score, finding.Name, finding.Format, categoryText(finding.Categories))
		if includeEvidence {
			printed := 0
			for _, item := range finding.Evidence {
				if printed >= maxSamples {
					break
				}
				fmt.Fprintf(w, "  evidence: %s = %s\n", item.Kind, redactEvidence(item))
				printed++
			}
		}
		for _, warning := range finding.Warnings {
			fmt.Fprintf(w, "  warning: %s\n", warning)
		}
	}
}

func categoryText(categories []categorySummary) string {
	parts := make([]string, 0, len(categories))
	for _, category := range categories {
		parts = append(parts, fmt.Sprintf("%s (%d)", category.Kind, category.Count))
	}
	if len(parts) == 0 {
		return "extractor warning; no detector evidence"
	}
	return strings.Join(parts, ", ")
}
