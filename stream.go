package main

import (
	"bufio"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

const (
	streamChunkBytes         = 4 << 20
	streamOverlapBytes       = 4 << 10
	maxTrackedEvidenceHashes = 250_000
)

var (
	databaseDumpExts = map[string]bool{
		".bak": true, ".bkp": true, ".dmp": true, ".dump": true,
	}
	jsonFieldNamePattern = regexp.MustCompile(`"((?:\\.|[^"\\]){1,256})"[[:space:]]*:`)
)

type findingAccumulator struct {
	categories map[string]*categorySummary
	evidence   []evidence
	limited    bool
	maxSamples int
	seen       map[[32]byte]struct{}
}

func newFindingAccumulator(maxSamples int) *findingAccumulator {
	if maxSamples < 1 {
		maxSamples = defaultMaxSamples
	}
	return &findingAccumulator{
		categories: make(map[string]*categorySummary),
		maxSamples: maxSamples,
		seen:       make(map[[32]byte]struct{}),
	}
}

func (accumulator *findingAccumulator) add(items []evidence) {
	for _, item := range items {
		digest := sha256.Sum256([]byte(item.Kind + "\x00" + strings.ToLower(item.Value)))
		if _, exists := accumulator.seen[digest]; exists {
			continue
		}
		if len(accumulator.seen) < maxTrackedEvidenceHashes {
			accumulator.seen[digest] = struct{}{}
		} else {
			accumulator.limited = true
		}
		category := accumulator.categories[item.Kind]
		if category == nil {
			category = &categorySummary{Kind: item.Kind, Confidence: item.Confidence}
			accumulator.categories[item.Kind] = category
		}
		category.Count++
		if item.Confidence > category.Confidence {
			category.Confidence = item.Confidence
		}
		if len(accumulator.evidence) < accumulator.maxSamples {
			accumulator.evidence = append(accumulator.evidence, item)
		}
	}
}

func (accumulator *findingAccumulator) result() ([]categorySummary, []evidence, int) {
	categories := make([]categorySummary, 0, len(accumulator.categories))
	for _, category := range accumulator.categories {
		categories = append(categories, *category)
	}
	sortCategorySummaries(categories)
	return categories, accumulator.evidence, scoreCategorySummaries(categories)
}

func scanFile(path string, options scanOptions) []scanFinding {
	stream, format, warnings, err := streamablePath(path)
	if err != nil {
		return []scanFinding{{Name: path, Format: formatName(path), Warnings: []string{err.Error()}}}
	}
	if stream {
		finding, scanErr := scanStreamPath(path, format, warnings, options.MaxSamples)
		if scanErr != nil {
			finding.Warnings = append(finding.Warnings, scanErr.Error())
		}
		if finding.Score < options.MinConfidence && len(finding.Warnings) == 0 {
			return nil
		}
		return []scanFinding{finding}
	}

	documents, extractErr := extractPath(path)
	if extractErr != nil {
		return []scanFinding{{Name: path, Format: formatName(path), Warnings: []string{extractErr.Error()}}}
	}
	findings := make([]scanFinding, 0, len(documents))
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
	return findings
}

func streamablePath(path string) (stream bool, format string, warnings []string, err error) {
	ext := strings.ToLower(filepath.Ext(path))
	if textExts[ext] {
		return true, formatName(path), nil, nil
	}

	file, err := os.Open(path)
	if err != nil {
		return false, "", nil, err
	}
	defer file.Close()
	header := make([]byte, 512)
	count, readErr := file.Read(header)
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return false, "", nil, readErr
	}
	header = header[:count]
	if isTextData(path, header) {
		return true, formatName(path), nil, nil
	}
	if databaseDumpExts[ext] {
		warning := "proprietary database backup scanned for readable text; compressed, encrypted, and vendor-encoded records may require the vendor restore tool"
		return true, "database backup (best effort)", []string{warning}, nil
	}
	return false, "", nil, nil
}

func scanStreamPath(path, format string, warnings []string, maxSamples int) (scanFinding, error) {
	file, err := os.Open(path)
	if err != nil {
		return scanFinding{Name: path, Format: format, Warnings: warnings}, err
	}
	defer file.Close()
	finding, err := scanTextReader(file, path, format, maxSamples)
	finding.Warnings = append(finding.Warnings, warnings...)
	return finding, err
}

func scanTextReader(reader io.Reader, name, format string, maxSamples int) (scanFinding, error) {
	accumulator := newFindingAccumulator(maxSamples)
	buffered := bufio.NewReaderSize(reader, streamChunkBytes)
	ext := strings.ToLower(filepath.Ext(name))
	tail := ""
	lineMatched := false
	totalLines := 0
	piiLines := 0
	for {
		fragment, readErr := buffered.ReadSlice('\n')
		if len(fragment) > 0 {
			window := tail + string(fragment)
			fields := structuredFieldNames(window, ext)
			items := detectPII([]string{window}, fields)
			if strings.Contains(window, obfuscationUUID) {
				items = append(items, evidence{Kind: "obfuscation marker", Value: obfuscationUUID, Confidence: 92})
			}
			if len(items) > 0 {
				lineMatched = true
			}
			accumulator.add(items)
			if len(window) > streamOverlapBytes {
				tail = window[len(window)-streamOverlapBytes:]
			} else {
				tail = window
			}
		}
		if errors.Is(readErr, bufio.ErrBufferFull) {
			continue
		}
		if len(fragment) > 0 {
			totalLines++
			if lineMatched {
				piiLines++
			}
			lineMatched = false
			tail = ""
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			categories, samples, score := accumulator.result()
			finding := scanFinding{Name: name, Format: format, Categories: categories, Evidence: samples, Score: score, TotalLines: totalLines, PIILines: piiLines}
			finding.Score = scoreWithLineRecurrence(finding)
			appendDeduplicationWarning(&finding, accumulator)
			return finding, fmt.Errorf("read stopped after partial scan: %w", readErr)
		}
	}
	categories, samples, score := accumulator.result()
	finding := scanFinding{Name: name, Format: format, Categories: categories, Evidence: samples, Score: score, TotalLines: totalLines, PIILines: piiLines}
	finding.Score = scoreWithLineRecurrence(finding)
	appendDeduplicationWarning(&finding, accumulator)
	return finding, nil
}

func scoreWithLineRecurrence(finding scanFinding) int {
	if finding.Score == 0 || finding.TotalLines < 100 || hasSchemaOrSecretEvidence(finding.Categories) {
		return finding.Score
	}
	density := finding.lineDensity()
	cap := finding.Score
	switch {
	case density < 0.02:
		cap = 25
	case density < 0.05:
		cap = 45
	case density < 0.10:
		cap = 60
	case density < 0.20:
		cap = 75
	}
	if finding.Score < cap {
		return finding.Score
	}
	return cap
}

func hasSchemaOrSecretEvidence(categories []categorySummary) bool {
	for _, category := range categories {
		if strings.HasSuffix(category.Kind, " field") {
			return true
		}
		switch category.Kind {
		case "private key", "AWS access key", "high-entropy key candidate":
			return true
		}
	}
	return false
}

func appendDeduplicationWarning(finding *scanFinding, accumulator *findingAccumulator) {
	if accumulator.limited {
		finding.Warnings = append(finding.Warnings, "unique-value tracking limit reached; scanning continued and later category counts may include repeated values")
	}
}

func structuredFieldNames(text, extension string) []string {
	switch extension {
	case ".sql":
		return sensitiveSQLFields(text)
	case ".json", ".jsonl", ".ndjson":
		return jsonFieldNames(text)
	default:
		return nil
	}
}

func jsonFieldNames(data string) []string {
	matches := jsonFieldNamePattern.FindAllStringSubmatch(data, -1)
	fields := make([]string, 0, len(matches))
	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		value, err := strconv.Unquote(`"` + match[1] + `"`)
		if err == nil {
			fields = append(fields, value)
		}
	}
	return fields
}
