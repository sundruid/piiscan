package main

import (
	"bufio"
	"io"
	"math"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

var regexes = map[string]*regexp.Regexp{}

func init() {
	// Initialize regular expressions inside init function
	regexes = map[string]*regexp.Regexp{
		//"US address":            regexp.MustCompile(`\b\d{1,5}[\s\t,][A-Z][a-z]{0,25}[\s\t,][A-Z][a-z]{0,25}\b`),
		//"EU address":            regexp.MustCompile(`\b[\w\s]+(?:\d[\w\s]*)?,\s[\w\s]+\b`),
		"email address":           regexp.MustCompile(`\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b`),
		"city/state/zip":          regexp.MustCompile(`\b[A-Z][a-z]{2,15}[\s\t,][A-Z]{2}[\s\t,]\d{5}\b`),
		"international phone":     regexp.MustCompile(`\+\d{9,14}`),
		"domestic phone":          regexp.MustCompile(`\b([2-9]\d{2}[-.\s]?)\d{3}[-.\s]?\d{4}\b`),
		"possible birthdate":      regexp.MustCompile(fmt.Sprintf(`\b\d{1,2}[-.\s]\d{1,2}[-.\s](?:19\d{2}|[2-%d]\d{3})\b`, time.Now().Year()-18)),
		"national/ssn id":         regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`),
		"MC detected":             regexp.MustCompile(`\b(?:5[1-5][0-9]{2}|222[1-9]|22[3-9][0-9]|2[3-6][0-9]{2}|27[01][0-9]|2720)[0-9]{12}\b`),
		"VISA detected":           regexp.MustCompile(`\b([4]\d{3}[\s]\d{4}[\s]\d{4}[\s]\d{4}|[4]\d{3}[-]\d{4}[-]\d{4}[-]\d{4}|[4]\d{3}[.]\d{4}[.]\d{4}[.]\d{4}|[4]\d{3}\d{4}\d{4}\d{4})\b`),
		"AMEX detected":           regexp.MustCompile(`\b3[47][0-9]{13}\b`),
		"sensitive_json_label":    regexp.MustCompile(`\b(nationalID|SSN)\b`),
		"sensitive_sql_column":    regexp.MustCompile(`\b(nationalID|SSN)\b`),

		// TLS private key regex
		"TLS private key": regexp.MustCompile(`(?s).*?-----BEGIN (RSA PRIVATE|EC PRIVATE|PRIVATE) KEY-----.*?-----END (RSA PRIVATE|EC PRIVATE|PRIVATE) KEY-----`),

	}
}

func isTextFile(file string) bool {
    f, err := os.Open(file)
    if err != nil {
        return false
    }
    defer f.Close()

    fileInfo, err := f.Stat()
    if err != nil {
        return false
    }

    // Get the size of the file and adjust the buffer size accordingly
    fileSize := fileInfo.Size()
    bufferSize := int(math.Min(float64(fileSize), 512))

    buf := make([]byte, bufferSize)
    _, err = f.Read(buf)
    if err != nil && err != io.EOF {
        return false
    }

    contentType := http.DetectContentType(buf)
    return strings.HasPrefix(contentType, "text")
}


func isSQL(file string) bool {
	return strings.HasSuffix(file, ".sql")
}

func isJSON(file string) bool {
	return strings.HasSuffix(file, ".json")
}

func isMySQLDump(file string) bool {
	// Check for .sql file extension
	if !strings.HasSuffix(file, ".sql") {
		return false
	}

	// Open the file to read its contents
	f, err := os.Open(file)
	if err != nil {
		fmt.Printf("Error opening file %s: %s\n", file, err)
		return false
	}
	defer f.Close()

	// Scan the first few lines of the file
	scanner := bufio.NewScanner(f)
	lineCount := 0
	for scanner.Scan() {
		line := scanner.Text()
		// Check for MySQL dump header patterns
		if strings.Contains(line, "-- MySQL dump") || strings.Contains(line, "Server version") {
			return true
		}
		// Limit the check to the first few lines to avoid extensive reading
		lineCount++
		if lineCount > 10 {
			break
		}
	}

	return false
}

func scanJSONFile(file string) {
	data, err := os.ReadFile(file)
	if err != nil {
		fmt.Printf("Error reading JSON file %s: %s\n", file, err)
		return
	}

	const maxSamplesPerType = 5

	// Determine if the file is in JSONL format
	isJSONL := strings.Contains(string(data), "\n") && !strings.HasPrefix(string(data), "[")

	// Process file based on its format
	if isJSONL {
		// Process each line as a separate JSON object
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			processJSONLine(line, maxSamplesPerType)
		}
	} else {
		// Process the entire file as a single JSON object or array
		processJSONLine(string(data), maxSamplesPerType)
	}
}

func processJSONLine(line string, maxSamplesPerType int) {
	var result map[string]interface{}
	if err := json.Unmarshal([]byte(line), &result); err != nil {
		// Skip this line if there's an error
		return
	}

	var matches []string
	var scanJSON func(map[string]interface{})
	scanJSON = func(m map[string]interface{}) {
		for k, v := range m {
			if regexes["sensitive_json_label"].MatchString(k) {
				match := fmt.Sprintf("%s: %v", k, v)
				matches = append(matches, match)
			}
			switch vv := v.(type) {
			case map[string]interface{}:
				scanJSON(vv)
			case []interface{}:
				for _, u := range vv {
					if um, ok := u.(map[string]interface{}); ok {
						scanJSON(um)
					}
				}
			}
		}
	}

	scanJSON(result)

	if len(matches) > 0 {
		fmt.Println("Found instances of sensitive JSON labels. Sample matches:")
		for i, match := range matches {
			if i >= maxSamplesPerType {
				break
			}
			fmt.Printf("  Match %d: %s\n", i+1, match)
		}
	}
}

func scanSQLFile(file string) {
	data, err := os.ReadFile(file)
	if err != nil {
		fmt.Printf("Error reading SQL file %s: %s\n", file, err)
		return
	}

	const maxSamplesPerType = 5

	sensitiveSqlColumnRegex, exists := regexes["sensitive_sql_column"]
	if !exists || sensitiveSqlColumnRegex == nil {
		fmt.Println("Regex for sensitive SQL columns is not initialized")
		return
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		matches := sensitiveSqlColumnRegex.FindAllStringIndex(line, -1)
		for _, match := range matches {
			start := match[1]
			end := findValueEnd(line, start)
			if end > start {
				value := line[start:end]
				fmt.Printf("Found sensitive data: %s\n", value)
			}
		}
	}
}

func findValueEnd(line string, start int) int {
	inQuotes := false
	for i := start; i < len(line); i++ {
		if line[i] == '\'' {
			inQuotes = !inQuotes
		} else if line[i] == ',' && !inQuotes {
			return i
		} else if line[i] == ')' && !inQuotes {
			return i
		}
	}
	return len(line)
}

func scanTextFile(file string) {
	data, err := os.ReadFile(file)
	if err != nil {
		fmt.Printf("Error reading file %s: %s\n", file, err)
		return
	}

	const maxSamplesPerType = 5 // Maximum number of samples to print per pattern

	fmt.Println("Scanning as a text file")

	for typeName, re := range regexes {
		matches := re.FindAllString(string(data), -1)
		if len(matches) > 0 {
			fmt.Printf("In file %s, found %d instances of %s. Sample matches:\n", file, len(matches), typeName)
			for i, match := range matches {
				if i >= maxSamplesPerType {
					break // Limit the number of samples printed
				}
				fmt.Printf("  Match %d: %s\n", i+1, match)
			}
		}
	}
}

func scanFile(file string) {
	if isMySQLDump(file) {
		scanMySQLDumpFile(file)
	} else if isJSON(file) {
		scanJSONFile(file)
	} else if isSQL(file) {
		scanSQLFile(file)
	} else if isTextFile(file) {
		scanTextFile(file)
	}

	// Check for obfuscation tag after scanning the file
	if checkForObfuscationTag(file) {
		fmt.Println("OBFUSCATION TAG FOUND ec4919e3-1fe2-4808-ab5b-4b323d6ce23a")
	}
}

func scanMySQLDumpFile(file string) {
	const maxSamplesPerType = 5

	data, err := os.ReadFile(file)
	if err != nil {
		fmt.Printf("Error reading MySQL dump file %s: %s\n", file, err)
		return
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		for typeName, re := range regexes {
			matches := re.FindAllString(line, -1)
			if len(matches) > 0 {
				fmt.Printf("In MySQL dump file %s, found instances of %s. Sample matches:\n", file, typeName)
				for i, match := range matches {
					if i >= maxSamplesPerType {
						break
					}
					fmt.Printf("  Match %d: %s\n", i+1, match)
				}
			}
		}
	}
}

func checkForObfuscationTag(file string) bool {
	const obfuscationUUID = "ec4919e3-1fe2-4808-ab5b-4b323d6ce23a"

	data, err := os.ReadFile(file)
	if err != nil {
		fmt.Printf("Error reading file %s: %s\n", file, err)
		return false
	}

	return strings.Contains(string(data), obfuscationUUID)
}

func main() {

	fmt.Println("pii_scanner v.3 maintained by kenneth.webster@imperva.com")

	filesystem := flag.String("filesystem", "", "The root of the filesystem to scan")
	flag.Parse()

	if *filesystem == "" {
		fmt.Println("Please specify a -filesystem to scan.")
		return
	}

	var wg sync.WaitGroup
	err := filepath.WalkDir(*filesystem, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			fmt.Printf("Error accessing path %s: %s\n", path, err)
			return nil
		}

		if d.IsDir() {
			return nil
		}

		wg.Add(1)
		go func(path string) {
			defer wg.Done()
			scanFile(path)
		}(path)

		return nil
	})
	if err != nil {
		fmt.Printf("Error walking the path %s: %s\n", *filesystem, err)
	}
	wg.Wait()
}
