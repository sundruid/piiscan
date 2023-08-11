package main

import (
	"flag"
	"fmt"
	"github.com/h2non/filetype"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

var regexes = map[string]*regexp.Regexp{
	"full name":               regexp.MustCompile(`\b[A-Z][a-z]{1,25}[\s\t,][A-Z][a-z]{1,25}\b`),
	"US address":              regexp.MustCompile(`\b\d{1,5}[\s\t,][A-Z][a-z]{0,25}[\s\t,][A-Z][a-z]{0,25}\b`),
	"city/state/zip":          regexp.MustCompile(`\b[A-Z][a-z]{2,15}[\s\t,][A-Z]{2}[\s\t,]\d{5}\b`),
	"internationalPhoneRegex": regexp.MustCompile(`(\+\d{1,4}[-.\s]?)(\(?\d{1,3}?\)?[-.\s]?)?\d{1,4}[-.\s]?\d{1,4}([-.\s]?\d{1,4})?`),
	"domesticPhoneRegex":      regexp.MustCompile(`^(\(?\d{3}?\)?[-.\s]?)?\d{3}[-.\s]?\d{4}$`),
	"public IP":               regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`),
	"birthdate":               regexp.MustCompile(fmt.Sprintf(`\b\d{1,2}[-.\s]\d{1,2}[-.\s](?:19\d{2}|[2-%d]\d{2})\b`, time.Now().Year()-18)),
	"national/SSN ID":         regexp.MustCompile(`\b\d{3}[-.\s]\d{2}[-.\s]\d{4}\b`),
	"EU address":              regexp.MustCompile(`\b[A-Z][a-z]{0,25}[\s\t,]\d{1,5}[\s\t,]\d{4,6}[\s\t,][A-Z][a-z]{2,15}\b`),
	"Hebrew detected":         regexp.MustCompile(`[\x{0590}-\x{05FF}]+`),
	"Hindi detected":          regexp.MustCompile(`[\x{0900}-\x{097F}]+`),
}

func isTextFile(file string) bool {
	buf, err := ioutil.ReadFile(file)
	if err != nil {
		return false
	}

	// Directly check for known text types
	kind, err := filetype.Match(buf)
	if err == nil && strings.Contains(kind.MIME.Value, "text") {
		return true
	}

	// Heuristic check: if unrecognized, let's see if we have a high percentage of printable characters
	printableChars := 0
	for _, b := range buf {
		if (b >= 32 && b <= 126) || b == 9 || b == 10 || b == 13 { // ASCII printable characters + tab + CR + LF
			printableChars++
		}
	}

	return float64(printableChars)/float64(len(buf)) > 0.95
}

func scanFile(file string) {
	data, err := ioutil.ReadFile(file)
	if err != nil {
		fmt.Printf("Error reading file %s: %s\n", file, err)
		return
	}

	foundData := false

	for typeName, re := range regexes {
		matches := re.FindAll(data, -1)
		if len(matches) > 3 {
			if !foundData {
				fmt.Println(file)
				foundData = true
			}
			fmt.Printf("  Found %s: %s...\n", typeName, string(matches[0]))
		}
	}
}

func main() {
	filesystem := flag.String("filesystem", "", "The root of the filesystem to scan")
	flag.Parse()

	if *filesystem == "" {
		fmt.Println("Please specify a -filesystem to scan.")
		return
	}

	filepath.Walk(*filesystem, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			fmt.Printf("Error accessing path %s: %s\n", path, err)
			return nil
		}

		if info.IsDir() {
			return nil
		}

		if isTextFile(path) {
			scanFile(path)
		}

		return nil
	})
}
