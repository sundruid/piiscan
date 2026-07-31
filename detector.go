package main

import (
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
)

type evidence struct {
	Kind       string
	Value      string
	Confidence int
}

type categorySummary struct {
	Kind       string
	Count      int
	Confidence int
}

type piiPattern struct {
	kind            string
	re              *regexp.Regexp
	capture         int
	confidence      int
	validate        func(string) bool
	digitBoundaries bool
}

var piiPatterns = []piiPattern{
	{
		kind:       "private key",
		re:         regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`),
		confidence: 99,
	},
	{
		kind:            "payment card",
		re:              regexp.MustCompile(`\b(?:[0-9][ -]?){12,18}[0-9]\b`),
		confidence:      96,
		validate:        validatePaymentCard,
		digitBoundaries: true,
	},
	{
		kind:            "US Social Security number",
		re:              regexp.MustCompile(`\b[0-9]{3}[- ]?[0-9]{2}[- ]?[0-9]{4}\b`),
		confidence:      94,
		validate:        validateSSN,
		digitBoundaries: true,
	},
	{
		kind:       "AWS access key",
		re:         regexp.MustCompile(`\b(?:AKIA|ASIA)[A-Z0-9]{16}\b`),
		confidence: 97,
	},
	{
		kind:       "IBAN",
		re:         regexp.MustCompile(`(?i)\b[A-Z]{2}[0-9]{2}(?:[ ]?[A-Z0-9]){11,30}\b`),
		confidence: 95,
		validate:   validateIBAN,
	},
	{
		kind:       "passport identifier",
		re:         regexp.MustCompile(`(?i)\bpassport(?:[ _-]*(?:number|no\.?|#))?[ ]*[:=#-]?[ ]*([A-Z0-9]{6,9})\b`),
		capture:    1,
		confidence: 92,
	},
	{
		kind:       "driver license identifier",
		re:         regexp.MustCompile(`(?i)\b(?:driver'?s?[ _-]*licen[cs]e|DL)(?:[ _-]*(?:number|no\.?|#))?[ ]*[:=#-]?[ ]*([A-Z0-9-]{5,16})\b`),
		capture:    1,
		confidence: 90,
	},
	{
		kind:       "email address",
		re:         regexp.MustCompile(`(?i)\b[a-z0-9.!#$%&'*+/=?^_{}|~-]+@[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+\b`),
		confidence: 84,
	},
	{
		kind:            "US/Canada phone number",
		re:              regexp.MustCompile(`(?:\+?1[ .-]?)?(?:\([2-9][0-9]{2}\)|[2-9][0-9]{2})[ .-]?[2-9][0-9]{2}[ .-]?[0-9]{4}(?:[ ]*(?:x|ext\.?)?[ ]*[0-9]{1,6})?`),
		confidence:      80,
		digitBoundaries: true,
	},
	{
		kind:            "international phone number",
		re:              regexp.MustCompile(`(?:\+|00)[2-9](?:[ .-]?[0-9]){7,14}(?:[ ]*(?:x|ext\.?)?[ ]*[0-9]{1,6})?`),
		confidence:      80,
		validate:        validateInternationalPhone,
		digitBoundaries: true,
	},
	{
		kind:       "possible birthdate",
		re:         regexp.MustCompile(`\b(?:[0-9]{1,2}[-/.][0-9]{1,2}[-/.](?:19|20)[0-9]{2}|(?:19|20)[0-9]{2}[-/.][0-9]{1,2}[-/.][0-9]{1,2})\b`),
		confidence: 65,
		validate:   validateDate,
	},
	{
		kind:       "postal address fragment",
		re:         regexp.MustCompile(`\b(?:[A-Z][a-z]{2,}(?:[ -]+[A-Z][a-z]{2,})*[ ,]+[A-Z]{2}[ ,]+[0-9]{5}(?:-[0-9]{4})?)\b`),
		confidence: 70,
	},
	{
		kind:       "IP address",
		re:         regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b`),
		confidence: 55,
	},
	{
		kind:       "MAC address",
		re:         regexp.MustCompile(`(?i)\b(?:[0-9A-F]{2}[:-]){5}[0-9A-F]{2}\b`),
		confidence: 55,
	},
	{
		kind:       "Bitcoin address",
		re:         regexp.MustCompile(`\b(?:bc1[ac-hj-np-z02-9]{11,71}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b`),
		confidence: 86,
	},
}

var sensitiveFieldPattern = regexp.MustCompile(`(?i)^(?:password|passwd|passphrase|secret|api[ _-]?key|auth[ _-]?token|access[ _-]?token|national[ _-]?id|social[ _-]?security(?:[ _-]?number)?|ssn|credit[ _-]?card(?:[ _-]?number)?|card[ _-]?number|date[ _-]?of[ _-]?birth|birth[ _-]?date|dob|passport(?:[ _-]?(?:number|no))?|driver'?s?[ _-]?licen[cs]e(?:[ _-]?(?:number|no))?)$`)

func detectPII(texts []string, fieldNames []string) []evidence {
	seen := make(map[string]struct{})
	var result []evidence

	for _, pattern := range piiPatterns {
		for _, text := range texts {
			for _, indexes := range pattern.re.FindAllStringSubmatchIndex(text, -1) {
				start, end := indexes[0], indexes[1]
				if pattern.capture > 0 {
					i := pattern.capture * 2
					if i+1 >= len(indexes) || indexes[i] < 0 {
						continue
					}
					start, end = indexes[i], indexes[i+1]
				}
				candidate := text[start:end]
				if pattern.digitBoundaries && hasAdjacentDigit(text, start, end) {
					continue
				}
				if pattern.validate != nil && !pattern.validate(candidate) {
					continue
				}
				addEvidence(&result, seen, evidence{Kind: pattern.kind, Value: candidate, Confidence: pattern.confidence})
			}
		}
	}

	for _, field := range fieldNames {
		trimmed := strings.TrimSpace(field)
		if sensitiveFieldPattern.MatchString(trimmed) {
			addEvidence(&result, seen, evidence{Kind: "sensitive field name", Value: trimmed, Confidence: 45})
		}
	}

	return result
}

func addEvidence(result *[]evidence, seen map[string]struct{}, item evidence) {
	key := item.Kind + "\x00" + strings.ToLower(item.Value)
	if _, ok := seen[key]; ok {
		return
	}
	seen[key] = struct{}{}
	*result = append(*result, item)
}

func hasAdjacentDigit(text string, start, end int) bool {
	return (start > 0 && text[start-1] >= '0' && text[start-1] <= '9') ||
		(end < len(text) && text[end] >= '0' && text[end] <= '9')
}

func summarizeEvidence(items []evidence) ([]categorySummary, int) {
	if len(items) == 0 {
		return nil, 0
	}

	byKind := make(map[string]*categorySummary)
	for _, item := range items {
		entry := byKind[item.Kind]
		if entry == nil {
			entry = &categorySummary{Kind: item.Kind, Confidence: item.Confidence}
			byKind[item.Kind] = entry
		}
		entry.Count++
		if item.Confidence > entry.Confidence {
			entry.Confidence = item.Confidence
		}
	}

	categories := make([]categorySummary, 0, len(byKind))
	for _, item := range byKind {
		categories = append(categories, *item)
	}
	sort.Slice(categories, func(i, j int) bool {
		if categories[i].Confidence != categories[j].Confidence {
			return categories[i].Confidence > categories[j].Confidence
		}
		return categories[i].Kind < categories[j].Kind
	})

	score := categories[0].Confidence
	if categories[0].Count > 1 {
		score += minInt(categories[0].Count-1, 3) * 2
	}
	score += minInt(len(categories)-1, 3) * 4
	if _, hasField := byKind["sensitive field name"]; hasField && len(categories) > 1 {
		score += 5
	}
	if score > 99 {
		score = 99
	}
	return categories, score
}

func validateSSN(value string) bool {
	digits := digitsOnly(value)
	if len(digits) != 9 {
		return false
	}
	area, _ := strconv.Atoi(digits[:3])
	return area != 0 && area != 666 && area < 900 && digits[3:5] != "00" && digits[5:] != "0000"
}

func validatePaymentCard(value string) bool {
	digits := digitsOnly(value)
	if len(digits) < 13 || len(digits) > 19 || !knownCardNetwork(digits) {
		return false
	}

	sum := 0
	alternate := false
	for i := len(digits) - 1; i >= 0; i-- {
		n := int(digits[i] - '0')
		if alternate {
			n *= 2
			if n > 9 {
				n -= 9
			}
		}
		sum += n
		alternate = !alternate
	}
	return sum%10 == 0
}

func knownCardNetwork(digits string) bool {
	length := len(digits)
	if digits[0] == '4' && (length == 13 || length == 16 || length == 19) {
		return true
	}
	if length == 15 && (strings.HasPrefix(digits, "34") || strings.HasPrefix(digits, "37")) {
		return true
	}
	if length == 16 {
		firstTwo, _ := strconv.Atoi(digits[:2])
		firstFour, _ := strconv.Atoi(digits[:4])
		firstSix, _ := strconv.Atoi(digits[:6])
		if firstTwo >= 51 && firstTwo <= 55 || firstFour >= 2221 && firstFour <= 2720 {
			return true
		}
		if strings.HasPrefix(digits, "6011") || firstTwo == 65 || firstFour >= 6440 && firstFour <= 6499 || firstSix >= 622126 && firstSix <= 622925 {
			return true
		}
		if firstFour >= 3528 && firstFour <= 3589 {
			return true
		}
	}
	if length >= 17 && length <= 19 && digits[0] == '4' {
		return true
	}
	return false
}

func validateInternationalPhone(value string) bool {
	digits := digitsOnly(value)
	return len(digits) >= 8 && len(digits) <= 15
}

func validateDate(value string) bool {
	layouts := []string{"1/2/2006", "1-2-2006", "1.2.2006", "2006/1/2", "2006-1-2", "2006.1.2"}
	for _, layout := range layouts {
		parsed, err := time.Parse(layout, value)
		if err == nil && parsed.Year() >= 1900 && !parsed.After(time.Now()) {
			return true
		}
	}
	return false
}

func validateIBAN(value string) bool {
	compact := strings.ToUpper(strings.ReplaceAll(value, " ", ""))
	if len(compact) < 15 || len(compact) > 34 {
		return false
	}
	rearranged := compact[4:] + compact[:4]
	remainder := 0
	for _, r := range rearranged {
		switch {
		case r >= '0' && r <= '9':
			remainder = (remainder*10 + int(r-'0')) % 97
		case r >= 'A' && r <= 'Z':
			value := int(r-'A') + 10
			remainder = (remainder*100 + value) % 97
		default:
			return false
		}
	}
	return remainder == 1
}

func digitsOnly(value string) string {
	var b strings.Builder
	for _, r := range value {
		if unicode.IsDigit(r) && r <= unicode.MaxASCII {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func redactEvidence(item evidence) string {
	value := item.Value
	switch item.Kind {
	case "email address":
		parts := strings.SplitN(value, "@", 2)
		if len(parts) == 2 && len(parts[0]) > 0 {
			return parts[0][:1] + "***@" + parts[1]
		}
	case "payment card", "US Social Security number", "US/Canada phone number", "international phone number":
		digits := digitsOnly(value)
		if len(digits) > 4 {
			return strings.Repeat("*", len(digits)-4) + digits[len(digits)-4:]
		}
	case "IP address":
		parts := strings.Split(value, ".")
		if len(parts) == 4 {
			return strings.Join(parts[:3], ".") + ".*"
		}
	}
	if len(value) <= 4 {
		return strings.Repeat("*", len(value))
	}
	return value[:2] + strings.Repeat("*", minInt(len(value)-4, 12)) + value[len(value)-2:]
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
