package main

import (
	"strings"
	"testing"
)

func TestDetectPIIValidatedPatterns(t *testing.T) {
	tests := []struct {
		name   string
		text   string
		kind   string
		want   string
		absent string
	}{
		{name: "email", text: "Contact Jane.Doe+alerts@example.co.uk", kind: "email address", want: "Jane.Doe+alerts@example.co.uk"},
		{name: "ssn", text: "SSN: 123-45-6789", kind: "US Social Security number", want: "123-45-6789"},
		{name: "formatted visa", text: "Card: 4111 1111 1111 1111", kind: "payment card", want: "4111 1111 1111 1111"},
		{name: "international phone", text: "Call +44 20 7946 0958", kind: "international phone number", want: "+44 20 7946 0958"},
		{name: "birthdate", text: "DOB 2000-02-29", kind: "possible birthdate", want: "2000-02-29"},
		{name: "passport context", text: "passport number: X12345678", kind: "passport identifier", want: "X12345678"},
		{name: "aws key", text: "AKIAIOSFODNN7EXAMPLE", kind: "AWS access key", want: "AKIAIOSFODNN7EXAMPLE"},
		{name: "iban", text: "GB82 WEST 1234 5698 7654 32", kind: "IBAN", want: "GB82 WEST 1234 5698 7654 32"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			items := detectPII([]string{test.text}, nil)
			for _, item := range items {
				if item.Kind == test.kind && item.Value == test.want {
					return
				}
			}
			t.Fatalf("detectPII(%q) did not find %s %q: %#v", test.text, test.kind, test.want, items)
		})
	}
}

func TestDetectPIIRejectsInvalidCandidates(t *testing.T) {
	invalid := []string{
		"000-12-3456",         // invalid SSN area
		"666-12-3456",         // invalid SSN area
		"900-12-3456",         // invalid SSN area
		"123-00-4567",         // invalid SSN group
		"123-45-0000",         // invalid SSN serial
		"4111 1111 1111 1112", // failed Luhn check
		"2023-02-29",          // invalid calendar date
		"2099-01-01",          // future date
	}
	for _, text := range invalid {
		items := detectPII([]string{text}, nil)
		if len(items) != 0 {
			t.Errorf("detectPII(%q) returned false positive: %#v", text, items)
		}
	}
	if items := detectPII([]string{"X1234567"}, nil); len(items) != 0 {
		t.Fatalf("unlabeled passport/license-shaped token was detected: %#v", items)
	}
}

func TestDetectPIISensitiveFieldsAndScore(t *testing.T) {
	items := detectPII([]string{"user@example.com"}, []string{"creditCardNumber"})
	categories, score := summarizeEvidence(items)
	if score < 85 {
		t.Fatalf("expected corroborated score >= 85, got %d (%#v)", score, categories)
	}
	if !containsKind(items, "payment card field") {
		t.Fatalf("sensitive camelCase field was not recognized: %#v", items)
	}
}

func TestDetectPIIDateOfBirthFieldSamplesValues(t *testing.T) {
	for _, field := range []string{"dob", "birthday", "birth_day", "birthDate", "date-of-birth"} {
		items := detectPII([]string{"1984-07-12"}, []string{field})
		if !containsKind(items, "date of birth field") || !containsKind(items, "possible birthdate") {
			t.Errorf("field %q did not produce field and sampled-value evidence: %#v", field, items)
		}
		_, score := summarizeEvidence(items)
		if score < 85 {
			t.Errorf("field %q confidence score = %d, want at least 85", field, score)
		}
	}
}

func TestDetectPIICommonDatabaseFieldTitles(t *testing.T) {
	tests := map[string]string{
		"address":        "address field",
		"address_line_1": "address field",
		"phone":          "phone field",
		"mobile":         "phone field",
		"ss":             "social security or tax ID field",
		"ssn":            "social security or tax ID field",
		"email_address":  "email field",
		"first_name":     "personal name field",
		"bank_account":   "financial account field",
		"patient_id":     "medical information field",
	}
	for field, kind := range tests {
		items := detectPII(nil, []string{field})
		if !containsKind(items, kind) {
			t.Errorf("field %q did not produce %q: %#v", field, kind, items)
		}
	}
}

func TestDetectPIIHighEntropyKeyCandidate(t *testing.T) {
	key := "A7kP3mQ9xT2vN8cR5jL4sW6z"
	items := detectPII([]string{"api_key = " + key}, []string{"api_key"})
	if !containsKind(items, "high-entropy key candidate") || !containsKind(items, "credential or secret field") {
		t.Fatalf("high-entropy API key was not detected with field context: %#v", items)
	}
	for _, item := range items {
		if item.Kind == "high-entropy key candidate" && item.Confidence < 90 {
			t.Fatalf("contextual key confidence = %d, want at least 90", item.Confidence)
		}
	}
	if items := detectPII([]string{"token = ABCABCABCABCABCABC123123"}, nil); containsKind(items, "high-entropy key candidate") {
		t.Fatalf("low-entropy repeated token was detected: %#v", items)
	}
}

func TestRedactEvidence(t *testing.T) {
	items := []evidence{
		{Kind: "email address", Value: "person@example.com"},
		{Kind: "payment card", Value: "4111 1111 1111 1111"},
	}
	for _, item := range items {
		redacted := redactEvidence(item)
		if strings.Contains(redacted, item.Value) || redacted == "" {
			t.Errorf("redactEvidence(%#v) = %q", item, redacted)
		}
	}
}

func containsKind(items []evidence, kind string) bool {
	for _, item := range items {
		if item.Kind == kind {
			return true
		}
	}
	return false
}
