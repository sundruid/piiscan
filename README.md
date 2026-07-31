# piiscan

`piiscan` is an offline, cross-platform triage scanner for personally identifiable information (PII), secrets, and other sensitive identifiers. It walks a directory, extracts readable content from common files and containers, ranks suspected logical files with an explainable confidence score, and writes an incident-response report in `.docx` format.

The score is a triage ranking, not a probability or a legal determination. Incident responders should validate the original source and business context before containment, deletion, or notification decisions.

## What it scans

The shared detector catalog and validation rules live in [`detector.go`](detector.go). Adding or tuning a detector is deliberately isolated from the file-extraction and reporting code.

The scanner supports:

- Text and structured data: text, CSV, TSV, JSON, JSON Lines/NDJSON, SQL, XML, HTML, YAML, RTF, logs, source files, and common configuration files.
- Office/OpenDocument packages: DOCX, XLSX, PPTX, ODT, ODS, and ODP. XML parts are decoded so values split across formatted runs can still be detected.
- Databases: SQLite files are opened read-only and scanned table by table. SQL dumps are scanned as text.
- Containers: ZIP, TAR, GZIP, and nested combinations, with bounded decompression to reduce archive-bomb risk.
- Email: `.eml` headers and message bodies.
- PDF: embedded text layers through a pure-Go parser. Scanned-image, encrypted, or otherwise textless PDFs require OCR or a separate controlled workflow.
- Legacy Office binaries (`.doc`, `.xls`, `.ppt`, and `.msg`) through best-effort printable-string extraction; embedded or encoded text can be missed.

The detector currently includes validated patterns for email addresses, phone numbers, dates, SSNs, payment cards, passport and driver-license identifiers when context labels them, postal address fragments, IP/MAC addresses, AWS access keys, IBANs, Bitcoin addresses, private-key headers, and sensitive field names. It is intentionally not a replacement for an organization-specific data classification policy.

## Usage

```bash
go build -trimpath -ldflags='-s -w' -o piiscan .
./piiscan \
  -filesystem=/path/to/evidence \
  -report=/path/to/piiscan-report.docx
```

Options:

- `-filesystem` (required): directory to scan. Symlinks are not followed.
- `-report`: output DOCX path. Defaults to `piiscan-report.docx`.
- `-workers`: concurrent extractors. Defaults to the available CPU count.
- `-min-confidence`: include findings at or above this score (0-99). Defaults to 40.
- `-include-evidence`: include a small number of redacted evidence samples in console output and the report. Raw values are never written by this option.
- `-max-samples`: maximum redacted evidence samples per logical finding. Defaults to 3.

Console output is intentionally file-centric:

```text
[96%] /evidence/customers.xlsx (XLSX) - payment card (4), email address (8)
```

The DOCX report includes an executive summary, ranked findings, extraction format, confidence rationale, warnings and limitations, redacted evidence when requested, and an incident-response checklist.

## Development

Requirements: Go 1.26 or newer.

```bash
gofmt -w .
go test -race ./...
go vet ./...
go build ./...
```

The GitHub Actions workflow runs formatting, race-enabled tests, vet, a native build, and CGO-free cross-builds for:

- macOS: amd64 and arm64
- Linux: amd64 and arm64
- Windows: amd64 and arm64

Pushing a semantic version tag such as `v5.0.0` runs the release workflow and publishes archives for all six targets. The release build is CGO-free so the SQLite driver remains portable.

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the maintenance checklist.
