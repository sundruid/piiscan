# piiscan

[![CI](https://github.com/sundruid/piiscan/actions/workflows/ci.yml/badge.svg)](https://github.com/sundruid/piiscan/actions/workflows/ci.yml)
[![Latest release](https://img.shields.io/github/v/release/sundruid/piiscan?sort=semver)](https://github.com/sundruid/piiscan/releases)

`piiscan` is an offline, cross-platform PII and secret triage scanner. It walks an evidence directory, extracts readable content from files, databases, office documents, and bounded archives, and ranks each logical file with an explainable confidence score. It writes a review-ready incident-response report in `.docx` format.

The current release is **v5.0.0**. Scores are triage signals (0–99%), not probabilities or legal conclusions. Validate the original evidence and business context before taking containment, deletion, or notification action.

## Quick start

Download the archive for the target operating system and architecture from the [latest release](https://github.com/sundruid/piiscan/releases/latest), or build from source with Go 1.26+:

```bash
go build -trimpath -ldflags='-s -w' -o piiscan .
./piiscan \
  -filesystem=/path/to/evidence \
  -report=/path/to/piiscan-report.docx
```

The scanner prints one ranked line per suspected file and writes the DOCX report. Evidence is omitted by default; `-include-evidence` adds only redacted samples.

```text
[96%] /evidence/customers.xlsx (XLSX) - payment card (4), email address (8)
Report written to /evidence/piiscan-report.docx
```

## What is scanned

Extraction and detection are separate layers. The detector catalog and its validators live in [`detector.go`](detector.go), so adding or tuning a PII class does not require changing file-format code. The catalog is the source of truth; the README intentionally describes coverage by family rather than duplicating every pattern.

Supported input families include:

- Text and structured data: plain text, logs, source/config files, CSV/TSV, JSON/JSONL, SQL, XML/HTML, YAML, RTF, and email (`.eml`).
- Office and OpenDocument packages: DOCX, XLSX, PPTX, ODT, ODS, and ODP, including values split across XML formatting runs.
- Databases: SQLite (`.db`, `.sqlite`, `.sqlite3`) scanned read-only table by table; SQL dumps are treated as text.
- Containers: ZIP, TAR, GZIP, and bounded nested combinations. Archive limits reduce accidental archive-bomb exposure.
- PDF: embedded text through a pure-Go parser.
- Legacy Office binaries: `.doc`, `.xls`, `.ppt`, and `.msg` through best-effort printable-string extraction.

Scanned-image or encrypted PDFs need OCR/decryption in a separate controlled workflow. Legacy binary formats and heavily encoded content can yield incomplete text.

## Detection and triage

The catalog combines pattern matching with validity checks and context signals. It is designed to find common identifiers and secrets while reducing obvious false positives. Findings are grouped by logical file and include:

- a confidence percentage for analyst prioritization;
- matched categories and counts;
- source format and extraction warnings;
- optional redacted evidence samples; and
- deterministic ordering for repeatable incident review.

Use `-min-confidence` to change the reporting threshold. The default is 40. A higher threshold is useful for a first-pass queue; a lower threshold is useful when recall matters more than analyst time.

## Command-line options

- `-filesystem` (required): root directory to scan. Symlinks are not followed.
- `-report`: output DOCX path; default `piiscan-report.docx`.
- `-workers`: maximum concurrent file scanners; defaults to the available CPU count.
- `-min-confidence`: include findings at or above 0–99; default 40.
- `-include-evidence`: include redacted samples in console output and the DOCX report.
- `-max-samples`: maximum redacted samples per finding; default 3.
- `-version`: print the scanner version.

The report contains an executive summary, ranked findings, format coverage, confidence rationale, warnings and limitations, optional redacted evidence, and a response checklist.

## Releases

Tags matching `vMAJOR.MINOR.PATCH` publish archives with SHA-256 checksums through GitHub Actions. Each release contains CGO-free builds for:

| OS | Architectures | Archive |
| --- | --- | --- |
| macOS | amd64, arm64 | `.tar.gz` |
| Linux | amd64, arm64 | `.tar.gz` |
| Windows | amd64, arm64 | `.zip` |

Every archive has a matching `.sha256` file. The release workflow is defined in [`.github/workflows/release.yml`](.github/workflows/release.yml).

## Development

Requirements: Go 1.26 or newer.

```bash
gofmt -w .
go test -race ./...
go vet ./...
go build ./...
```

CI also runs CGO-free cross-builds for all six release targets. See [`CONTRIBUTING.md`](CONTRIBUTING.md) for detector, extractor, fixture, and release conventions.

## License

No license has been declared yet. Treat the repository as all-rights-reserved until a project license is added.
