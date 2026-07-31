# PIIScan

[![CI](https://github.com/sundruid/PIIScan/actions/workflows/ci.yml/badge.svg)](https://github.com/sundruid/PIIScan/actions/workflows/ci.yml)
[![Latest release](https://img.shields.io/github/v/release/sundruid/PIIScan?sort=semver)](https://github.com/sundruid/PIIScan/releases)

PIIScan is an offline, cross-platform PII and secret triage scanner. It walks an evidence directory, extracts readable content from files, databases, office documents, and bounded archives, and ranks each logical file with an explainable confidence score. It writes a review-ready incident-response report in `.docx` format.

The current release is **v5.0.1**. Scores are triage signals (0–99%), not probabilities or legal conclusions. Validate the original evidence and business context before taking containment, deletion, or notification action.

## Quick start

Download the archive for the target operating system and architecture from the [latest release](https://github.com/sundruid/PIIScan/releases/latest), or build from source with Go 1.26+:

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

### Incident-response examples

Scan a macOS investigation directory with the Apple Silicon release:

```bash
piiscan-darwin-arm64 -filesystem /IR/Investigation_1234
```

Include up to three redacted evidence samples per finding:

```bash
piiscan-darwin-arm64 -include-evidence -filesystem /IR/Investigation_1234 -max-samples 3
```

Scan a directory containing large SQL exports. Plain-text dumps are streamed to the end of the file and are not subject to the former 128 MiB in-memory limit:

```bash
piiscan-darwin-arm64 -include-evidence -filesystem /IR/Investigation_1234/database-dumps -max-samples 3
```

Linux and Windows releases use the same options:

```bash
piiscan-linux-amd64 -filesystem /srv/IR/Investigation_1234
piiscan-windows-amd64.exe -filesystem C:\IR\Investigation_1234
```

## What is scanned

Extraction and detection are separate layers. The detector catalog and its validators live in [`detector.go`](detector.go), so adding or tuning a PII class does not require changing file-format code. The catalog is the source of truth; the README intentionally describes coverage by family rather than duplicating every pattern.

Supported input families include:

- Text and structured data: plain text, logs, source/config files, CSV/TSV, JSON/JSONL, SQL, XML/HTML, YAML, RTF, and email (`.eml`). These inputs are streamed in bounded chunks rather than loaded as one allocation, including multi-gigabyte files and PII that crosses a chunk boundary.
- Office and OpenDocument packages: DOCX, XLSX, PPTX, ODT, ODS, and ODP, including values split across XML formatting runs.
- Databases: SQLite (`.db`, `.sqlite`, `.sqlite3`) scanned read-only table by table. Plain-text MySQL/MariaDB, PostgreSQL, SQL Server, and Oracle exports are streamed without a file-size cutoff or dependence on vendor SQL syntax.
- Containers: ZIP, TAR, GZIP, and bounded nested combinations. Archive limits reduce accidental archive-bomb exposure.
- PDF: embedded text through a pure-Go parser.
- Legacy Office binaries: `.doc`, `.xls`, `.ppt`, and `.msg` through best-effort printable-string extraction.

Scanned-image or encrypted PDFs need OCR/decryption in a separate controlled workflow. Legacy binary formats and heavily encoded content can yield incomplete text.

Native proprietary database backups such as SQL Server `.bak`, Oracle `.dmp`, and PostgreSQL custom `.dump` files receive best-effort readable-text scanning. Compressed, encrypted, page-encoded, or otherwise opaque records should first be restored or converted to a plain-text SQL/CSV export with the vendor tool.

## Detection and triage

The catalog combines pattern matching with validity checks and context signals. It is designed to find common identifiers and secrets while reducing obvious false positives. Findings are grouped by logical file and include:

- a confidence percentage for analyst prioritization;
- matched categories and counts;
- source format and extraction warnings;
- optional redacted evidence samples; and
- deterministic ordering for repeatable incident review.

Database and structured-data scans are field-aware. Common PII column titles—including abbreviated or camelCase forms—create a high-confidence signal even when only one table in a very large dump contains sensitive data or the stored representation does not match a standard pattern; sampled values such as dates, addresses, phones, and identifiers provide corroborating evidence. Long mixed alphanumeric values are also evaluated for Shannon entropy and reported as suspected API keys or other secrets when they resemble generated credentials, with higher confidence when a nearby field or label supplies key/token context.

For streamed data files, PIIScan records how many logical lines contain detector evidence. Sparse, content-only coincidences are discounted—for example, 22 matching lines in a 1,500-line file score as low probability. This recurrence adjustment does not reduce confidence supplied by explicit PII schema/field labels or strong secret indicators, because one sensitive table or credential can be significant even in a much larger file.

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
