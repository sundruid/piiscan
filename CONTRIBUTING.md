# Contributing to piiscan

Keep changes small, testable, and focused on scanner accuracy or operational safety.

## Before opening a pull request

1. Read the relevant extractor and detector code before changing behavior.
2. Add positive and negative regression cases for every detector change.
3. Keep raw PII out of fixtures unless a validator needs a synthetic example; use clearly synthetic values.
4. Run `gofmt -w .`, `go test -race ./...`, `go vet ./...`, and `go build ./...`.
5. If a format is added, document its extraction boundary and failure mode in the README.
6. Preserve the file-centric, redacted-by-default report behavior.

Detector confidence values are intentionally explainable. A change to a score or validation rule should explain the false-positive/false-negative tradeoff in the pull request.

## Release process

Releases are created by pushing a semantic version tag (`vMAJOR.MINOR.PATCH`). GitHub Actions cross-compiles CGO-free binaries for macOS, Linux, and Windows on amd64 and arm64, packages them, and publishes the archives to the GitHub release.
