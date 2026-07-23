# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- CVSS v3.1 base score computation from vector strings (`cvss` module), applied
  both at ingestion and as a read-time fallback for records stored before
  vector-based scoring existed — most GitHub Security Advisories ship vectors
  without numeric scores
- Withdrawn advisories (OSV `withdrawn` field) are now parsed and excluded from
  audit findings
- Markdown reports link each advisory to osv.dev and show CVE aliases and
  fix-version guidance per finding; plaintext reports show fix versions
- Bundled demo SBOM and generated report under `examples/`
- `#![forbid(unsafe_code)]` at both crate roots

### Fixed

- Advisory summaries containing multi-byte UTF-8 no longer risk a panic during
  report truncation (character-based instead of byte-based slicing)
- Table-breaking characters (`|`, newlines) in advisory summaries are escaped
  in Markdown reports
- CLI audit tests now pass an explicit `--db-path`, making them hermetic
  instead of dependent on the developer's local vulnerability database
- `Cargo.lock` is now committed for reproducible builds
- Repository URL in `Cargo.toml`

## [0.1.0] - 2026-01-27

### Added

- SBOM ingestion for CycloneDX and SPDX JSON with format auto-detection
- Offline vulnerability matching against an OSV-sourced SQLite database
  (PURL and ecosystem+name strategies, semver-aware range filtering)
- CRA risk classification covering 26 product categories from Annexes III/IV
- Markdown and plaintext compliance report generation
- CLI with `audit`, `sbom validate`, `vuln update`, and `vuln status` commands
- CI (rustfmt, clippy, build, test), pre-commit hooks, integration test suite
