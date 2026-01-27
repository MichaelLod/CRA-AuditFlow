# CRA-AuditFlow

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![CI](https://github.com/MichaelLod/CRA-AuditFlow/actions/workflows/ci.yml/badge.svg)](https://github.com/MichaelLod/CRA-AuditFlow/actions)
![Status: MVP](https://img.shields.io/badge/Status-MVP-green)

**The sovereign bridge to EU Cyber Resilience Act compliance.**

A Rust CLI that ingests your SBOM, checks components against known vulnerabilities, classifies your product under CRA Annex III/IV risk tiers, and generates a compliance report — entirely offline, with no telemetry.

Built for SMEs, solo developers, and anyone who needs CRA readiness without handing their supply chain data to a third party.

## Why This Exists

By September 2026, the EU Cyber Resilience Act (CRA) becomes mandatory for nearly all software products sold in the European market. Article 18 demands technical documentation, Annexes III and IV define critical product categories with stricter conformity requirements, and Article 10 requires ongoing vulnerability handling.

For large enterprises with compliance departments, this is business as usual. For everyone else, the bureaucratic burden is immense. CRA-AuditFlow automates the heavy lifting so you can focus on building software.

## What Works Today

The MVP delivers a complete end-to-end pipeline:

- **SBOM Ingestion** — Parse CycloneDX and SPDX JSON files, auto-detecting the format
- **Vulnerability Matching** — Offline lookup against an OSV-sourced SQLite database, matching by PURL and ecosystem+name with version filtering
- **CRA Risk Classification** — 26 product categories from Annexes III and IV, keyword-matched against your product name and description to determine Default, Class I, Class II, or Critical risk tier
- **Compliance Reports** — Markdown or plaintext output with risk classification, vulnerability findings by component, and SBOM overview

No network calls during audit. The only command that touches the network is `vuln update`, which downloads public OSV data on your terms.

## Quick Start

### Prerequisites

- Rust toolchain (stable)

### Build and install

```sh
git clone https://github.com/MichaelLod/CRA-AuditFlow.git
cd CRA-AuditFlow
cargo build --release
```

### Download vulnerability data

```sh
cargo run --release -- vuln update
```

This downloads OSV vulnerability records for npm, PyPI, Maven, crates.io, Go, NuGet, and RubyGems into a local SQLite database. Run it once, then update periodically.

### Run an audit

```sh
cargo run --release -- audit my-sbom.json -n "My Product" -d "a web application"
```

This parses your SBOM, matches components against the local vulnerability database, classifies your product under CRA rules, and prints a Markdown compliance report to stdout.

### Validate an SBOM

```sh
cargo run --release -- sbom validate my-sbom.json
```

### Check database status

```sh
cargo run --release -- vuln status
```

### Full CLI reference

```
cra-auditflow audit <SBOM_FILE> [OPTIONS]
  -n, --product-name <NAME>       Product name for the report
  -d, --description <DESC>        Product description (used for CRA classification)
  -f, --format <FORMAT>           Report format: markdown or plaintext [default: markdown]
  -o, --output <FILE>             Write report to file instead of stdout
      --rules <PATH>              Custom CRA classification rules TOML

cra-auditflow sbom validate <SBOM_FILE>

cra-auditflow vuln update [--ecosystems npm,pypi,...]
cra-auditflow vuln status

Global options:
      --db-path <PATH>            Custom vulnerability database path
  -v, --verbose                   Increase logging verbosity (-v, -vv, -vvv)
```

## Architecture

- **Language:** Rust — memory safety by default, directly aligned with CRA's security-by-design mandate
- **Privacy:** No telemetry, no cloud sync. Operates fully offline or within air-gapped environments
- **Storage:** Embedded SQLite via rusqlite (bundled), zero external database dependencies
- **SBOM Parsing:** Raw `serde_json::Value` extraction — no dependency on spec-version-locked ecosystem crates
- **Classification Rules:** TOML-based, embedded at compile time, overridable at runtime

## Vision

The MVP is the foundation. The roadmap toward September 2026 includes:

- **CERT-EU & EUVD Integration** — European vulnerability sources alongside OSV
- **VEX Engine** — Structured workflow for documenting why a CVE does not affect your product (Article 10)
- **Article 18 Documentation** — Automated generation of the Technical Documentation required for CE-marking
- **CI/CD Integration** — GitHub Actions, GitLab CI, and Forgejo/Codeberg pipeline templates with policy-as-code gating
- **SARIF Output** — Feed findings into code scanning dashboards

See [ROADMAP.md](ROADMAP.md) for the full development timeline.

## Contributing

Contributions that advance CRA compliance tooling are welcome. Check the [ROADMAP.md](ROADMAP.md) for development priorities, or open an Issue for feature requests and bug reports.

## License

Apache License 2.0 — see [LICENSE](LICENSE).

*Developed by Michael Lodzik*
