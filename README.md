# CRA-AuditFlow

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
![Status: Proof of Concept](https://img.shields.io/badge/Status-Proof_of_Concept-orange)

A CLI toolkit for automating EU Cyber Resilience Act (CRA) compliance — built for SMEs and solo developers.

## Overview

The EU Cyber Resilience Act becomes mandatory in September 2026 for nearly all software products sold in the European market. Compliance requires extensive technical documentation (Article 18), risk classification against critical component lists (Annex III/IV), and ongoing vulnerability handling. CRA-AuditFlow automates documentation generation, vulnerability mapping, and risk classification through an offline-first CLI with no telemetry.

## Features

- **SBOM Management** — CycloneDX/SPDX ingestion and validation
- **Vulnerability Mapping** — Local cross-referencing against CERT-EU and EUVD advisories
- **Risk-Class Classifier** — Annex III/IV critical component flagging
- **VEX Engine** — Document CVE non-applicability per Article 10
- **Article 18 Reports** — Automated Technical Documentation for CE-marking

## Architecture

- **Language:** Rust (memory safety, performance)
- **Privacy:** Offline-first, no telemetry, air-gap compatible
- **Integrations:** CLI-first with CI/CD pipeline support (GitHub Actions, GitLab CI)

## Getting Started

> Project is in Proof of Concept phase. Build and install instructions will be added as the CLI takes shape.

### Prerequisites

- Rust toolchain (stable)

### Build from source

```sh
git clone https://github.com/yourusername/CRA-AuditFlow.git
cd CRA-AuditFlow
cargo build
```

## Roadmap

See [ROADMAP.md](ROADMAP.md) for development milestones and timeline.

## Contributing

Open an Issue for feature requests or bug reports. PRs welcome.

## License

Apache License 2.0 — see [LICENSE](LICENSE).
