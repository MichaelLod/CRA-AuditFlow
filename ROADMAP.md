# Project Roadmap: CRA-AuditFlow

Development path toward a production-ready compliance tool by the September 2026 CRA deadline.

## Phase 0: MVP Foundation -- Complete

- Project scaffolding (Cargo.toml, CI, linting, pre-commit hooks)
- Data models (Component, Vulnerability, Assessment)
- SBOM ingestion (CycloneDX + SPDX JSON, auto-detection)
- Offline vulnerability matching via OSV/SQLite (PURL + ecosystem lookup)
- Semver-aware version range comparison
- CVSS v3.1 base score computation from vector strings
- Withdrawn-advisory filtering
- CRA risk classification (26 categories from Annexes III/IV)
- Markdown + plaintext report generation (CVE aliases, OSV links, fix versions)
- CLI with `audit`, `sbom validate`, `vuln update`, `vuln status`
- 96 tests (unit + integration + CLI binary)

## Phase 1: Extended Vulnerability Sources

- CERT-EU advisory integration
- EUVD (ENISA) feed support
- NVD/CVE cross-referencing
- CPE-based matching alongside PURL
- CVSS v4.0 base score computation

## Phase 2: VEX Engine

- VEX document ingestion (CSAF / OpenVEX)
- Interactive triage workflow
- Justification templates per CRA Article 10
- VEX export for downstream consumers

## Phase 3: Article 18 Technical Documentation

- Structured documentation generation (PDF/HTML)
- CE-mark readiness checklist
- Evidence attachment support
- Conformity assessment routing (self / third-party / EU type)

## Phase 4: CI/CD Integration

- GitHub Actions reusable workflow
- GitLab CI template
- Forgejo/Codeberg pipeline support
- SARIF output for code scanning dashboards
- Policy-as-code gate (fail builds on critical findings)
