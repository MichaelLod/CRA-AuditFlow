# CRA-AuditFlow Roadmap

## Phase 0 -- MVP Foundation (Current)

- Project scaffolding (Cargo.toml, CI, linting)
- Data models (Component, Vulnerability, Assessment)
- SBOM ingestion (CycloneDX + SPDX JSON)
- Offline vulnerability matching via OSV/SQLite
- CRA risk classification (Annex III/IV keyword matching)
- Markdown + plaintext report generation
- CLI with `audit`, `sbom validate`, `vuln update`, `vuln status`

## Phase 1 -- Extended Vulnerability Sources

- CERT-EU advisory integration
- EUVD (ENISA) feed support
- NVD/CVE cross-referencing
- CPE-based matching alongside PURL

## Phase 2 -- VEX Engine

- VEX document ingestion (CSAF / OpenVEX)
- Interactive triage workflow
- Justification templates per CRA Article 10
- VEX export for downstream consumers

## Phase 3 -- Article 18 Technical Documentation

- Structured documentation generation (PDF/HTML)
- CE-mark readiness checklist
- Evidence attachment support
- Conformity assessment routing (self / third-party / EU type)

## Phase 4 -- CI/CD Integration

- GitHub Actions reusable workflow
- GitLab CI template
- Forgejo/Codeberg pipeline support
- SARIF output for code scanning dashboards
- Policy-as-code gate (fail builds on critical findings)
