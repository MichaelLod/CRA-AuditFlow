# Project Roadmap: CRA-AuditFlow

This roadmap outlines the development path toward a production-ready compliance tool by the September 2026 CRA deadline.

## Phase 1: Core Architecture (Month 1-2)
- Initial CLI structure in Rust.
- Implementation of CycloneDX and SPDX JSON parsers.
- Local database schema for vulnerability caching (to ensure privacy).

## Phase 2: Vulnerability Mapping (Month 3-4)
- Integration with OSV.dev and CERT-EU API adapters.
- Logic for cross-referencing SBOM components with known CVEs.
- First Alpha release: Basic "Identify" functionality.

## Phase 3: CRA Intelligence (Month 5)
- Categorization engine for CRA Annex III and IV (Critical software classes).
- VEX (Vulnerability Exploitability eXchange) file generator.
- Second Alpha release: Basic "VEX-Export" functionality.

## Phase 4: Reporting & Compliance (Month 6-7)
- Automated generation of Technical Documentation according to CRA Article 18.
- Integration plugins for GitLab CI and GitHub Actions.
- Beta release: Full end-to-end compliance workflow.

## Phase 5: Audit & Launch (Month 8+)
- External security audit of the Rust codebase.
- Community feedback and stable 1.0 release for the September 2026 deadline.
