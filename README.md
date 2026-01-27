# CRA-AuditFlow

**The Sovereign Bridge to Cyber Resilience Act (CRA) Compliance.**

License: Apache 2.0
Status: EU Digital Sovereignty Focus
Project Phase: Proof of Concept
Target Deadline: September 2026

---

## Mission: Compliance for Everyone

By September 2026, the EU Cyber Resilience Act (CRA) becomes mandatory for almost all software products in the European market. For SMEs and solo developers, the bureaucratic burden of Article 18 (Technical Documentation) and Annex III/IV (Risk Mapping) is immense.

CRA-AuditFlow is a lightweight, open-source CLI toolkit designed to automate the heavy lifting of CRA compliance. It bridges the gap between your code and the regulatory requirements without leaking your intellectual property to non-EU cloud providers.

---

## Key Features

CRA-AuditFlow is built with a modular-first philosophy to ensure high impact:

* **Sovereign SBOM Management:** Automated ingestion and validation of CycloneDX and SPDX files to ensure full transparency of the software supply chain.
* **Local-First Vulnerability Mapping:** Cross-referencing dependencies with CERT-EU and EUVD (ENISA) advisories locally. This ensures that no sensitive dependency data leaves your infrastructure.
* **CRA Risk-Class Classifier:** Automated flagging of components that fall under Critical categories in Annex III and IV of the Cyber Resilience Act.
* **VEX (Vulnerability Exploitability eXchange) Engine:** A streamlined workflow for developers to document why a specific CVE does not affect their product, fulfilling the key requirement for Article 10 reporting.
* **Automated Article 18 Reports:** Generation of the Technical Documentation required for the CE-mark, significantly reducing the manual effort for compliance audits.

---

## Technical Architecture

* **Language:** Rust. Chosen for memory safety and performance, directly fulfilling the CRA's Security-by-Design mandate.
* **Privacy:** No telemetry, no cloud-sync. Operates 100% offline or within sovereign air-gapped environments.
* **Integrations:** CLI-first design with native support for European Git-forges like Codeberg and Forgejo, as well as standard GitLab/GitHub pipelines.

## Strategic Importance

The European digital landscape is shifting. With the potential withdrawal or restriction of international security services, Europe requires independent tools to verify its own software supply chain. CRA-AuditFlow is part of the strategic autonomy for European digital infrastructure, ensuring that compliance does not become an entry barrier for innovative small-scale developers.

---

## Contributing

We welcome contributions that align with the goal of European Digital Sovereignty. 

1. Check the [ROADMAP.md](ROADMAP.md) for development milestones.
2. Open an Issue for feature requests related to NIS2 or CRA specificities.

**License:** Apache License 2.0 (Industry-friendly Open Source)

---

*Developed by Michael Lodzik*
