use std::path::PathBuf;

use cra_auditflow::classifier::cra;
use cra_auditflow::models::assessment::{AuditSummary, ComponentFinding, CraRiskClass};
use cra_auditflow::models::vulnerability::{AffectedPackage, AffectedRange, Severity, VulnRecord};
use cra_auditflow::report::{self, ReportFormat};
use cra_auditflow::sbom;
use cra_auditflow::vuln::db::VulnDb;
use cra_auditflow::vuln::matcher;

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}

fn seed_test_db() -> VulnDb {
    let mut db = VulnDb::open_in_memory().unwrap();
    let records = vec![
        VulnRecord {
            id: "GHSA-lodash-proto".into(),
            aliases: vec!["CVE-2025-0001".into()],
            summary: Some("Prototype pollution in lodash".into()),
            severity: vec![Severity {
                score: Some(7.5),
                severity_type: "CVSS_V3".into(),
                vector: None,
            }],
            affected: vec![AffectedPackage {
                ecosystem: Some("npm".into()),
                name: "lodash".into(),
                purl: Some("pkg:npm/lodash".into()),
                versions: vec!["4.17.21".into()],
                ranges: vec![],
            }],
            references: vec![],
            modified: "2025-01-01T00:00:00Z".into(),
            withdrawn: None,
        },
        VulnRecord {
            id: "GHSA-spring-rce".into(),
            aliases: vec!["CVE-2025-0002".into()],
            summary: Some("Remote code execution in Spring Boot".into()),
            severity: vec![Severity {
                score: Some(9.8),
                severity_type: "CVSS_V3".into(),
                vector: None,
            }],
            affected: vec![AffectedPackage {
                ecosystem: Some("maven".into()),
                name: "spring-boot".into(),
                purl: Some("pkg:maven/org.springframework.boot/spring-boot".into()),
                versions: vec!["3.2.0".into()],
                ranges: vec![AffectedRange {
                    range_type: "ECOSYSTEM".into(),
                    introduced: Some("3.0.0".into()),
                    fixed: Some("3.2.1".into()),
                    last_affected: None,
                }],
            }],
            references: vec![],
            modified: "2025-02-01T00:00:00Z".into(),
            withdrawn: None,
        },
    ];
    db.upsert_records(&records).unwrap();
    db
}

#[test]
fn end_to_end_audit_pipeline_cyclonedx() {
    // 1. Parse SBOM
    let doc = sbom::parse_sbom(&fixture_path("cyclonedx_minimal.json")).unwrap();
    assert_eq!(doc.components.len(), 3);

    // 2. Match vulnerabilities
    let db = seed_test_db();
    let findings: Vec<ComponentFinding> = doc
        .components
        .iter()
        .map(|c| {
            let vulns = matcher::find_vulnerabilities(&db, c).unwrap_or_default();
            ComponentFinding {
                component_name: c.name.clone(),
                component_version: c.version.clone(),
                purl: c.purl.clone(),
                vulnerabilities: vulns,
            }
        })
        .collect();

    // lodash and spring-boot should have vulns
    let lodash_findings = findings
        .iter()
        .find(|f| f.component_name == "lodash")
        .unwrap();
    assert_eq!(lodash_findings.vulnerabilities.len(), 1);
    assert_eq!(lodash_findings.vulnerabilities[0].id, "GHSA-lodash-proto");

    let spring_findings = findings
        .iter()
        .find(|f| f.component_name == "spring-boot")
        .unwrap();
    assert_eq!(spring_findings.vulnerabilities.len(), 1);
    assert_eq!(spring_findings.vulnerabilities[0].id, "GHSA-spring-rce");

    // serde should have no vulns
    let serde_findings = findings
        .iter()
        .find(|f| f.component_name == "serde")
        .unwrap();
    assert!(serde_findings.vulnerabilities.is_empty());

    // 3. Classify
    let rules = cra::load_default_rules();
    let classification = cra::classify_product(&rules, "My Browser Product", Some("a web browser"));
    assert_eq!(classification.risk_class, CraRiskClass::ImportantClassI);

    // 4. Build summary
    let summary = AuditSummary::from_findings(&findings, doc.components.len());
    assert_eq!(summary.total_components, 3);
    assert_eq!(summary.components_with_vulns, 2);
    assert_eq!(summary.total_vulnerabilities, 2);
    assert_eq!(summary.critical_count, 1); // spring-boot 9.8
    assert_eq!(summary.high_count, 1); // lodash 7.5

    // 5. Generate report
    let assessment = cra_auditflow::models::assessment::AuditAssessment {
        product_name: Some("My Browser Product".into()),
        classification,
        findings,
        summary,
        sbom_format: doc.format.to_string(),
        sbom_spec_version: doc.spec_version.clone(),
        sbom_component_count: doc.components.len(),
    };

    let md_report = report::render(&assessment, ReportFormat::Markdown);
    assert!(md_report.contains("# CRA Compliance Audit Report"));
    assert!(md_report.contains("Important (Class I)"));
    assert!(md_report.contains("GHSA-lodash-proto"));
    assert!(md_report.contains("GHSA-spring-rce"));
    assert!(md_report.contains("CycloneDX"));

    let txt_report = report::render(&assessment, ReportFormat::Plaintext);
    assert!(txt_report.contains("CRA COMPLIANCE AUDIT REPORT"));
    assert!(txt_report.contains("Important (Class I)"));
    assert!(txt_report.contains("GHSA-lodash-proto"));
}

#[test]
fn end_to_end_audit_pipeline_spdx() {
    let doc = sbom::parse_sbom(&fixture_path("spdx_minimal.json")).unwrap();
    assert_eq!(doc.components.len(), 3);

    let db = seed_test_db();
    let findings: Vec<ComponentFinding> = doc
        .components
        .iter()
        .map(|c| {
            let vulns = matcher::find_vulnerabilities(&db, c).unwrap_or_default();
            ComponentFinding {
                component_name: c.name.clone(),
                component_version: c.version.clone(),
                purl: c.purl.clone(),
                vulnerabilities: vulns,
            }
        })
        .collect();

    let summary = AuditSummary::from_findings(&findings, doc.components.len());
    assert_eq!(summary.components_with_vulns, 2);
    assert_eq!(summary.total_vulnerabilities, 2);
}
