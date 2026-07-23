use serde::{Deserialize, Serialize};
use std::fmt;

use super::vulnerability::VulnRecord;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CraRiskClass {
    Default,
    ImportantClassI,
    ImportantClassII,
    Critical,
}

impl fmt::Display for CraRiskClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Default => write!(f, "Default"),
            Self::ImportantClassI => write!(f, "Important (Class I)"),
            Self::ImportantClassII => write!(f, "Important (Class II)"),
            Self::Critical => write!(f, "Critical"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CraClassification {
    pub risk_class: CraRiskClass,
    pub matched_category: Option<String>,
    pub matched_keywords: Vec<String>,
    pub applicable_articles: Vec<String>,
    pub conformity_note: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentFinding {
    pub component_name: String,
    pub component_version: Option<String>,
    pub purl: Option<String>,
    pub vulnerabilities: Vec<VulnRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditSummary {
    pub total_components: usize,
    pub components_with_vulns: usize,
    pub total_vulnerabilities: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub unknown_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditAssessment {
    pub product_name: Option<String>,
    pub classification: CraClassification,
    pub findings: Vec<ComponentFinding>,
    pub summary: AuditSummary,
    pub sbom_format: String,
    pub sbom_spec_version: String,
    pub sbom_component_count: usize,
}

impl AuditSummary {
    pub fn from_findings(findings: &[ComponentFinding], total_components: usize) -> Self {
        let mut critical = 0usize;
        let mut high = 0usize;
        let mut medium = 0usize;
        let mut low = 0usize;
        let mut unknown = 0usize;
        let mut total_vulns = 0usize;

        for f in findings {
            for v in &f.vulnerabilities {
                total_vulns += 1;
                match v.severity_label() {
                    "CRITICAL" => critical += 1,
                    "HIGH" => high += 1,
                    "MEDIUM" => medium += 1,
                    "LOW" => low += 1,
                    _ => unknown += 1,
                }
            }
        }

        Self {
            total_components,
            components_with_vulns: findings
                .iter()
                .filter(|f| !f.vulnerabilities.is_empty())
                .count(),
            total_vulnerabilities: total_vulns,
            critical_count: critical,
            high_count: high,
            medium_count: medium,
            low_count: low,
            unknown_count: unknown,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::vulnerability::{Severity, VulnRecord};

    #[test]
    fn risk_class_display() {
        assert_eq!(CraRiskClass::Default.to_string(), "Default");
        assert_eq!(CraRiskClass::Critical.to_string(), "Critical");
        assert_eq!(
            CraRiskClass::ImportantClassI.to_string(),
            "Important (Class I)"
        );
        assert_eq!(
            CraRiskClass::ImportantClassII.to_string(),
            "Important (Class II)"
        );
    }

    #[test]
    fn audit_summary_counts() {
        let findings = vec![ComponentFinding {
            component_name: "test".into(),
            component_version: Some("1.0".into()),
            purl: None,
            vulnerabilities: vec![
                VulnRecord {
                    id: "CVE-2025-0001".into(),
                    aliases: vec![],
                    summary: None,
                    severity: vec![Severity {
                        score: Some(9.8),
                        severity_type: "CVSS_V3".into(),
                        vector: None,
                    }],
                    affected: vec![],
                    references: vec![],
                    modified: String::new(),
                    withdrawn: None,
                },
                VulnRecord {
                    id: "CVE-2025-0002".into(),
                    aliases: vec![],
                    summary: None,
                    severity: vec![Severity {
                        score: Some(5.5),
                        severity_type: "CVSS_V3".into(),
                        vector: None,
                    }],
                    affected: vec![],
                    references: vec![],
                    modified: String::new(),
                    withdrawn: None,
                },
            ],
        }];

        let summary = AuditSummary::from_findings(&findings, 10);
        assert_eq!(summary.total_components, 10);
        assert_eq!(summary.components_with_vulns, 1);
        assert_eq!(summary.total_vulnerabilities, 2);
        assert_eq!(summary.critical_count, 1);
        assert_eq!(summary.medium_count, 1);
    }
}
