use crate::models::assessment::AuditAssessment;

pub fn render(assessment: &AuditAssessment) -> String {
    let mut out = String::new();
    let width = 72;
    let sep = "=".repeat(width);
    let thin_sep = "-".repeat(width);

    // Header
    let product = assessment
        .product_name
        .as_deref()
        .unwrap_or("Unknown Product");
    let date = chrono::Utc::now().format("%Y-%m-%d");
    let version = env!("CARGO_PKG_VERSION");

    out.push_str(&sep);
    out.push('\n');
    out.push_str("  CRA COMPLIANCE AUDIT REPORT\n");
    out.push_str(&sep);
    out.push('\n');
    out.push_str(&format!("  Product:  {product}\n"));
    out.push_str(&format!("  Date:     {date}\n"));
    out.push_str(&format!("  Tool:     cra-auditflow v{version}\n"));
    out.push('\n');

    // CRA Risk Classification
    let cls = &assessment.classification;
    out.push_str(&thin_sep);
    out.push('\n');
    out.push_str("  CRA RISK CLASSIFICATION\n");
    out.push_str(&thin_sep);
    out.push('\n');
    out.push_str(&format!("  Risk Class:           {}\n", cls.risk_class));

    if let Some(cat) = &cls.matched_category {
        out.push_str(&format!("  Matched Category:     {cat}\n"));
    }

    if !cls.matched_keywords.is_empty() {
        out.push_str(&format!(
            "  Matched Keywords:     {}\n",
            cls.matched_keywords.join(", ")
        ));
    }

    if !cls.applicable_articles.is_empty() {
        out.push_str(&format!(
            "  Applicable Articles:  {}\n",
            cls.applicable_articles.join(", ")
        ));
    }

    out.push_str(&format!(
        "  Conformity:           {}\n",
        cls.conformity_note
    ));
    out.push('\n');

    // Audit Summary
    let s = &assessment.summary;
    out.push_str(&thin_sep);
    out.push('\n');
    out.push_str("  AUDIT SUMMARY\n");
    out.push_str(&thin_sep);
    out.push('\n');
    out.push_str(&format!(
        "  Total Components:              {}\n",
        s.total_components
    ));
    out.push_str(&format!(
        "  Components with Vulns:         {}\n",
        s.components_with_vulns
    ));
    out.push_str(&format!(
        "  Total Vulnerabilities:         {}\n",
        s.total_vulnerabilities
    ));
    out.push_str(&format!(
        "  Critical:                      {}\n",
        s.critical_count
    ));
    out.push_str(&format!(
        "  High:                          {}\n",
        s.high_count
    ));
    out.push_str(&format!(
        "  Medium:                        {}\n",
        s.medium_count
    ));
    out.push_str(&format!(
        "  Low:                           {}\n",
        s.low_count
    ));

    if s.unknown_count > 0 {
        out.push_str(&format!(
            "  Unknown:                       {}\n",
            s.unknown_count
        ));
    }
    out.push('\n');

    // Vulnerability Findings
    let has_findings = assessment
        .findings
        .iter()
        .any(|f| !f.vulnerabilities.is_empty());

    if has_findings {
        out.push_str(&thin_sep);
        out.push('\n');
        out.push_str("  VULNERABILITY FINDINGS\n");
        out.push_str(&thin_sep);
        out.push('\n');

        for finding in &assessment.findings {
            if finding.vulnerabilities.is_empty() {
                continue;
            }

            let ver = finding.component_version.as_deref().unwrap_or("unknown");
            out.push_str(&format!("\n  {} v{}\n", finding.component_name, ver));

            if let Some(purl) = &finding.purl {
                out.push_str(&format!("  PURL: {purl}\n"));
            }
            out.push('\n');

            for vuln in &finding.vulnerabilities {
                let score_str = vuln
                    .max_score()
                    .map(|s| format!("{s:.1}"))
                    .unwrap_or_else(|| "N/A".into());
                let summary = vuln
                    .summary
                    .as_deref()
                    .unwrap_or("No description")
                    .replace('\n', " ");
                let truncated = super::truncate_chars(&summary, 60);

                out.push_str(&format!(
                    "    [{:8}] {:>5}  {}  {}\n",
                    vuln.severity_label(),
                    score_str,
                    vuln.id,
                    truncated
                ));

                let fixed =
                    vuln.fixed_versions_for(&finding.component_name, finding.purl.as_deref());
                if !fixed.is_empty() {
                    out.push_str(&format!("               fixed in: {}\n", fixed.join(", ")));
                }
            }
        }
        out.push('\n');
    }

    // SBOM Overview
    out.push_str(&thin_sep);
    out.push('\n');
    out.push_str("  SBOM OVERVIEW\n");
    out.push_str(&thin_sep);
    out.push('\n');
    out.push_str(&format!("  Format:          {}\n", assessment.sbom_format));
    out.push_str(&format!(
        "  Spec Version:    {}\n",
        assessment.sbom_spec_version
    ));
    out.push_str(&format!(
        "  Component Count: {}\n",
        assessment.sbom_component_count
    ));
    out.push('\n');

    out.push_str(&sep);
    out.push('\n');
    out.push_str(&format!(
        "  Generated by cra-auditflow v{version} on {date}\n"
    ));
    out.push_str(&sep);
    out.push('\n');

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::assessment::*;

    fn sample_assessment() -> AuditAssessment {
        AuditAssessment {
            product_name: Some("TestProduct".into()),
            classification: CraClassification {
                risk_class: CraRiskClass::Default,
                matched_category: None,
                matched_keywords: vec![],
                applicable_articles: vec!["Article 32".into()],
                conformity_note: "Self-assessment".into(),
            },
            findings: vec![],
            summary: AuditSummary {
                total_components: 3,
                components_with_vulns: 0,
                total_vulnerabilities: 0,
                critical_count: 0,
                high_count: 0,
                medium_count: 0,
                low_count: 0,
                unknown_count: 0,
            },
            sbom_format: "SPDX".into(),
            sbom_spec_version: "2.3".into(),
            sbom_component_count: 3,
        }
    }

    #[test]
    fn renders_plaintext_header() {
        let report = render(&sample_assessment());
        assert!(report.contains("CRA COMPLIANCE AUDIT REPORT"));
        assert!(report.contains("TestProduct"));
    }

    #[test]
    fn renders_plaintext_classification() {
        let report = render(&sample_assessment());
        assert!(report.contains("Default"));
        assert!(report.contains("Self-assessment"));
    }

    #[test]
    fn renders_plaintext_sbom_overview() {
        let report = render(&sample_assessment());
        assert!(report.contains("SPDX"));
    }
}
