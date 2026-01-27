use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::classifier::cra;
use crate::models::assessment::{AuditAssessment, AuditSummary, ComponentFinding};
use crate::report::{self, ReportFormat};
use crate::sbom;
use crate::vuln::db::{self, VulnDb};
use crate::vuln::matcher;
use crate::vuln::osv;

/// Run the full audit pipeline: parse SBOM -> match vulns -> classify -> report.
pub fn run_audit(
    sbom_file: &Path,
    product_name: Option<&str>,
    description: Option<&str>,
    format_str: &str,
    output: Option<&Path>,
    rules_path: Option<&Path>,
    db_path: Option<&Path>,
) -> Result<()> {
    let format = ReportFormat::from_str_opt(format_str)
        .with_context(|| format!("unsupported report format: '{format_str}'"))?;

    // 1. Parse SBOM
    tracing::info!("Parsing SBOM: {}", sbom_file.display());
    let doc = sbom::parse_sbom(sbom_file)
        .with_context(|| format!("failed to parse SBOM: {}", sbom_file.display()))?;

    let product = product_name.map(String::from).or(doc.document_name.clone());

    tracing::info!(
        "SBOM: {} ({} v{}), {} components",
        product.as_deref().unwrap_or("unknown"),
        doc.format,
        doc.spec_version,
        doc.components.len()
    );

    // 2. Open vulnerability database and match
    let resolved_db_path = resolve_db_path(db_path)?;
    let findings = if resolved_db_path.exists() {
        tracing::info!(
            "Opening vulnerability database: {}",
            resolved_db_path.display()
        );
        let vuln_db =
            VulnDb::open(&resolved_db_path).context("failed to open vulnerability database")?;

        doc.components
            .iter()
            .map(|component| {
                let vulns = matcher::find_vulnerabilities(&vuln_db, component).unwrap_or_default();
                ComponentFinding {
                    component_name: component.name.clone(),
                    component_version: component.version.clone(),
                    purl: component.purl.clone(),
                    vulnerabilities: vulns,
                }
            })
            .collect::<Vec<_>>()
    } else {
        tracing::warn!(
            "No vulnerability database found at {}. Run 'cra-auditflow vuln update' first. Skipping vulnerability matching.",
            resolved_db_path.display()
        );
        vec![]
    };

    // 3. Classify CRA risk
    let rules = match rules_path {
        Some(p) => cra::load_rules(p)
            .with_context(|| format!("failed to load rules from {}", p.display()))?,
        None => cra::load_default_rules(),
    };

    let classification =
        cra::classify_product(&rules, product.as_deref().unwrap_or(""), description);

    tracing::info!("CRA risk class: {}", classification.risk_class);

    // 4. Build assessment
    let summary = AuditSummary::from_findings(&findings, doc.components.len());
    let assessment = AuditAssessment {
        product_name: product,
        classification,
        findings,
        summary,
        sbom_format: doc.format.to_string(),
        sbom_spec_version: doc.spec_version,
        sbom_component_count: doc.components.len(),
    };

    // 5. Generate report
    let report_text = report::render(&assessment, format);

    match output {
        Some(path) => {
            std::fs::write(path, &report_text)
                .with_context(|| format!("failed to write report to {}", path.display()))?;
            eprintln!("Report written to {}", path.display());
        }
        None => {
            print!("{report_text}");
        }
    }

    Ok(())
}

/// Validate an SBOM file and print a summary.
pub fn run_sbom_validate(sbom_file: &Path) -> Result<()> {
    let doc = sbom::parse_sbom(sbom_file)
        .with_context(|| format!("failed to parse SBOM: {}", sbom_file.display()))?;

    eprintln!("SBOM is valid.");
    eprintln!("  Format:          {}", doc.format);
    eprintln!("  Spec Version:    {}", doc.spec_version);
    if let Some(name) = &doc.document_name {
        eprintln!("  Document Name:   {name}");
    }
    eprintln!("  Components:      {}", doc.components.len());

    let with_purl = doc.components.iter().filter(|c| c.purl.is_some()).count();
    let with_license = doc
        .components
        .iter()
        .filter(|c| c.license.is_some())
        .count();
    eprintln!("  With PURL:       {with_purl}");
    eprintln!("  With License:    {with_license}");

    Ok(())
}

/// Download and update the vulnerability database from OSV.
pub fn run_vuln_update(ecosystems: Option<&[String]>, db_path: Option<&Path>) -> Result<()> {
    let resolved_path = resolve_db_path(db_path)?;

    if let Some(parent) = resolved_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create directory: {}", parent.display()))?;
    }

    let mut vuln_db =
        VulnDb::open(&resolved_path).context("failed to open vulnerability database")?;

    let eco_list: Vec<&str> = match ecosystems {
        Some(list) => list.iter().map(|s| s.as_str()).collect(),
        None => osv::DEFAULT_ECOSYSTEMS.to_vec(),
    };

    eprintln!(
        "Updating vulnerability data for {} ecosystems...",
        eco_list.len()
    );

    let mut total_records = 0usize;
    for ecosystem in &eco_list {
        eprint!("  Downloading {ecosystem}...");
        match osv::download_ecosystem(ecosystem) {
            Ok(records) => {
                let count = records.len();
                vuln_db
                    .upsert_records(&records)
                    .with_context(|| format!("failed to store {ecosystem} records"))?;
                total_records += count;
                eprintln!(" {count} records");
            }
            Err(e) => {
                eprintln!(" ERROR: {e}");
            }
        }
    }

    eprintln!("Done. Total records stored: {total_records}");
    eprintln!("Database: {}", resolved_path.display());

    Ok(())
}

/// Show the status of the vulnerability database.
pub fn run_vuln_status(db_path: Option<&Path>) -> Result<()> {
    let resolved_path = resolve_db_path(db_path)?;

    if !resolved_path.exists() {
        eprintln!(
            "No vulnerability database found at {}",
            resolved_path.display()
        );
        eprintln!("Run 'cra-auditflow vuln update' to download vulnerability data.");
        return Ok(());
    }

    let vuln_db = VulnDb::open(&resolved_path).context("failed to open vulnerability database")?;

    let record_count = vuln_db.record_count().context("failed to count records")?;
    let eco_count = vuln_db
        .ecosystem_count()
        .context("failed to count ecosystems")?;

    eprintln!("Vulnerability Database Status:");
    eprintln!("  Path:        {}", resolved_path.display());
    eprintln!("  Records:     {record_count}");
    eprintln!("  Ecosystems:  {eco_count}");

    Ok(())
}

fn resolve_db_path(custom: Option<&Path>) -> Result<PathBuf> {
    match custom {
        Some(p) => Ok(p.to_path_buf()),
        None => db::default_db_path().context("could not determine default database path"),
    }
}
