use crate::models::component::Component;
use crate::models::vulnerability::VulnRecord;

use super::db::VulnDb;
use super::VulnError;

/// Match a component against the vulnerability database.
///
/// Strategy:
/// 1. Try PURL match first (most precise).
/// 2. Fall back to ecosystem + name match.
/// 3. Filter results by version (if component has a version).
pub fn find_vulnerabilities(
    db: &VulnDb,
    component: &Component,
) -> Result<Vec<VulnRecord>, VulnError> {
    let mut candidates = Vec::new();

    // Strategy 1: PURL match (strip version from PURL for broader matching)
    if let Some(purl) = &component.purl {
        let base_purl = strip_purl_version(purl);
        let found = db.find_by_purl(&base_purl)?;
        candidates.extend(found);
    }

    // Strategy 2: ecosystem + name fallback (if PURL match yielded nothing)
    if candidates.is_empty() {
        if let (Some(ecosystem), name) = (&component.ecosystem, &component.name) {
            let found = db.find_by_package(ecosystem, name)?;
            candidates.extend(found);
        }
    }

    // Filter by version if available
    if let Some(version) = &component.version {
        candidates.retain(|vuln| is_version_affected(vuln, &component.name, version));
    }

    Ok(candidates)
}

/// Strip the version qualifier from a PURL.
/// "pkg:npm/lodash@4.17.21" -> "pkg:npm/lodash"
fn strip_purl_version(purl: &str) -> String {
    match purl.rfind('@') {
        Some(idx) => purl[..idx].to_string(),
        None => purl.to_string(),
    }
}

/// Check whether a specific version is affected by a vulnerability record.
///
/// Uses two strategies:
/// 1. Exact version list match (`affected.versions[]` contains the version).
/// 2. Range check: if the version is in the introduced..fixed range.
///    (Simplified: only exact string matching for now; semver comparison is a Phase 1 enhancement.)
fn is_version_affected(vuln: &VulnRecord, _name: &str, version: &str) -> bool {
    for affected in &vuln.affected {
        // Check explicit version list
        if affected.versions.iter().any(|v| v == version) {
            return true;
        }

        // Check ranges: if there's a range with `introduced` but no `fixed`,
        // or the version doesn't match `fixed`, consider it potentially affected.
        // This is a conservative check -- proper semver comparison is planned for Phase 1.
        for range in &affected.ranges {
            if range.introduced.is_some() {
                match &range.fixed {
                    Some(fixed) if fixed == version => return false,
                    Some(_) => {
                        // Version is not the fixed version. We can't do semver comparison
                        // yet, so conservatively mark as affected if introduced is "0" or
                        // the version appears before fixed alphabetically.
                        // For MVP: if there's an introduced range and no exact version list
                        // match, we flag it as potentially affected.
                        if affected.versions.is_empty() {
                            return true;
                        }
                    }
                    None => {
                        // No fix available -- all versions after introduced are affected.
                        if affected.versions.is_empty() {
                            return true;
                        }
                    }
                }
            }
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::component::ComponentType;
    use crate::models::vulnerability::{AffectedPackage, AffectedRange, Severity};

    fn make_db_with_vuln() -> VulnDb {
        let mut db = VulnDb::open_in_memory().unwrap();
        let record = VulnRecord {
            id: "GHSA-test-0001".into(),
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
                versions: vec!["4.17.20".into()],
                ranges: vec![AffectedRange {
                    range_type: "SEMVER".into(),
                    introduced: Some("0".into()),
                    fixed: Some("4.17.21".into()),
                    last_affected: None,
                }],
            }],
            references: vec![],
            modified: "2025-01-01T00:00:00Z".into(),
        };
        db.upsert_records(&[record]).unwrap();
        db
    }

    #[test]
    fn matches_by_purl_and_version() {
        let db = make_db_with_vuln();
        let component = Component {
            name: "lodash".into(),
            version: Some("4.17.20".into()),
            supplier: None,
            license: None,
            purl: Some("pkg:npm/lodash@4.17.20".into()),
            cpe: None,
            component_type: ComponentType::Library,
            ecosystem: Some("npm".into()),
            sha256: None,
        };

        let vulns = find_vulnerabilities(&db, &component).unwrap();
        assert_eq!(vulns.len(), 1);
        assert_eq!(vulns[0].id, "GHSA-test-0001");
    }

    #[test]
    fn fixed_version_not_affected() {
        let db = make_db_with_vuln();
        let component = Component {
            name: "lodash".into(),
            version: Some("4.17.21".into()),
            supplier: None,
            license: None,
            purl: Some("pkg:npm/lodash@4.17.21".into()),
            cpe: None,
            component_type: ComponentType::Library,
            ecosystem: Some("npm".into()),
            sha256: None,
        };

        let vulns = find_vulnerabilities(&db, &component).unwrap();
        assert!(vulns.is_empty());
    }

    #[test]
    fn fallback_to_ecosystem_name() {
        let db = make_db_with_vuln();
        let component = Component {
            name: "lodash".into(),
            version: Some("4.17.20".into()),
            supplier: None,
            license: None,
            purl: None,
            cpe: None,
            component_type: ComponentType::Library,
            ecosystem: Some("npm".into()),
            sha256: None,
        };

        let vulns = find_vulnerabilities(&db, &component).unwrap();
        assert_eq!(vulns.len(), 1);
    }

    #[test]
    fn strip_purl_version_works() {
        assert_eq!(
            strip_purl_version("pkg:npm/lodash@4.17.21"),
            "pkg:npm/lodash"
        );
        assert_eq!(strip_purl_version("pkg:npm/lodash"), "pkg:npm/lodash");
        assert_eq!(
            strip_purl_version("pkg:maven/org.example/lib@1.0"),
            "pkg:maven/org.example/lib"
        );
    }
}
