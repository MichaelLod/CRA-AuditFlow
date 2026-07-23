use std::str::FromStr;

use crate::models::component::Component;
use crate::models::vulnerability::{AffectedPackage, VulnRecord};

use super::db::VulnDb;
use super::VulnError;

/// Match a component against the vulnerability database.
///
/// Strategy:
/// 1. Try PURL match first (most precise).
/// 2. Fall back to ecosystem + name match.
/// 3. Drop advisories withdrawn upstream.
/// 4. Filter results by version (if component has a version).
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
        if let Some(ecosystem) = &component.ecosystem {
            let canonical_name = component
                .purl
                .as_deref()
                .and_then(extract_canonical_name_from_purl)
                .unwrap_or_else(|| component.name.clone());
            let found = db.find_by_package(ecosystem, &canonical_name)?;
            candidates.extend(found);
        }
    }

    // Withdrawn advisories are no longer valid findings
    candidates.retain(|vuln| vuln.withdrawn.is_none());

    // Filter by version if available
    if let Some(version) = &component.version {
        candidates.retain(|vuln| {
            is_version_affected(vuln, &component.name, version, component.purl.as_deref())
        });
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

/// Extract the canonical package name from a PURL string.
///
/// For scoped packages (e.g. `pkg:npm/%40types/react-dom`), reconstructs the
/// full name (`@types/react-dom`) from namespace + name. Returns just the name
/// for unscoped packages.
fn extract_canonical_name_from_purl(purl_str: &str) -> Option<String> {
    let purl = packageurl::PackageUrl::from_str(purl_str).ok()?;
    match purl.namespace() {
        Some(ns) => Some(format!("{ns}/{}", purl.name())),
        None => Some(purl.name().to_string()),
    }
}

/// Parse a version string leniently into a `semver::Version`.
///
/// Handles shortened forms: `"0"` -> `0.0.0`, `"1.2"` -> `1.2.0`, as well as
/// standard semver strings.
fn parse_semver_lenient(version: &str) -> Option<semver::Version> {
    if let Ok(v) = semver::Version::parse(version) {
        return Some(v);
    }
    let parts: Vec<&str> = version.split('.').collect();
    match parts.len() {
        1 => {
            let major: u64 = parts[0].parse().ok()?;
            Some(semver::Version::new(major, 0, 0))
        }
        2 => {
            let major: u64 = parts[0].parse().ok()?;
            let minor: u64 = parts[1].parse().ok()?;
            Some(semver::Version::new(major, minor, 0))
        }
        _ => None,
    }
}

/// Check whether `version` falls within a semver range.
///
/// Returns `Some(true)` if `introduced <= version < fixed` (or `<= last_affected`),
/// `Some(false)` if outside the range, or `None` if any version string is unparseable.
fn is_in_semver_range(
    version: &str,
    introduced: Option<&str>,
    fixed: Option<&str>,
    last_affected: Option<&str>,
) -> Option<bool> {
    let ver = parse_semver_lenient(version)?;

    if let Some(intro) = introduced {
        let intro_ver = parse_semver_lenient(intro)?;
        if ver < intro_ver {
            return Some(false);
        }
    }

    if let Some(fix) = fixed {
        let fix_ver = parse_semver_lenient(fix)?;
        return Some(ver < fix_ver);
    }

    if let Some(last) = last_affected {
        let last_ver = parse_semver_lenient(last)?;
        return Some(ver <= last_ver);
    }

    // No upper bound — all versions after introduced are affected.
    Some(true)
}

/// Check whether an `AffectedPackage` entry matches the given component by PURL
/// or by name fallback.
fn matches_component(
    affected: &AffectedPackage,
    component_purl: Option<&str>,
    component_name: &str,
) -> bool {
    if let (Some(c_purl), Some(a_purl)) = (component_purl, &affected.purl) {
        let c_base = strip_purl_version(c_purl);
        let a_base = strip_purl_version(a_purl);
        return c_base == a_base;
    }
    affected.name == component_name
}

/// Check whether a specific version is affected by a vulnerability record.
///
/// Filters affected entries by component match, then checks:
/// 1. Explicit version lists.
/// 2. SEMVER ranges using proper semver comparison.
/// 3. Non-SEMVER ranges (ECOSYSTEM, GIT) with conservative behavior.
fn is_version_affected(
    vuln: &VulnRecord,
    component_name: &str,
    version: &str,
    component_purl: Option<&str>,
) -> bool {
    for affected in &vuln.affected {
        if !matches_component(affected, component_purl, component_name) {
            continue;
        }

        // Check explicit version list
        if affected.versions.iter().any(|v| v == version) {
            return true;
        }

        // Check ranges
        for range in &affected.ranges {
            if range.introduced.is_none() {
                continue;
            }

            if range.range_type == "SEMVER" {
                match is_in_semver_range(
                    version,
                    range.introduced.as_deref(),
                    range.fixed.as_deref(),
                    range.last_affected.as_deref(),
                ) {
                    Some(true) => return true,
                    Some(false) => continue,
                    None => {
                        // Unparseable — conservative fallback
                        if affected.versions.is_empty() {
                            return true;
                        }
                    }
                }
            } else {
                // Non-SEMVER ranges: conservative behavior
                match &range.fixed {
                    Some(fixed) if fixed == version => return false,
                    Some(_) => {
                        if affected.versions.is_empty() {
                            return true;
                        }
                    }
                    None => {
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
            withdrawn: None,
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
    fn withdrawn_advisory_excluded() {
        let mut db = VulnDb::open_in_memory().unwrap();
        let record = VulnRecord {
            id: "GHSA-withdrawn-0001".into(),
            aliases: vec![],
            summary: Some("Later disputed and withdrawn".into()),
            severity: vec![],
            affected: vec![AffectedPackage {
                ecosystem: Some("npm".into()),
                name: "lodash".into(),
                purl: Some("pkg:npm/lodash".into()),
                versions: vec!["4.17.20".into()],
                ranges: vec![],
            }],
            references: vec![],
            modified: "2025-01-01T00:00:00Z".into(),
            withdrawn: Some("2025-03-01T00:00:00Z".into()),
        };
        db.upsert_records(&[record]).unwrap();

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
        assert!(vulns.is_empty());
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

    #[test]
    fn extract_canonical_name_scoped() {
        assert_eq!(
            extract_canonical_name_from_purl("pkg:npm/%40types/react-dom@1.0.0"),
            Some("@types/react-dom".into())
        );
    }

    #[test]
    fn extract_canonical_name_unscoped() {
        assert_eq!(
            extract_canonical_name_from_purl("pkg:npm/lodash@4.17.21"),
            Some("lodash".into())
        );
    }

    #[test]
    fn semver_lenient_parsing() {
        assert_eq!(
            parse_semver_lenient("0"),
            Some(semver::Version::new(0, 0, 0))
        );
        assert_eq!(
            parse_semver_lenient("1.2"),
            Some(semver::Version::new(1, 2, 0))
        );
        assert_eq!(
            parse_semver_lenient("4.17.21"),
            Some(semver::Version::new(4, 17, 21))
        );
        assert_eq!(parse_semver_lenient("not-a-version"), None);
    }

    #[test]
    fn semver_range_check() {
        // 4.17.20 is in [0, 4.17.21)
        assert_eq!(
            is_in_semver_range("4.17.20", Some("0"), Some("4.17.21"), None),
            Some(true)
        );
        // 4.17.21 is NOT in [0, 4.17.21)
        assert_eq!(
            is_in_semver_range("4.17.21", Some("0"), Some("4.17.21"), None),
            Some(false)
        );
        // 16.0.3 is NOT in [0, 13.0.0)
        assert_eq!(
            is_in_semver_range("16.0.3", Some("0"), Some("13.0.0"), None),
            Some(false)
        );
    }

    #[test]
    fn version_not_affected_when_above_fixed_semver() {
        let vuln = VulnRecord {
            id: "GHSA-next-0001".into(),
            aliases: vec![],
            summary: Some("Vuln fixed in next@13.0.0".into()),
            severity: vec![],
            affected: vec![AffectedPackage {
                ecosystem: Some("npm".into()),
                name: "next".into(),
                purl: Some("pkg:npm/next".into()),
                versions: vec![],
                ranges: vec![AffectedRange {
                    range_type: "SEMVER".into(),
                    introduced: Some("0".into()),
                    fixed: Some("13.0.0".into()),
                    last_affected: None,
                }],
            }],
            references: vec![],
            modified: "2025-01-01T00:00:00Z".into(),
            withdrawn: None,
        };
        // v16.0.3 is above the fix — not affected
        assert!(!is_version_affected(
            &vuln,
            "next",
            "16.0.3",
            Some("pkg:npm/next@16.0.3")
        ));
        // v12.0.0 is below the fix — affected
        assert!(is_version_affected(
            &vuln,
            "next",
            "12.0.0",
            Some("pkg:npm/next@12.0.0")
        ));
    }

    #[test]
    fn types_package_not_matched_to_real_package() {
        let vuln = VulnRecord {
            id: "GHSA-real-0001".into(),
            aliases: vec![],
            summary: Some("Vuln in react-dom".into()),
            severity: vec![],
            affected: vec![AffectedPackage {
                ecosystem: Some("npm".into()),
                name: "react-dom".into(),
                purl: Some("pkg:npm/react-dom".into()),
                versions: vec!["16.0.0".into()],
                ranges: vec![],
            }],
            references: vec![],
            modified: "2025-01-01T00:00:00Z".into(),
            withdrawn: None,
        };
        // @types/react-dom should NOT match react-dom advisory
        assert!(!is_version_affected(
            &vuln,
            "@types/react-dom",
            "16.0.0",
            Some("pkg:npm/%40types/react-dom@16.0.0")
        ));
        // real react-dom SHOULD match
        assert!(is_version_affected(
            &vuln,
            "react-dom",
            "16.0.0",
            Some("pkg:npm/react-dom@16.0.0")
        ));
    }
}
