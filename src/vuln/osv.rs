use std::io::Read;

use crate::models::vulnerability::{
    AffectedPackage, AffectedRange, Reference, Severity, VulnRecord,
};

use super::VulnError;

/// Default ecosystems to download from OSV.
pub const DEFAULT_ECOSYSTEMS: &[&str] = &[
    "npm",
    "PyPI",
    "Maven",
    "crates.io",
    "Go",
    "NuGet",
    "RubyGems",
];

/// Download and parse OSV vulnerability data for a given ecosystem.
///
/// Returns parsed `VulnRecord`s. Uses the public Google Cloud Storage bucket:
/// `https://storage.googleapis.com/osv-vulnerabilities/{ecosystem}/all.zip`
pub fn download_ecosystem(ecosystem: &str) -> Result<Vec<VulnRecord>, VulnError> {
    let url = format!("https://storage.googleapis.com/osv-vulnerabilities/{ecosystem}/all.zip");

    tracing::info!("Downloading OSV data for {ecosystem} from {url}");

    let response = ureq::get(&url)
        .call()
        .map_err(|e| VulnError::Http(format!("failed to download {ecosystem}: {e}")))?;

    let mut body = Vec::new();
    response
        .into_reader()
        .read_to_end(&mut body)
        .map_err(VulnError::Io)?;

    parse_osv_zip(&body)
}

/// Parse an OSV ZIP archive (in memory) into vulnerability records.
pub fn parse_osv_zip(data: &[u8]) -> Result<Vec<VulnRecord>, VulnError> {
    let cursor = std::io::Cursor::new(data);
    let mut archive = zip::ZipArchive::new(cursor)?;
    let mut records = Vec::new();

    for i in 0..archive.len() {
        let mut file = archive.by_index(i)?;
        if !file.name().ends_with(".json") {
            continue;
        }

        let mut content = String::new();
        file.read_to_string(&mut content)?;

        match parse_osv_json(&content) {
            Ok(record) => records.push(record),
            Err(e) => {
                tracing::debug!("Skipping {}: {e}", file.name());
            }
        }
    }

    Ok(records)
}

/// Parse a single OSV JSON entry into a `VulnRecord`.
pub fn parse_osv_json(json: &str) -> Result<VulnRecord, VulnError> {
    let val: serde_json::Value = serde_json::from_str(json)?;

    let id = val
        .get("id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| VulnError::Other("missing 'id' field".into()))?
        .to_string();

    let aliases = val
        .get("aliases")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    let summary = val
        .get("summary")
        .and_then(|v| v.as_str())
        .map(String::from);

    let severity = val
        .get("severity")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(parse_severity).collect())
        .unwrap_or_default();

    let affected = val
        .get("affected")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(parse_affected).collect())
        .unwrap_or_default();

    let references = val
        .get("references")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(parse_reference).collect())
        .unwrap_or_default();

    let modified = val
        .get("modified")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();

    let withdrawn = val
        .get("withdrawn")
        .and_then(|v| v.as_str())
        .map(String::from);

    Ok(VulnRecord {
        id,
        aliases,
        summary,
        severity,
        affected,
        references,
        modified,
        withdrawn,
    })
}

fn parse_severity(val: &serde_json::Value) -> Option<Severity> {
    let severity_type = val.get("type").and_then(|v| v.as_str())?.to_string();
    let score_str = val.get("score").and_then(|v| v.as_str());
    let vector = score_str.map(String::from);

    let score = val.get("score").and_then(|v| v.as_f64()).or_else(|| {
        let s = score_str?;
        crate::cvss::base_score_v3(s).or_else(|| s.parse::<f64>().ok())
    });

    Some(Severity {
        score,
        severity_type,
        vector,
    })
}

fn parse_affected(val: &serde_json::Value) -> Option<AffectedPackage> {
    let pkg = val.get("package")?;
    let name = pkg.get("name")?.as_str()?.to_string();
    let ecosystem = pkg
        .get("ecosystem")
        .and_then(|v| v.as_str())
        .map(String::from);
    let purl = pkg.get("purl").and_then(|v| v.as_str()).map(String::from);

    let versions = val
        .get("versions")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    let ranges = val
        .get("ranges")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(parse_range).collect())
        .unwrap_or_default();

    Some(AffectedPackage {
        ecosystem,
        name,
        purl,
        versions,
        ranges,
    })
}

fn parse_range(val: &serde_json::Value) -> Option<AffectedRange> {
    let range_type = val.get("type")?.as_str()?.to_string();
    let events = val.get("events").and_then(|v| v.as_array())?;

    let mut introduced = None;
    let mut fixed = None;
    let mut last_affected = None;

    for event in events {
        if let Some(v) = event.get("introduced").and_then(|v| v.as_str()) {
            introduced = Some(v.to_string());
        }
        if let Some(v) = event.get("fixed").and_then(|v| v.as_str()) {
            fixed = Some(v.to_string());
        }
        if let Some(v) = event.get("last_affected").and_then(|v| v.as_str()) {
            last_affected = Some(v.to_string());
        }
    }

    Some(AffectedRange {
        range_type,
        introduced,
        fixed,
        last_affected,
    })
}

fn parse_reference(val: &serde_json::Value) -> Option<Reference> {
    let url = val.get("url")?.as_str()?.to_string();
    let ref_type = val.get("type").and_then(|v| v.as_str()).map(String::from);
    Some(Reference { ref_type, url })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_OSV: &str = r#"{
        "id": "GHSA-xxxx-yyyy-zzzz",
        "aliases": ["CVE-2025-9999"],
        "summary": "Test vulnerability in testpkg",
        "severity": [
            {"type": "CVSS_V3", "score": "7.5"}
        ],
        "affected": [
            {
                "package": {
                    "ecosystem": "npm",
                    "name": "testpkg",
                    "purl": "pkg:npm/testpkg"
                },
                "versions": ["1.0.0", "1.0.1"],
                "ranges": [
                    {
                        "type": "SEMVER",
                        "events": [
                            {"introduced": "0"},
                            {"fixed": "1.0.2"}
                        ]
                    }
                ]
            }
        ],
        "references": [
            {"type": "ADVISORY", "url": "https://example.com"}
        ],
        "modified": "2025-06-01T00:00:00Z"
    }"#;

    #[test]
    fn parse_single_osv_entry() {
        let record = parse_osv_json(SAMPLE_OSV).unwrap();
        assert_eq!(record.id, "GHSA-xxxx-yyyy-zzzz");
        assert_eq!(record.aliases, vec!["CVE-2025-9999"]);
        assert_eq!(record.affected.len(), 1);
        assert_eq!(record.affected[0].name, "testpkg");
        assert_eq!(record.affected[0].versions.len(), 2);
        assert_eq!(record.affected[0].ranges.len(), 1);
        assert_eq!(record.affected[0].ranges[0].fixed.as_deref(), Some("1.0.2"));
    }

    #[test]
    fn parse_osv_severity_string_score() {
        let record = parse_osv_json(SAMPLE_OSV).unwrap();
        assert_eq!(record.severity.len(), 1);
        assert_eq!(record.severity[0].score, Some(7.5));
    }

    #[test]
    fn parse_withdrawn_advisory() {
        let json = r#"{
            "id": "GHSA-withdrawn-test",
            "withdrawn": "2024-01-27T22:59:24Z",
            "affected": [],
            "references": [],
            "modified": "2025-06-01T00:00:00Z"
        }"#;
        let record = parse_osv_json(json).unwrap();
        assert_eq!(record.withdrawn.as_deref(), Some("2024-01-27T22:59:24Z"));

        let record = parse_osv_json(SAMPLE_OSV).unwrap();
        assert!(record.withdrawn.is_none());
    }

    #[test]
    fn parse_severity_with_cvss_vector() {
        let json = r#"{
            "id": "GHSA-vec-test",
            "severity": [
                {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
            ],
            "affected": [],
            "references": [],
            "modified": "2025-06-01T00:00:00Z"
        }"#;
        let record = parse_osv_json(json).unwrap();
        assert_eq!(record.severity.len(), 1);
        assert_eq!(record.severity[0].score, Some(9.8));
        assert_eq!(record.severity_label(), "CRITICAL");
    }
}
