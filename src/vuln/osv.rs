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

    Ok(VulnRecord {
        id,
        aliases,
        summary,
        severity,
        affected,
        references,
        modified,
    })
}

fn parse_severity(val: &serde_json::Value) -> Option<Severity> {
    let severity_type = val.get("type").and_then(|v| v.as_str())?.to_string();
    let score_str = val.get("score").and_then(|v| v.as_str());
    let vector = score_str.map(String::from);

    let score = val
        .get("score")
        .and_then(|v| v.as_f64())
        .or_else(|| {
            let s = score_str?;
            compute_cvss3_base_score(s).or_else(|| s.parse::<f64>().ok())
        });

    Some(Severity {
        score,
        severity_type,
        vector,
    })
}

/// CVSS v3.1 spec "Roundup": smallest number to one decimal place >= input.
fn roundup(x: f64) -> f64 {
    let int_input = (x * 100_000.0).round() as i64;
    if int_input % 10_000 == 0 {
        int_input as f64 / 100_000.0
    } else {
        ((int_input / 10_000) + 1) as f64 / 10.0
    }
}

/// Compute a CVSS v3.x base score from a vector string.
///
/// Parses the 8 base metrics (AV, AC, PR, UI, S, C, I, A) and applies the
/// deterministic formula from the CVSS v3.1 specification.
fn compute_cvss3_base_score(vector: &str) -> Option<f64> {
    if !vector.starts_with("CVSS:3") {
        return None;
    }

    let mut av = None;
    let mut ac = None;
    let mut pr_raw = None;
    let mut ui = None;
    let mut scope = None;
    let mut c = None;
    let mut i_val = None;
    let mut a = None;

    for part in vector.split('/') {
        let mut kv = part.splitn(2, ':');
        let key = match kv.next() {
            Some(k) => k,
            None => continue,
        };
        let val = match kv.next() {
            Some(v) => v,
            None => continue,
        };
        match key {
            "AV" => av = Some(val),
            "AC" => ac = Some(val),
            "PR" => pr_raw = Some(val),
            "UI" => ui = Some(val),
            "S" => scope = Some(val),
            "C" => c = Some(val),
            "I" => i_val = Some(val),
            "A" => a = Some(val),
            _ => {}
        }
    }

    let av = match av? {
        "N" => 0.85,
        "A" => 0.62,
        "L" => 0.55,
        "P" => 0.20,
        _ => return None,
    };
    let ac = match ac? {
        "L" => 0.77,
        "H" => 0.44,
        _ => return None,
    };
    let scope_changed = match scope? {
        "U" => false,
        "C" => true,
        _ => return None,
    };
    let pr = match (pr_raw?, scope_changed) {
        ("N", _) => 0.85,
        ("L", false) => 0.62,
        ("L", true) => 0.68,
        ("H", false) => 0.27,
        ("H", true) => 0.50,
        _ => return None,
    };
    let ui = match ui? {
        "N" => 0.85,
        "R" => 0.62,
        _ => return None,
    };
    let c = match c? {
        "H" => 0.56,
        "L" => 0.22,
        "N" => 0.0,
        _ => return None,
    };
    let i_val = match i_val? {
        "H" => 0.56,
        "L" => 0.22,
        "N" => 0.0,
        _ => return None,
    };
    let a = match a? {
        "H" => 0.56,
        "L" => 0.22,
        "N" => 0.0,
        _ => return None,
    };

    let iss: f64 = 1.0 - ((1.0 - c) * (1.0 - i_val) * (1.0 - a));

    let impact = if scope_changed {
        7.52 * (iss - 0.029) - 3.25 * (iss - 0.02).powf(15.0)
    } else {
        6.42 * iss
    };

    if impact <= 0.0 {
        return Some(0.0);
    }

    let exploitability = 8.22 * av * ac * pr * ui;

    let base = if scope_changed {
        roundup(f64::min(1.08 * (impact + exploitability), 10.0))
    } else {
        roundup(f64::min(impact + exploitability, 10.0))
    };

    Some(base)
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
    fn compute_cvss3_vector_score() {
        // CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H -> 9.8 (Critical)
        let score = compute_cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
        assert_eq!(score, Some(9.8));

        // CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N -> 6.1 (Medium)
        let score = compute_cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
        assert_eq!(score, Some(6.1));

        // Not a CVSS v3 vector
        assert_eq!(compute_cvss3_base_score("not-a-vector"), None);
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
