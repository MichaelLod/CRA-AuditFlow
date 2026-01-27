mod cyclonedx;
mod spdx;

use std::path::Path;

use thiserror::Error;

use crate::models::component::SbomDocument;

#[derive(Debug, Error)]
pub enum SbomError {
    #[error("failed to read file: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("unrecognized SBOM format: no 'bomFormat' or 'spdxVersion' key found")]
    UnrecognizedFormat,
    #[error("parse error: {0}")]
    Parse(String),
}

/// Auto-detect the SBOM format and parse into a unified `SbomDocument`.
pub fn parse_sbom(path: &Path) -> Result<SbomDocument, SbomError> {
    let content = std::fs::read_to_string(path)?;
    parse_sbom_str(&content)
}

/// Parse an SBOM from a JSON string (useful for testing).
pub fn parse_sbom_str(json: &str) -> Result<SbomDocument, SbomError> {
    let value: serde_json::Value = serde_json::from_str(json)?;

    if value.get("bomFormat").and_then(|v| v.as_str()) == Some("CycloneDX") {
        cyclonedx::parse_cyclonedx(&value)
    } else if value.get("spdxVersion").is_some() {
        spdx::parse_spdx(&value)
    } else {
        Err(SbomError::UnrecognizedFormat)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn fixture_path(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join(name)
    }

    #[test]
    fn parse_cyclonedx_file() {
        let doc = parse_sbom(&fixture_path("cyclonedx_minimal.json")).unwrap();
        assert_eq!(doc.format, crate::models::component::SbomFormat::CycloneDx);
        assert_eq!(doc.spec_version, "1.5");
        assert_eq!(doc.components.len(), 3);
        assert_eq!(doc.components[0].name, "serde");
        assert_eq!(doc.components[0].version.as_deref(), Some("1.0.200"));
        assert_eq!(doc.components[0].ecosystem.as_deref(), Some("cargo"));
    }

    #[test]
    fn parse_spdx_file() {
        let doc = parse_sbom(&fixture_path("spdx_minimal.json")).unwrap();
        assert_eq!(doc.format, crate::models::component::SbomFormat::Spdx);
        assert_eq!(doc.spec_version, "SPDX-2.3");
        assert_eq!(doc.components.len(), 3);
        assert_eq!(doc.components[2].name, "spring-boot");
        assert!(doc.components[2].cpe.is_some());
    }

    #[test]
    fn unrecognized_format() {
        let result = parse_sbom_str(r#"{"foo": "bar"}"#);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SbomError::UnrecognizedFormat));
    }

    #[test]
    fn invalid_json() {
        let result = parse_sbom_str("not json at all");
        assert!(result.is_err());
    }
}
