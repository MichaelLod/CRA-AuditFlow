use serde_json::Value;

use crate::models::component::{Component, ComponentType, SbomDocument, SbomFormat};

use super::SbomError;

pub fn parse_cyclonedx(root: &Value) -> Result<SbomDocument, SbomError> {
    let spec_version = root
        .get("specVersion")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();

    let document_name = root
        .pointer("/metadata/component/name")
        .and_then(|v| v.as_str())
        .map(String::from);

    let components = root
        .get("components")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(parse_component).collect())
        .unwrap_or_default();

    Ok(SbomDocument {
        format: SbomFormat::CycloneDx,
        spec_version,
        document_name,
        components,
    })
}

fn parse_component(val: &Value) -> Option<Component> {
    let name = val.get("name")?.as_str()?.to_string();
    let version = val
        .get("version")
        .and_then(|v| v.as_str())
        .map(String::from);
    let supplier = val
        .pointer("/supplier/name")
        .and_then(|v| v.as_str())
        .map(String::from);
    let purl = val.get("purl").and_then(|v| v.as_str()).map(String::from);
    let cpe = val.get("cpe").and_then(|v| v.as_str()).map(String::from);
    let license = extract_license(val);
    let component_type = parse_component_type(val.get("type").and_then(|v| v.as_str()));
    let ecosystem = purl
        .as_deref()
        .and_then(extract_ecosystem_from_purl)
        .map(String::from);
    let sha256 = extract_sha256(val);

    Some(Component {
        name,
        version,
        supplier,
        license,
        purl,
        cpe,
        component_type,
        ecosystem,
        sha256,
    })
}

fn extract_license(val: &Value) -> Option<String> {
    val.get("licenses")
        .and_then(|v| v.as_array())
        .and_then(|arr| arr.first())
        .and_then(|entry| {
            entry
                .pointer("/license/id")
                .or_else(|| entry.pointer("/license/name"))
                .or_else(|| entry.get("expression"))
                .and_then(|v| v.as_str())
                .map(String::from)
        })
}

fn parse_component_type(type_str: Option<&str>) -> ComponentType {
    match type_str {
        Some("library") => ComponentType::Library,
        Some("framework") => ComponentType::Framework,
        Some("application") => ComponentType::Application,
        Some("device") => ComponentType::Device,
        Some("firmware") => ComponentType::Firmware,
        Some("operating-system") => ComponentType::OperatingSystem,
        Some("container") => ComponentType::Container,
        Some(other) => ComponentType::Other(other.to_string()),
        None => ComponentType::default(),
    }
}

fn extract_sha256(val: &Value) -> Option<String> {
    val.get("hashes")
        .and_then(|v| v.as_array())
        .and_then(|arr| {
            arr.iter().find_map(|h| {
                let alg = h.get("alg").and_then(|a| a.as_str())?;
                if alg.eq_ignore_ascii_case("SHA-256") {
                    h.get("content").and_then(|c| c.as_str()).map(String::from)
                } else {
                    None
                }
            })
        })
}

/// Extract the ecosystem from a PURL string (e.g., "pkg:npm/lodash@1.0" -> "npm").
pub(crate) fn extract_ecosystem_from_purl(purl: &str) -> Option<&str> {
    let without_scheme = purl.strip_prefix("pkg:")?;
    without_scheme.split('/').next()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ecosystem_extraction() {
        assert_eq!(
            extract_ecosystem_from_purl("pkg:npm/lodash@4.17.21"),
            Some("npm")
        );
        assert_eq!(
            extract_ecosystem_from_purl("pkg:maven/org.springframework.boot/spring-boot@3.2.0"),
            Some("maven")
        );
        assert_eq!(
            extract_ecosystem_from_purl("pkg:cargo/serde@1.0.200"),
            Some("cargo")
        );
        assert_eq!(extract_ecosystem_from_purl("not-a-purl"), None);
    }

    #[test]
    fn parse_component_type_variants() {
        assert_eq!(
            parse_component_type(Some("library")),
            ComponentType::Library
        );
        assert_eq!(
            parse_component_type(Some("framework")),
            ComponentType::Framework
        );
        assert_eq!(parse_component_type(None), ComponentType::Library);
        assert_eq!(
            parse_component_type(Some("custom")),
            ComponentType::Other("custom".into())
        );
    }
}
