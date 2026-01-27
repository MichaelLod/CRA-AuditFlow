use serde_json::Value;

use crate::models::component::{Component, ComponentType, SbomDocument, SbomFormat};

use super::cyclonedx::extract_ecosystem_from_purl;
use super::SbomError;

pub fn parse_spdx(root: &Value) -> Result<SbomDocument, SbomError> {
    let spec_version = root
        .get("spdxVersion")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();

    let document_name = root.get("name").and_then(|v| v.as_str()).map(String::from);

    let components = root
        .get("packages")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(parse_package).collect())
        .unwrap_or_default();

    Ok(SbomDocument {
        format: SbomFormat::Spdx,
        spec_version,
        document_name,
        components,
    })
}

fn parse_package(val: &Value) -> Option<Component> {
    let name = val.get("name")?.as_str()?.to_string();
    let version = val
        .get("versionInfo")
        .and_then(|v| v.as_str())
        .map(String::from);

    let supplier = val
        .get("supplier")
        .and_then(|v| v.as_str())
        .map(|s| s.strip_prefix("Organization: ").unwrap_or(s))
        .map(String::from);

    let license = val
        .get("licenseDeclared")
        .and_then(|v| v.as_str())
        .filter(|&l| l != "NOASSERTION")
        .map(String::from);

    let (purl, cpe) = extract_external_refs(val);
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
        component_type: ComponentType::Library,
        ecosystem,
        sha256,
    })
}

fn extract_external_refs(val: &Value) -> (Option<String>, Option<String>) {
    let refs = match val.get("externalRefs").and_then(|v| v.as_array()) {
        Some(arr) => arr,
        None => return (None, None),
    };

    let mut purl = None;
    let mut cpe = None;

    for r in refs {
        let ref_type = r
            .get("referenceType")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        let locator = r
            .get("referenceLocator")
            .and_then(|v| v.as_str())
            .map(String::from);

        match ref_type {
            "purl" => purl = locator,
            "cpe23Type" | "cpe22Type" => cpe = locator,
            _ => {}
        }
    }

    (purl, cpe)
}

fn extract_sha256(val: &Value) -> Option<String> {
    val.get("checksums")
        .and_then(|v| v.as_array())
        .and_then(|arr| {
            arr.iter().find_map(|c| {
                let alg = c.get("algorithm").and_then(|a| a.as_str())?;
                if alg.eq_ignore_ascii_case("SHA256") {
                    c.get("checksumValue")
                        .and_then(|v| v.as_str())
                        .map(String::from)
                } else {
                    None
                }
            })
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_organization_prefix() {
        let val = serde_json::json!({
            "name": "test",
            "supplier": "Organization: Acme Corp"
        });
        let comp = parse_package(&val).unwrap();
        assert_eq!(comp.supplier.as_deref(), Some("Acme Corp"));
    }

    #[test]
    fn noassertion_license_is_none() {
        let val = serde_json::json!({
            "name": "test",
            "licenseDeclared": "NOASSERTION"
        });
        let comp = parse_package(&val).unwrap();
        assert!(comp.license.is_none());
    }
}
