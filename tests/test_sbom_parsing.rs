use std::path::PathBuf;

use cra_auditflow::models::component::{ComponentType, SbomFormat};
use cra_auditflow::sbom;

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}

#[test]
fn cyclonedx_parses_all_components() {
    let doc = sbom::parse_sbom(&fixture_path("cyclonedx_minimal.json")).unwrap();
    assert_eq!(doc.format, SbomFormat::CycloneDx);
    assert_eq!(doc.spec_version, "1.5");
    assert_eq!(doc.document_name.as_deref(), Some("my-application"));
    assert_eq!(doc.components.len(), 3);

    // serde (cargo)
    let serde = &doc.components[0];
    assert_eq!(serde.name, "serde");
    assert_eq!(serde.version.as_deref(), Some("1.0.200"));
    assert_eq!(serde.purl.as_deref(), Some("pkg:cargo/serde@1.0.200"));
    assert_eq!(serde.license.as_deref(), Some("MIT"));
    assert_eq!(serde.supplier.as_deref(), Some("David Tolnay"));
    assert_eq!(serde.ecosystem.as_deref(), Some("cargo"));
    assert_eq!(serde.component_type, ComponentType::Library);
    assert_eq!(serde.sha256.as_deref(), Some("abc123def456"));

    // lodash (npm)
    let lodash = &doc.components[1];
    assert_eq!(lodash.name, "lodash");
    assert_eq!(lodash.ecosystem.as_deref(), Some("npm"));

    // spring-boot (maven)
    let spring = &doc.components[2];
    assert_eq!(spring.name, "spring-boot");
    assert_eq!(spring.component_type, ComponentType::Framework);
    assert_eq!(spring.ecosystem.as_deref(), Some("maven"));
}

#[test]
fn spdx_parses_all_packages() {
    let doc = sbom::parse_sbom(&fixture_path("spdx_minimal.json")).unwrap();
    assert_eq!(doc.format, SbomFormat::Spdx);
    assert_eq!(doc.spec_version, "SPDX-2.3");
    assert_eq!(doc.document_name.as_deref(), Some("my-spdx-document"));
    assert_eq!(doc.components.len(), 3);

    // serde
    let serde = &doc.components[0];
    assert_eq!(serde.name, "serde");
    assert_eq!(serde.version.as_deref(), Some("1.0.200"));
    assert_eq!(serde.purl.as_deref(), Some("pkg:cargo/serde@1.0.200"));
    assert_eq!(serde.license.as_deref(), Some("MIT"));
    assert_eq!(serde.supplier.as_deref(), Some("David Tolnay"));
    assert_eq!(serde.sha256.as_deref(), Some("abc123def456"));

    // spring-boot with CPE
    let spring = &doc.components[2];
    assert_eq!(spring.name, "spring-boot");
    assert!(spring.cpe.as_ref().unwrap().contains("cpe:2.3"));
}

#[test]
fn both_formats_produce_consistent_output() {
    let cdx = sbom::parse_sbom(&fixture_path("cyclonedx_minimal.json")).unwrap();
    let spdx = sbom::parse_sbom(&fixture_path("spdx_minimal.json")).unwrap();

    // Both have 3 components
    assert_eq!(cdx.components.len(), spdx.components.len());

    // Same component names
    for (c, s) in cdx.components.iter().zip(spdx.components.iter()) {
        assert_eq!(c.name, s.name);
        assert_eq!(c.version, s.version);
    }
}
