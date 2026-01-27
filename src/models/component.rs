use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum ComponentType {
    #[default]
    Library,
    Framework,
    Application,
    Device,
    Firmware,
    OperatingSystem,
    Container,
    Other(String),
}

impl fmt::Display for ComponentType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Library => write!(f, "library"),
            Self::Framework => write!(f, "framework"),
            Self::Application => write!(f, "application"),
            Self::Device => write!(f, "device"),
            Self::Firmware => write!(f, "firmware"),
            Self::OperatingSystem => write!(f, "operating-system"),
            Self::Container => write!(f, "container"),
            Self::Other(s) => write!(f, "{s}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SbomFormat {
    CycloneDx,
    Spdx,
}

impl fmt::Display for SbomFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CycloneDx => write!(f, "CycloneDX"),
            Self::Spdx => write!(f, "SPDX"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Component {
    pub name: String,
    pub version: Option<String>,
    pub supplier: Option<String>,
    pub license: Option<String>,
    pub purl: Option<String>,
    pub cpe: Option<String>,
    pub component_type: ComponentType,
    pub ecosystem: Option<String>,
    pub sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SbomDocument {
    pub format: SbomFormat,
    pub spec_version: String,
    pub document_name: Option<String>,
    pub components: Vec<Component>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn component_type_display() {
        assert_eq!(ComponentType::Library.to_string(), "library");
        assert_eq!(ComponentType::Other("plugin".into()).to_string(), "plugin");
    }

    #[test]
    fn sbom_format_display() {
        assert_eq!(SbomFormat::CycloneDx.to_string(), "CycloneDX");
        assert_eq!(SbomFormat::Spdx.to_string(), "SPDX");
    }
}
