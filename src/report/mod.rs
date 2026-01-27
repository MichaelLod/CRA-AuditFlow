pub mod markdown;
pub mod plaintext;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ReportError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("formatting error: {0}")]
    Fmt(#[from] std::fmt::Error),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportFormat {
    Markdown,
    Plaintext,
}

impl ReportFormat {
    pub fn from_str_opt(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "markdown" | "md" => Some(Self::Markdown),
            "plaintext" | "text" | "txt" => Some(Self::Plaintext),
            _ => None,
        }
    }
}

use crate::models::assessment::AuditAssessment;

/// Render an audit assessment to a string in the specified format.
pub fn render(assessment: &AuditAssessment, format: ReportFormat) -> String {
    match format {
        ReportFormat::Markdown => markdown::render(assessment),
        ReportFormat::Plaintext => plaintext::render(assessment),
    }
}
