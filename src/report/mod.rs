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

/// Truncate to at most `max` characters (not bytes), appending "..." when cut.
/// Slicing by bytes would panic on multi-byte UTF-8 in advisory summaries.
pub(crate) fn truncate_chars(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let cut: String = s.chars().take(max.saturating_sub(3)).collect();
        format!("{}...", cut.trim_end())
    }
}

#[cfg(test)]
mod tests {
    use super::truncate_chars;

    #[test]
    fn truncate_short_string_unchanged() {
        assert_eq!(truncate_chars("hello", 10), "hello");
    }

    #[test]
    fn truncate_long_string_appends_ellipsis() {
        assert_eq!(truncate_chars("abcdefghij", 8), "abcde...");
    }

    #[test]
    fn truncate_multibyte_does_not_panic() {
        // 'é' is 2 bytes in UTF-8; byte slicing here would panic.
        let s = "é".repeat(100);
        let out = truncate_chars(&s, 10);
        assert!(out.ends_with("..."));
        assert_eq!(out.chars().count(), 10);
    }
}
