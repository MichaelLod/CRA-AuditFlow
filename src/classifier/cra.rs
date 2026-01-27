use std::path::Path;

use serde::Deserialize;

use crate::models::assessment::{CraClassification, CraRiskClass};

use super::ClassifierError;

#[derive(Debug, Deserialize)]
struct CraRulesFile {
    category: Vec<CategoryEntry>,
}

#[derive(Debug, Clone, Deserialize)]
struct CategoryEntry {
    #[allow(dead_code)]
    id: String,
    #[allow(dead_code)]
    annex: String,
    class: String,
    name: String,
    keywords: Vec<String>,
    conformity_note: String,
    applicable_articles: Vec<String>,
}

pub struct CraRules {
    categories: Vec<CategoryEntry>,
}

/// Load CRA classification rules from a TOML file.
pub fn load_rules(path: &Path) -> Result<CraRules, ClassifierError> {
    let content = std::fs::read_to_string(path)?;
    load_rules_str(&content)
}

/// Load CRA classification rules from a TOML string (useful for testing).
pub fn load_rules_str(toml_str: &str) -> Result<CraRules, ClassifierError> {
    let parsed: CraRulesFile = toml::from_str(toml_str)?;
    Ok(CraRules {
        categories: parsed.category,
    })
}

/// Load the embedded default rules (compiled into the binary).
pub fn load_default_rules() -> CraRules {
    let toml_str = include_str!("../../data/cra_categories.toml");
    load_rules_str(toml_str).expect("embedded CRA rules must be valid TOML")
}

/// Classify a product based on its name and optional description.
///
/// Algorithm: check Critical first (most restrictive), then Class II, then Class I.
/// Returns the highest matching risk class.
pub fn classify_product(
    rules: &CraRules,
    name: &str,
    description: Option<&str>,
) -> CraClassification {
    let search_text = match description {
        Some(desc) => format!("{name} {desc}"),
        None => name.to_string(),
    };
    let search_lower = search_text.to_lowercase();

    // Check in order of severity: Critical > Class II > Class I
    let priority_order = ["critical", "class_ii", "class_i"];

    for target_class in &priority_order {
        for cat in &rules.categories {
            if cat.class != *target_class {
                continue;
            }

            let matched: Vec<String> = cat
                .keywords
                .iter()
                .filter(|kw| search_lower.contains(&kw.to_lowercase()))
                .cloned()
                .collect();

            if !matched.is_empty() {
                return CraClassification {
                    risk_class: parse_risk_class(&cat.class),
                    matched_category: Some(cat.name.clone()),
                    matched_keywords: matched,
                    applicable_articles: cat.applicable_articles.clone(),
                    conformity_note: cat.conformity_note.clone(),
                };
            }
        }
    }

    // No match -> Default
    CraClassification {
        risk_class: CraRiskClass::Default,
        matched_category: None,
        matched_keywords: vec![],
        applicable_articles: vec!["Article 32".into()],
        conformity_note: "Self-assessment based on essential requirements (Article 32)".into(),
    }
}

fn parse_risk_class(class_str: &str) -> CraRiskClass {
    match class_str {
        "critical" => CraRiskClass::Critical,
        "class_ii" => CraRiskClass::ImportantClassII,
        "class_i" => CraRiskClass::ImportantClassI,
        _ => CraRiskClass::Default,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules() -> CraRules {
        load_default_rules()
    }

    #[test]
    fn classifies_critical_hsm() {
        let result = classify_product(&rules(), "Enterprise HSM Appliance", None);
        assert_eq!(result.risk_class, CraRiskClass::Critical);
        assert!(result.matched_keywords.contains(&"HSM".to_string()));
    }

    #[test]
    fn classifies_critical_smart_meter() {
        let result = classify_product(
            &rules(),
            "GridLink",
            Some("smart meter gateway for AMI systems"),
        );
        assert_eq!(result.risk_class, CraRiskClass::Critical);
    }

    #[test]
    fn classifies_critical_smartcard() {
        let result = classify_product(&rules(), "SecureID Smart Card", None);
        assert_eq!(result.risk_class, CraRiskClass::Critical);
    }

    #[test]
    fn classifies_class_ii_firewall() {
        let result = classify_product(&rules(), "NetGuard Firewall Pro", None);
        assert_eq!(result.risk_class, CraRiskClass::ImportantClassII);
    }

    #[test]
    fn classifies_class_ii_hypervisor() {
        let result = classify_product(&rules(), "CloudVM Hypervisor", None);
        assert_eq!(result.risk_class, CraRiskClass::ImportantClassII);
    }

    #[test]
    fn classifies_class_ii_container_runtime() {
        let result = classify_product(
            &rules(),
            "PodEngine",
            Some("a lightweight container runtime for Kubernetes"),
        );
        assert_eq!(result.risk_class, CraRiskClass::ImportantClassII);
    }

    #[test]
    fn classifies_class_i_browser() {
        let result = classify_product(&rules(), "FreedomBrowser", Some("a web browser for Linux"));
        assert_eq!(result.risk_class, CraRiskClass::ImportantClassI);
    }

    #[test]
    fn classifies_class_i_vpn() {
        let result = classify_product(&rules(), "PrivateLink VPN Client", None);
        assert_eq!(result.risk_class, CraRiskClass::ImportantClassI);
    }

    #[test]
    fn classifies_class_i_password_manager() {
        let result = classify_product(&rules(), "SafeKeys Password Manager", None);
        assert_eq!(result.risk_class, CraRiskClass::ImportantClassI);
    }

    #[test]
    fn classifies_class_i_os() {
        let result = classify_product(&rules(), "EuroLinux", Some("A European Linux distribution"));
        assert_eq!(result.risk_class, CraRiskClass::ImportantClassI);
    }

    #[test]
    fn classifies_class_i_router() {
        let result = classify_product(&rules(), "HomeConnect Router", None);
        assert_eq!(result.risk_class, CraRiskClass::ImportantClassI);
    }

    #[test]
    fn classifies_class_i_siem() {
        let result = classify_product(&rules(), "LogSentry SIEM", None);
        assert_eq!(result.risk_class, CraRiskClass::ImportantClassI);
    }

    #[test]
    fn classifies_default_for_generic_tool() {
        let result = classify_product(&rules(), "My Todo App", Some("A simple task manager"));
        assert_eq!(result.risk_class, CraRiskClass::Default);
        assert!(result.matched_category.is_none());
        assert!(result.matched_keywords.is_empty());
    }

    #[test]
    fn critical_takes_priority_over_class_ii() {
        // "hardware security module" matches both Critical HSM and
        // Class II tamper-resistant; Critical should win.
        let result = classify_product(
            &rules(),
            "SecureVault",
            Some("hardware security module appliance"),
        );
        assert_eq!(result.risk_class, CraRiskClass::Critical);
    }

    #[test]
    fn loads_default_rules_successfully() {
        let r = rules();
        assert!(r.categories.len() >= 26);
    }
}
