use cra_auditflow::classifier::cra::{classify_product, load_default_rules};
use cra_auditflow::models::assessment::CraRiskClass;

#[test]
fn all_four_risk_tiers_classify_correctly() {
    let rules = load_default_rules();

    // Critical
    let crit = classify_product(&rules, "Enterprise HSM", None);
    assert_eq!(crit.risk_class, CraRiskClass::Critical);

    // Class II
    let class2 = classify_product(&rules, "NetGuard Firewall", None);
    assert_eq!(class2.risk_class, CraRiskClass::ImportantClassII);

    // Class I
    let class1 = classify_product(&rules, "SecurePass Password Manager", None);
    assert_eq!(class1.risk_class, CraRiskClass::ImportantClassI);

    // Default
    let default = classify_product(&rules, "My Calculator App", None);
    assert_eq!(default.risk_class, CraRiskClass::Default);
}

#[test]
fn description_contributes_to_classification() {
    let rules = load_default_rules();

    // Name alone doesn't classify
    let without = classify_product(&rules, "SecureGrid", None);
    assert_eq!(without.risk_class, CraRiskClass::Default);

    // Description pushes it into Class I
    let with = classify_product(
        &rules,
        "SecureGrid",
        Some("network management platform for enterprise routers"),
    );
    assert_eq!(with.risk_class, CraRiskClass::ImportantClassI);
}

#[test]
fn classification_is_case_insensitive() {
    let rules = load_default_rules();

    let upper = classify_product(&rules, "MY VPN CLIENT", None);
    assert_eq!(upper.risk_class, CraRiskClass::ImportantClassI);

    let lower = classify_product(&rules, "my vpn client", None);
    assert_eq!(lower.risk_class, CraRiskClass::ImportantClassI);
}

#[test]
fn default_classification_has_correct_fields() {
    let rules = load_default_rules();
    let result = classify_product(&rules, "Simple Notes App", None);

    assert_eq!(result.risk_class, CraRiskClass::Default);
    assert!(result.matched_category.is_none());
    assert!(result.matched_keywords.is_empty());
    assert!(!result.applicable_articles.is_empty());
    assert!(!result.conformity_note.is_empty());
}
