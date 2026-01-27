use assert_cmd::Command;
use predicates::prelude::*;

#[allow(deprecated)]
fn cmd() -> Command {
    Command::cargo_bin("cra-auditflow").unwrap()
}

#[test]
fn help_displays_usage() {
    cmd()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("CRA compliance pipeline"));
}

#[test]
fn version_flag() {
    cmd()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains("cra-auditflow"));
}

#[test]
fn audit_help() {
    cmd()
        .args(["audit", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("SBOM file"));
}

#[test]
fn sbom_validate_help() {
    cmd()
        .args(["sbom", "validate", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Validate"));
}

#[test]
fn vuln_update_help() {
    cmd()
        .args(["vuln", "update", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("ecosystems"));
}

#[test]
fn audit_missing_file_fails() {
    cmd()
        .args(["audit", "nonexistent.json"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("failed to parse SBOM"));
}

#[test]
fn sbom_validate_missing_file_fails() {
    cmd()
        .args(["sbom", "validate", "nonexistent.json"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("failed to parse SBOM"));
}

#[test]
fn audit_invalid_format_fails() {
    cmd()
        .args([
            "audit",
            "tests/fixtures/cyclonedx_minimal.json",
            "-f",
            "docx",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("unsupported report format"));
}

#[test]
fn sbom_validate_cyclonedx() {
    cmd()
        .args(["sbom", "validate", "tests/fixtures/cyclonedx_minimal.json"])
        .assert()
        .success()
        .stderr(predicate::str::contains("SBOM is valid"));
}

#[test]
fn sbom_validate_spdx() {
    cmd()
        .args(["sbom", "validate", "tests/fixtures/spdx_minimal.json"])
        .assert()
        .success()
        .stderr(predicate::str::contains("SBOM is valid"));
}

#[test]
fn audit_produces_markdown_output() {
    cmd()
        .args([
            "audit",
            "tests/fixtures/cyclonedx_minimal.json",
            "-n",
            "TestApp",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("# CRA Compliance Audit Report"));
}

#[test]
fn audit_produces_plaintext_output() {
    cmd()
        .args([
            "audit",
            "tests/fixtures/cyclonedx_minimal.json",
            "-n",
            "TestApp",
            "-f",
            "plaintext",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("CRA COMPLIANCE AUDIT REPORT"));
}

#[test]
fn audit_with_output_file() {
    let dir = tempfile::tempdir().unwrap();
    let output_path = dir.path().join("report.md");

    cmd()
        .args([
            "audit",
            "tests/fixtures/cyclonedx_minimal.json",
            "-n",
            "TestApp",
            "-o",
        ])
        .arg(&output_path)
        .assert()
        .success()
        .stderr(predicate::str::contains("Report written to"));

    let content = std::fs::read_to_string(&output_path).unwrap();
    assert!(content.contains("# CRA Compliance Audit Report"));
}

#[test]
fn vuln_status_no_db() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("nonexistent.db");

    cmd()
        .args(["vuln", "status", "--db-path"])
        .arg(&db_path)
        .assert()
        .success()
        .stderr(predicate::str::contains("No vulnerability database found"));
}
