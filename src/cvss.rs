//! CVSS base score computation from vector strings.
//!
//! OSV records (notably GitHub Security Advisories) frequently carry a CVSS
//! vector string instead of a numeric score. This module implements the
//! deterministic base score formula from the CVSS v3.1 specification
//! (<https://www.first.org/cvss/v3.1/specification-document>), so severity can
//! be derived even when no numeric score is provided.

/// CVSS v3.1 spec "Roundup": smallest number to one decimal place >= input.
fn roundup(x: f64) -> f64 {
    let int_input = (x * 100_000.0).round() as i64;
    if int_input % 10_000 == 0 {
        int_input as f64 / 100_000.0
    } else {
        ((int_input / 10_000) + 1) as f64 / 10.0
    }
}

/// Compute a CVSS v3.x base score from a vector string.
///
/// Parses the 8 base metrics (AV, AC, PR, UI, S, C, I, A) and applies the
/// deterministic formula from the CVSS v3.1 specification. Returns `None` for
/// non-v3 vectors or vectors with missing/invalid base metrics.
pub fn base_score_v3(vector: &str) -> Option<f64> {
    if !vector.starts_with("CVSS:3") {
        return None;
    }

    let mut av = None;
    let mut ac = None;
    let mut pr_raw = None;
    let mut ui = None;
    let mut scope = None;
    let mut c = None;
    let mut i_val = None;
    let mut a = None;

    for part in vector.split('/') {
        let mut kv = part.splitn(2, ':');
        let key = match kv.next() {
            Some(k) => k,
            None => continue,
        };
        let val = match kv.next() {
            Some(v) => v,
            None => continue,
        };
        match key {
            "AV" => av = Some(val),
            "AC" => ac = Some(val),
            "PR" => pr_raw = Some(val),
            "UI" => ui = Some(val),
            "S" => scope = Some(val),
            "C" => c = Some(val),
            "I" => i_val = Some(val),
            "A" => a = Some(val),
            _ => {}
        }
    }

    let av = match av? {
        "N" => 0.85,
        "A" => 0.62,
        "L" => 0.55,
        "P" => 0.20,
        _ => return None,
    };
    let ac = match ac? {
        "L" => 0.77,
        "H" => 0.44,
        _ => return None,
    };
    let scope_changed = match scope? {
        "U" => false,
        "C" => true,
        _ => return None,
    };
    let pr = match (pr_raw?, scope_changed) {
        ("N", _) => 0.85,
        ("L", false) => 0.62,
        ("L", true) => 0.68,
        ("H", false) => 0.27,
        ("H", true) => 0.50,
        _ => return None,
    };
    let ui = match ui? {
        "N" => 0.85,
        "R" => 0.62,
        _ => return None,
    };
    let c = match c? {
        "H" => 0.56,
        "L" => 0.22,
        "N" => 0.0,
        _ => return None,
    };
    let i_val = match i_val? {
        "H" => 0.56,
        "L" => 0.22,
        "N" => 0.0,
        _ => return None,
    };
    let a = match a? {
        "H" => 0.56,
        "L" => 0.22,
        "N" => 0.0,
        _ => return None,
    };

    let iss: f64 = 1.0 - ((1.0 - c) * (1.0 - i_val) * (1.0 - a));

    let impact = if scope_changed {
        7.52 * (iss - 0.029) - 3.25 * (iss - 0.02).powf(15.0)
    } else {
        6.42 * iss
    };

    if impact <= 0.0 {
        return Some(0.0);
    }

    let exploitability = 8.22 * av * ac * pr * ui;

    let base = if scope_changed {
        roundup(f64::min(1.08 * (impact + exploitability), 10.0))
    } else {
        roundup(f64::min(impact + exploitability, 10.0))
    };

    Some(base)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_critical_vector() {
        // CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H -> 9.8 (Critical)
        let score = base_score_v3("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
        assert_eq!(score, Some(9.8));
    }

    #[test]
    fn scope_changed_medium_vector() {
        // CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N -> 6.1 (Medium)
        let score = base_score_v3("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
        assert_eq!(score, Some(6.1));
    }

    #[test]
    fn log4shell_maximum_vector() {
        // CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H -> 10.0 (log4shell)
        let score = base_score_v3("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
        assert_eq!(score, Some(10.0));
    }

    #[test]
    fn cvss30_prefix_accepted() {
        let score = base_score_v3("CVSS:3.0/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N");
        assert_eq!(score, Some(1.8));
    }

    #[test]
    fn no_impact_scores_zero() {
        let score = base_score_v3("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N");
        assert_eq!(score, Some(0.0));
    }

    #[test]
    fn rejects_non_v3_vectors() {
        assert_eq!(base_score_v3("not-a-vector"), None);
        assert_eq!(base_score_v3("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N"), None);
        assert_eq!(base_score_v3("CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P"), None);
    }

    #[test]
    fn rejects_missing_metrics() {
        assert_eq!(base_score_v3("CVSS:3.1/AV:N/AC:L"), None);
    }
}
