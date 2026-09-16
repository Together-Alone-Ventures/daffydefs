//! PROVISIONAL rendering of [`VerificationFacts`].
//!
//! Everything a person reads is produced here and only here, so the shared
//! output vocabulary can replace this module without touching verification.
//! Two rules hold regardless: the first result line is
//! `validity: PASS | FAIL | INCOMPLETE`, and no line consists of a bare `PASS`.

use crate::report::{CheckOutcome, ProtocolLine, TimingFact, Validity, VerificationFacts};

pub const PROVISIONAL_NOTICE: &str =
    "output format: PROVISIONAL (pending the shared output contract)";

/// JSON rendering: the facts as serialised, pretty-printed.
pub fn render_json(facts: &VerificationFacts) -> String {
    serde_json::to_string_pretty(facts).expect("verification facts serialise")
}

fn validity_word(v: Validity) -> &'static str {
    match v {
        Validity::Pass => "PASS",
        Validity::Fail => "FAIL",
        Validity::Incomplete => "INCOMPLETE",
    }
}

fn protocol_line(facts: &VerificationFacts) -> String {
    match (&facts.protocol_version, facts.protocol_line) {
        (Some(label), Some(line)) if line.is_historical() => format!("{label} (historical)"),
        (Some(label), Some(ProtocolLine::V5)) => label.clone(),
        _ => "unknown (intake rejected)".to_string(),
    }
}

fn check_line(name: &str, outcome: &CheckOutcome) -> String {
    match outcome {
        CheckOutcome::Pass { established } => format!("{name}: PASS — {established}"),
        CheckOutcome::Fail {
            error,
            detail: Some(d),
        } => format!("{name}: FAIL {error} — {d}"),
        CheckOutcome::Fail {
            error,
            detail: None,
        } => format!("{name}: FAIL {error}"),
        CheckOutcome::NotEvaluated { reason } => format!("{name}: NOT_EVALUATED — {reason}"),
    }
}

fn timing_line(t: &TimingFact) -> String {
    match t {
        TimingFact::V2CertificateTime {
            certificate_time_ns,
            receipt_timestamp_ns,
            delta_secs,
            warn_threshold_secs,
            exceeds_warning_threshold,
        } => format!(
            "V2 timing: certificate_time_ns={certificate_time_ns} receipt_time_ns={receipt_timestamp_ns} delta_secs={delta_secs:.3}{}",
            if *exceeds_warning_threshold {
                format!(" (warning: exceeds {warn_threshold_secs}s; set CVDR_V2_CERT_TIME_WARN_SECS to adjust)")
            } else {
                String::new()
            }
        ),
        TimingFact::V2CertificateTimeUnavailable { detail } => format!("V2 timing: {detail}"),
        TimingFact::V3aFinalizationDelay { delta_secs, max_finalization_delay_secs, verdict, .. } => match delta_secs {
            Some(d) => format!(
                "V3A timing: {verdict} — finalization delay {d:.1}s (threshold {max_finalization_delay_secs}s{})",
                if *verdict == "DELAY_EXCEEDED" { "; downgrade, not rejection" } else { "" }
            ),
            None => format!("V3A timing: {verdict} — module-hash certificate predates the bls certificate"),
        },
    }
}

/// Human rendering.
pub fn render_human(facts: &VerificationFacts) -> String {
    let mut out = vec![
        "============================================================".to_string(),
        " CVDR-Verify: MKTd02 receipt".to_string(),
        format!(" {PROVISIONAL_NOTICE}"),
        "============================================================".to_string(),
        format!("validity: {}", validity_word(facts.validity.validity)),
    ];
    if let Some(reason) = &facts.validity.reason {
        out.push(format!("  reason: {reason}"));
    }
    out.push("assurance:".to_string());
    out.push(format!("  source: {}", facts.source));
    out.push(format!("  protocol_line: {}", protocol_line(facts)));
    if let Some(e) = &facts.intake_error {
        out.push(format!("  intake_error: {e}"));
    }
    if let Some(id) = &facts.receipt_id {
        out.push(format!("  receipt_id: {id}"));
    }
    if let Some(c) = &facts.canister_id {
        out.push(format!("  canister_id: {c}"));
    }
    if let Some(s) = &facts.receipt_state {
        out.push(format!("  receipt_state: {s:?}"));
    }
    if let Some(root) = &facts.trust_root_used {
        out.push(format!("  trust_root: {} ({})", root.id, root.source));
    }
    if let Some(receipt_id) = &facts.receipt_trust_root_key_id {
        out.push(format!("  receipt trust_root_key_id: {:?}", receipt_id));
    }
    match &facts.trust_root_mismatch {
        Some(m) => out.push(format!(
            "  trust_root_mismatch: receipt says {:?}, verification used {} (warning)",
            m.receipt_says, m.verification_used
        )),
        None if facts.trust_root_used.is_some() => {
            out.push("  trust_root_mismatch: none".to_string())
        }
        None => {}
    }
    out.push(format!("  attestation_class: {}", facts.attestation_class));
    out.push(format!("  {}", check_line("V1", &facts.checks.v1)));
    out.push(format!("  {}", check_line("V2", &facts.checks.v2)));
    out.push(format!("  {}", check_line("V3A", &facts.checks.v3a)));
    out.push(format!("  {}", check_line("V3B", &facts.checks.v3b)));
    for t in &facts.timing {
        out.push(format!("    {}", timing_line(t)));
    }
    out.push("evidence established:".to_string());
    if facts.evidence_established.is_empty() {
        out.push("  (none)".to_string());
    }
    for e in &facts.evidence_established {
        out.push(format!("  - {e}"));
    }
    match &facts.diagnostics {
        None => out.push("diagnostics: not requested".to_string()),
        Some(diags) => {
            out.push("diagnostics (live, point-in-time; never affects validity):".to_string());
            for d in diags {
                out.push(format!("  {}: {} — {}", d.name, d.status, d.detail));
            }
        }
    }
    out.push("============================================================".to_string());
    out.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::{Checks, DiagnosticFact, TrustRootUsed, ValidityFact};
    use zombie_core::ReceiptState;

    fn facts(validity: Validity, v3a: CheckOutcome) -> VerificationFacts {
        VerificationFacts {
            source: "file:x.json".into(),
            protocol_version: Some("mktd02-v4".into()),
            protocol_line: Some(ProtocolLine::V4),
            historical: Some(true),
            receipt_id: Some("00".repeat(32)),
            canister_id: Some("aaaaa-aa".into()),
            receipt_state: Some(ReceiptState::FinalizedCandidate),
            intake_error: None,
            trust_root_used: Some(TrustRootUsed {
                id: "mainnet".into(),
                source: "built-in",
            }),
            receipt_trust_root_key_id: Some("mainnet".into()),
            trust_root_mismatch: None,
            attestation_class: "subnet-attested",
            checks: Checks {
                v1: CheckOutcome::pass("recomputed"),
                v2: CheckOutcome::pass("certified"),
                v3a,
                v3b: CheckOutcome::not_evaluated("no build provenance supplied (--wasm-hash)"),
            },
            timing: vec![],
            evidence_established: vec!["V1: recomputed".into()],
            validity: ValidityFact {
                validity,
                reason: None,
            },
            diagnostics: Some(vec![DiagnosticFact {
                name: "live-module-hash",
                status: "consistent",
                detail: "d".into(),
            }]),
        }
    }

    fn assert_no_bare_pass(text: &str) {
        for line in text.lines() {
            let t = line.trim().trim_matches(|c: char| !c.is_alphanumeric());
            assert_ne!(t, "PASS", "bare PASS line in:\n{text}");
        }
    }

    #[test]
    fn human_output_leads_with_validity_and_has_no_bare_pass() {
        let text = render_human(&facts(Validity::Pass, CheckOutcome::pass("attested")));
        assert_no_bare_pass(&text);
        let first_result = text.lines().find(|l| l.starts_with("validity: ")).unwrap();
        assert_eq!(first_result, "validity: PASS");
        assert!(text.contains("protocol_line: mktd02-v4 (historical)"));
        assert!(text.contains(PROVISIONAL_NOTICE));
    }

    #[test]
    fn every_not_evaluated_carries_a_reason() {
        let text = render_human(&facts(
            Validity::Incomplete,
            CheckOutcome::not_evaluated("pending"),
        ));
        assert!(text.contains("validity: INCOMPLETE"));
        for line in text.lines().filter(|l| l.contains("NOT_EVALUATED")) {
            let reason = line.split("NOT_EVALUATED — ").nth(1).unwrap_or("");
            assert!(
                !reason.trim().is_empty(),
                "NOT_EVALUATED without a reason: {line}"
            );
        }
    }

    #[test]
    fn json_carries_the_facts() {
        let json: serde_json::Value = serde_json::from_str(&render_json(&facts(
            Validity::Fail,
            CheckOutcome::fail("v3a:x", None),
        )))
        .unwrap();
        assert_eq!(json["validity"]["validity"], "FAIL");
        assert_eq!(json["checks"]["v3a"]["outcome"], "fail");
        assert_eq!(json["checks"]["v3a"]["error"], "v3a:x");
        assert_eq!(json["checks"]["v3b"]["outcome"], "not_evaluated");
    }
}
