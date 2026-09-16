//! Structured verification facts for an MKTd02 receipt.
//!
//! This module is the verifier's result: plain, serialisable facts with no
//! presentation vocabulary. How they are shown to a person is decided in
//! [`crate::render`], which is deliberately provisional and replaceable.

use serde::Serialize;
use zombie_core::{AnyDeletionReceipt, ReceiptState};

/// The MKTd02 receipt line, as zombie-core classifies it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum ProtocolLine {
    V2,
    V3,
    V4,
    V5,
}

impl ProtocolLine {
    /// Line of a decoded receipt.
    pub fn of(receipt: &AnyDeletionReceipt) -> Self {
        match receipt {
            AnyDeletionReceipt::V5(_) => ProtocolLine::V5,
            AnyDeletionReceipt::V4(r) => Self::of_v4_label(&r.protocol_version),
        }
    }

    /// Line of a label that decoded as `DeletionReceiptV4`. Mirrors zombie-core's
    /// classification (`receipt.rs` `classify_protocol`: v2–v4 by prefix); a
    /// decoded `DeletionReceiptV4` always carries one of these prefixes.
    pub fn of_v4_label(label: &str) -> Self {
        if label.starts_with("mktd02-v4") {
            ProtocolLine::V4
        } else if label.starts_with("mktd02-v3") {
            ProtocolLine::V3
        } else {
            ProtocolLine::V2
        }
    }

    pub fn is_historical(self) -> bool {
        self != ProtocolLine::V5
    }

    /// Whether V3A (subnet-attested code identity) exists on this line.
    pub fn has_module_hash_certification(self) -> bool {
        matches!(self, ProtocolLine::V4 | ProtocolLine::V5)
    }
}

/// Outcome of one check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum CheckOutcome {
    Pass {
        established: String,
    },
    Fail {
        error: String,
        detail: Option<String>,
    },
    NotEvaluated {
        reason: String,
    },
}

impl CheckOutcome {
    pub fn pass(established: impl Into<String>) -> Self {
        CheckOutcome::Pass {
            established: established.into(),
        }
    }
    pub fn fail(error: impl Into<String>, detail: Option<String>) -> Self {
        CheckOutcome::Fail {
            error: error.into(),
            detail,
        }
    }
    pub fn not_evaluated(reason: impl Into<String>) -> Self {
        CheckOutcome::NotEvaluated {
            reason: reason.into(),
        }
    }
    pub fn is_pass(&self) -> bool {
        matches!(self, CheckOutcome::Pass { .. })
    }
    /// The named error of a failed check.
    pub fn error(&self) -> Option<&str> {
        match self {
            CheckOutcome::Fail { error, .. } => Some(error),
            _ => None,
        }
    }
}

/// Per-check outcomes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Checks {
    /// Internal consistency of the receipt.
    pub v1: CheckOutcome,
    /// Direct certification: embedded certificate vs trust root, certified_data.
    pub v2: CheckOutcome,
    /// Subnet-attested code identity (module-hash certificate).
    pub v3a: CheckOutcome,
    /// Build provenance comparison (only when provenance is supplied).
    pub v3b: CheckOutcome,
}

/// Timing sub-results. Existing timing semantics are unchanged: none of these
/// alters a check outcome except the V3A ordering failure, which is a V3A FAIL.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TimingFact {
    /// V2: certificate `/time` against the receipt's internal timestamp.
    /// Informational; a warning past the threshold, never a failure.
    V2CertificateTime {
        certificate_time_ns: u64,
        receipt_timestamp_ns: u64,
        delta_secs: f64,
        warn_threshold_secs: u64,
        exceeds_warning_threshold: bool,
    },
    /// V2: the certificate `/time` could not be decoded (informational).
    V2CertificateTimeUnavailable { detail: String },
    /// V3A: t(module_hash certificate) − t(bls certificate), bounded by
    /// `zombie_core::MAX_FINALIZATION_DELAY_NS`.
    V3aFinalizationDelay {
        bls_certificate_time_ns: u64,
        module_hash_certificate_time_ns: u64,
        delta_secs: Option<f64>,
        max_finalization_delay_secs: u64,
        /// `ROUTINE`, `DELAY_EXCEEDED` (downgrade, not rejection) or
        /// `ORDERING_FAILURE` (V3A FAIL).
        verdict: &'static str,
    },
}

/// Which trust root the certificate checks used.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TrustRootUsed {
    /// `mainnet` for a built-in key, `pem:<sha256-prefix>` for a supplied PEM.
    pub id: String,
    /// `built-in` or `pem`.
    pub source: &'static str,
}

/// Recorded when the receipt's own `trust_root_key_id` differs from the root
/// used. A warning, never a failure and never a key selector.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TrustRootMismatch {
    pub receipt_says: String,
    pub verification_used: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Validity {
    #[serde(rename = "PASS")]
    Pass,
    #[serde(rename = "FAIL")]
    Fail,
    #[serde(rename = "INCOMPLETE")]
    Incomplete,
}

/// Exit codes of the MKTd02 path. 3 is left to the OpenChatZD `LateFinalized` tier.
pub const EXIT_PASS: i32 = 0;
pub const EXIT_FAIL: i32 = 1;
pub const EXIT_USAGE: i32 = 2;
pub const EXIT_INCOMPLETE: i32 = 4;

impl Validity {
    pub fn exit_code(self) -> i32 {
        match self {
            Validity::Pass => EXIT_PASS,
            Validity::Fail => EXIT_FAIL,
            Validity::Incomplete => EXIT_INCOMPLETE,
        }
    }
}

/// Named validity reasons.
pub const REASON_INCOMPLETE_FINALISATION: &str = "incomplete-finalisation";
pub const REASON_PENDING: &str = "pending — Phase B certificate not yet embedded; V2 not evaluable";

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ValidityFact {
    pub validity: Validity,
    /// Named reason for FAIL / INCOMPLETE; `None` for PASS.
    pub reason: Option<String>,
}

/// One live query result. Diagnostics never enter validity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DiagnosticFact {
    pub name: &'static str,
    /// `consistent`, `inconsistent`, `unavailable` or `informational`.
    pub status: &'static str,
    pub detail: String,
}

/// The complete result of verifying one MKTd02 receipt.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct VerificationFacts {
    pub source: String,
    /// Wire label, e.g. `mktd02-v4`; `None` if intake rejected the receipt.
    pub protocol_version: Option<String>,
    pub protocol_line: Option<ProtocolLine>,
    pub historical: Option<bool>,
    pub receipt_id: Option<String>,
    pub canister_id: Option<String>,
    pub receipt_state: Option<ReceiptState>,
    /// Named intake rejection (verbatim from zombie-core where it originates there).
    pub intake_error: Option<String>,
    pub trust_root_used: Option<TrustRootUsed>,
    /// The receipt's own `trust_root_key_id`, recorded, not used to select a key.
    pub receipt_trust_root_key_id: Option<String>,
    pub trust_root_mismatch: Option<TrustRootMismatch>,
    /// `subnet-attested` when V3A passed, else `not-attested`.
    pub attestation_class: &'static str,
    pub checks: Checks,
    pub timing: Vec<TimingFact>,
    /// What the passing checks established, one entry per passing check.
    pub evidence_established: Vec<String>,
    pub validity: ValidityFact,
    /// `None` when no live diagnostics were requested.
    pub diagnostics: Option<Vec<DiagnosticFact>>,
}

/// Per-line validity rule.
///
/// - V1 failure → FAIL (V1 applies to every state).
/// - `InvalidIncompleteFinalization` → FAIL `incomplete-finalisation`.
/// - `Pending` → INCOMPLETE.
/// - v4/v5: V1 ∧ V2 ∧ V3A; v2/v3: V1 ∧ V2. First failing required check names
///   the FAIL; a required check left unevaluated on a finalized receipt fails
///   closed.
pub fn derive_validity(line: ProtocolLine, state: ReceiptState, checks: &Checks) -> ValidityFact {
    let fail = |reason: String| ValidityFact {
        validity: Validity::Fail,
        reason: Some(reason),
    };
    if let Some(e) = checks.v1.error() {
        return fail(e.to_string());
    }
    match state {
        ReceiptState::InvalidIncompleteFinalization => {
            return fail(REASON_INCOMPLETE_FINALISATION.into())
        }
        ReceiptState::Pending => {
            return ValidityFact {
                validity: Validity::Incomplete,
                reason: Some(REASON_PENDING.into()),
            }
        }
        ReceiptState::FinalizedCandidate => {}
    }
    let mut required = vec![("V1", &checks.v1), ("V2", &checks.v2)];
    if line.has_module_hash_certification() {
        required.push(("V3A", &checks.v3a));
    }
    for (name, outcome) in &required {
        match outcome {
            CheckOutcome::Fail { error, .. } => return fail(error.clone()),
            CheckOutcome::NotEvaluated { .. } => {
                return fail(format!("required-check-not-evaluated:{name}"))
            }
            CheckOutcome::Pass { .. } => {}
        }
    }
    ValidityFact {
        validity: Validity::Pass,
        reason: None,
    }
}

impl VerificationFacts {
    /// Facts for a receipt that intake rejected: validity FAIL with the named
    /// error, no check evaluated.
    pub fn intake_rejected(source: String, error: String) -> Self {
        let not_evaluated = || CheckOutcome::not_evaluated("intake rejected the receipt");
        VerificationFacts {
            source,
            protocol_version: None,
            protocol_line: None,
            historical: None,
            receipt_id: None,
            canister_id: None,
            receipt_state: None,
            intake_error: Some(error.clone()),
            trust_root_used: None,
            receipt_trust_root_key_id: None,
            trust_root_mismatch: None,
            attestation_class: "not-attested",
            checks: Checks {
                v1: not_evaluated(),
                v2: not_evaluated(),
                v3a: not_evaluated(),
                v3b: not_evaluated(),
            },
            timing: Vec::new(),
            evidence_established: Vec::new(),
            validity: ValidityFact {
                validity: Validity::Fail,
                reason: Some(error),
            },
            diagnostics: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn checks(v1: CheckOutcome, v2: CheckOutcome, v3a: CheckOutcome) -> Checks {
        Checks {
            v1,
            v2,
            v3a,
            v3b: CheckOutcome::not_evaluated("no build provenance supplied"),
        }
    }
    fn pass() -> CheckOutcome {
        CheckOutcome::pass("ok")
    }

    #[test]
    fn v4_v5_require_v3a_and_v2_v3_do_not() {
        let no_v3a = checks(
            pass(),
            pass(),
            CheckOutcome::not_evaluated("line predates module-hash certification"),
        );
        for line in [ProtocolLine::V2, ProtocolLine::V3] {
            assert_eq!(
                derive_validity(line, ReceiptState::FinalizedCandidate, &no_v3a).validity,
                Validity::Pass
            );
        }
        for line in [ProtocolLine::V4, ProtocolLine::V5] {
            let v = derive_validity(line, ReceiptState::FinalizedCandidate, &no_v3a);
            assert_eq!(v.validity, Validity::Fail);
            assert_eq!(
                v.reason.as_deref(),
                Some("required-check-not-evaluated:V3A")
            );
            let all = checks(pass(), pass(), pass());
            assert_eq!(
                derive_validity(line, ReceiptState::FinalizedCandidate, &all).validity,
                Validity::Pass
            );
        }
    }

    #[test]
    fn pending_is_incomplete_and_invalid_is_named_fail() {
        let pending = checks(
            pass(),
            CheckOutcome::not_evaluated("pending"),
            CheckOutcome::not_evaluated("pending"),
        );
        let v = derive_validity(ProtocolLine::V5, ReceiptState::Pending, &pending);
        assert_eq!(
            (v.validity, v.reason.as_deref()),
            (Validity::Incomplete, Some(REASON_PENDING))
        );
        assert_eq!(v.validity.exit_code(), EXIT_INCOMPLETE);

        let v = derive_validity(
            ProtocolLine::V4,
            ReceiptState::InvalidIncompleteFinalization,
            &pending,
        );
        assert_eq!(
            (v.validity, v.reason.as_deref()),
            (Validity::Fail, Some(REASON_INCOMPLETE_FINALISATION))
        );
    }

    #[test]
    fn v1_failure_wins_even_when_pending() {
        let c = checks(
            CheckOutcome::fail("v1:receipt-id-mismatch", None),
            pass(),
            pass(),
        );
        let v = derive_validity(ProtocolLine::V5, ReceiptState::Pending, &c);
        assert_eq!(
            (v.validity, v.reason.as_deref()),
            (Validity::Fail, Some("v1:receipt-id-mismatch"))
        );
    }

    #[test]
    fn exit_codes_are_distinct() {
        let codes = [EXIT_PASS, EXIT_FAIL, EXIT_USAGE, EXIT_INCOMPLETE];
        for (i, a) in codes.iter().enumerate() {
            for b in &codes[i + 1..] {
                assert_ne!(a, b);
            }
        }
    }
}
