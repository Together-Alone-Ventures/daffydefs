//! Offline verification of a decoded receipt into [`VerificationFacts`].

use zombie_core::AnyDeletionReceipt;

use crate::report::{derive_validity, Checks, ProtocolLine, VerificationFacts};
use crate::trust_root::TrustRoot;
use crate::{v1_transition, v2_certificate, v3_module};

pub struct VerifyOptions {
    pub trust_root: TrustRoot,
    /// Build provenance for V3B (`--wasm-hash`).
    pub published_module_hash: Option<[u8; 32]>,
}

/// Run V1, V2, V3A and V3B and derive validity. Pure: no network.
pub fn verify_receipt(
    receipt: &AnyDeletionReceipt,
    source: String,
    options: &VerifyOptions,
) -> VerificationFacts {
    let line = ProtocolLine::of(receipt);
    let state = receipt.state();
    let (canister_id, receipt_trust_root_key_id) = match receipt {
        AnyDeletionReceipt::V5(r) => (r.canister_id, r.trust_root_key_id.clone()),
        AnyDeletionReceipt::V4(r) => (r.canister_id, r.trust_root_key_id.clone()),
    };

    let v2 = v2_certificate::verify(receipt, &options.trust_root);
    let v3a = v3_module::verify_v3a(receipt, &options.trust_root);
    let checks = Checks {
        v1: v1_transition::verify(receipt),
        v2: v2.outcome,
        v3a: v3a.outcome,
        v3b: v3_module::verify_v3b(receipt, options.published_module_hash),
    };
    let timing = v2.timing.into_iter().chain(v3a.timing).collect();
    let evidence_established = [
        ("V1", &checks.v1),
        ("V2", &checks.v2),
        ("V3A", &checks.v3a),
        ("V3B", &checks.v3b),
    ]
    .iter()
    .filter_map(|(name, outcome)| match outcome {
        crate::report::CheckOutcome::Pass { established } => Some(format!("{name}: {established}")),
        _ => None,
    })
    .collect();

    VerificationFacts {
        source,
        protocol_version: Some(receipt.protocol_version().to_string()),
        protocol_line: Some(line),
        historical: Some(line.is_historical()),
        receipt_id: Some(hex::encode(receipt.receipt_id())),
        canister_id: Some(canister_id.to_text()),
        receipt_state: Some(state),
        intake_error: None,
        trust_root_used: Some(options.trust_root.fact()),
        trust_root_mismatch: options.trust_root.mismatch(&receipt_trust_root_key_id),
        receipt_trust_root_key_id: Some(receipt_trust_root_key_id),
        attestation_class: if checks.v3a.is_pass() {
            "subnet-attested"
        } else {
            "not-attested"
        },
        validity: derive_validity(line, state, &checks),
        checks,
        timing,
        evidence_established,
        diagnostics: None,
    }
}
