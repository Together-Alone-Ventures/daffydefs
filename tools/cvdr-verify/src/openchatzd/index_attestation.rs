//! OpenChatZD INDEX code-identity outcomes + orthogonal timing (spec §14.4 / §17).
//!
//! Distinct from MKTd02 Leaf `v3_module.rs` — OpenChatZD compares a folded
//! `h_index = SHA256(H_INDEX_TAG ‖ index_principal ‖ module_hash)` against the
//! receipt body, never treating raw module_hash as `h_index`.
//!
//! Timing labels (v0.7.0 five-value axis) are orthogonal to the four evidence
//! outcomes. Delay is t(INDEX certificate) − t(commitment certificate) — it
//! bounds certificate separation, not how long a receipt sat pending (S12).

use candid::Principal;
use zombie_core::hashing::sha256_concat;

use crate::v2_certificate::{self, ModuleHashOutcome};

/// b"OPENCHATZD_CVDR_H_INDEX_V1" — must match OpenChatZD / CVDR_BUILD_SPEC_V1 §2.
pub const H_INDEX_TAG: &[u8] = b"OPENCHATZD_CVDR_H_INDEX_V1";

/// Attestation-delay threshold (spec §5): INDEX cert `/time` − commitment cert `/time`.
pub const ATTESTATION_DELAY_NS: u64 = 3_600_000_000_000; // 1 hour
/// Completion window from `receipt_committed_at` (spec §5).
pub const COMPLETION_WINDOW_NS: u64 = 86_400_000_000_000; // 24 hours

pub const INDEX_HASH_MATCH_AT_CERT_TIME: &str = "INDEX_HASH_MATCH_AT_CERT_TIME";
pub const INDEX_HASH_MISMATCH: &str = "INDEX_HASH_MISMATCH";
pub const INDEX_ATTESTATION_UNAVAILABLE: &str = "INDEX_ATTESTATION_UNAVAILABLE";
pub const INDEX_ATTESTATION_INVALID: &str = "INDEX_ATTESTATION_INVALID";

/// Orthogonal timing axis (spec §17.2 / G v0.7.0). Exact wire strings.
pub const TIMING_ROUTINE: &str = "ROUTINE";
pub const TIMING_DELAY_EXCEEDED: &str = "DELAY_EXCEEDED";
pub const TIMING_PREDATES_COMMITMENT: &str = "PREDATES_COMMITMENT";
pub const TIMING_OUTSIDE_COMPLETION_WINDOW: &str = "OUTSIDE_COMPLETION_WINDOW";
pub const TIMING_NOT_APPLICABLE: &str = "NOT_APPLICABLE";

pub const OCZD_SUPPORTED_CLAIM: &str = "OpenChatZD can carry subnet-certified evidence of the Module Hash \
installed on the INDEX canister at the INDEX certificate time and compare it with the h_index \
captured in the receipt. Because OpenChatZD currently has no demonstrated upgrade-continuity \
interlock on local_user_index, matching endpoint hashes do not prove uninterrupted execution by \
that module throughout the sealing window.";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexAttestationResult {
    pub outcome: &'static str,
    /// Always one of the five timing labels (never omitted on the wire contract).
    pub timing: &'static str,
    pub detail: String,
    pub module_hash_hex: Option<String>,
    pub index_cert_time_ns: Option<u64>,
}

/// Fold certified module_hash under H_INDEX_TAG with the INDEX principal (spec §2).
pub fn fold_h_index(index_canister_id: Principal, module_hash: &[u8]) -> [u8; 32] {
    sha256_concat(&[H_INDEX_TAG, index_canister_id.as_slice(), module_hash])
}

/// Timing qualifier (spec §5 / §17.2). Always returns one of the five axis values.
///
/// Delay = INDEX cert `/time` − commitment cert `/time` (certificate-pair separation).
pub fn timing_qualifier(
    index_cert_time_ns: u64,
    commitment_cert_time_ns: u64,
    receipt_committed_at_ns: u64,
) -> &'static str {
    if index_cert_time_ns < commitment_cert_time_ns {
        return TIMING_PREDATES_COMMITMENT;
    }
    let delay = index_cert_time_ns - commitment_cert_time_ns;
    let from_commit = index_cert_time_ns.saturating_sub(receipt_committed_at_ns);
    if from_commit > COMPLETION_WINDOW_NS {
        return TIMING_OUTSIDE_COMPLETION_WINDOW;
    }
    if delay <= ATTESTATION_DELAY_NS {
        TIMING_ROUTINE
    } else {
        TIMING_DELAY_EXCEEDED
    }
}

/// Evaluate INDEX code-identity from optional evidence bytes.
///
/// `None` / empty evidence → `INDEX_ATTESTATION_UNAVAILABLE` (FrozenWire-only path).
/// Incomplete PortablePackageV2 must be rejected at parse time, never reach here as
/// a "V2 without evidence" shape (G v0.7.0).
pub fn evaluate(
    evidence_certificate: Option<&[u8]>,
    index_canister_id: Principal,
    body_h_index: &[u8; 32],
    commitment_cert_time_ns: u64,
    receipt_committed_at_ns: u64,
    trust_root_der: &[u8],
) -> IndexAttestationResult {
    let Some(cert_bytes) = evidence_certificate else {
        return IndexAttestationResult {
            outcome: INDEX_ATTESTATION_UNAVAILABLE,
            timing: TIMING_NOT_APPLICABLE,
            detail: "no INDEX code-identity evidence in package (FrozenWire-only or missing field)"
                .to_string(),
            module_hash_hex: None,
            index_cert_time_ns: None,
        };
    };
    if cert_bytes.is_empty() {
        return IndexAttestationResult {
            outcome: INDEX_ATTESTATION_UNAVAILABLE,
            timing: TIMING_NOT_APPLICABLE,
            detail: "INDEX evidence certificate_bytes is empty".to_string(),
            module_hash_hex: None,
            index_cert_time_ns: None,
        };
    }

    let verified: ModuleHashOutcome =
        match v2_certificate::verify_certificate_over_module_hash(cert_bytes, index_canister_id, trust_root_der)
        {
            Ok(o) => o,
            Err(e) => {
                return IndexAttestationResult {
                    outcome: INDEX_ATTESTATION_INVALID,
                    timing: TIMING_NOT_APPLICABLE,
                    detail: e,
                    module_hash_hex: None,
                    index_cert_time_ns: None,
                };
            }
        };

    let timing = timing_qualifier(
        verified.certificate_time_ns,
        commitment_cert_time_ns,
        receipt_committed_at_ns,
    );

    let folded = fold_h_index(index_canister_id, &verified.certified_module_hash);
    let (outcome, detail) = if &folded == body_h_index {
        (
            INDEX_HASH_MATCH_AT_CERT_TIME,
            format!(
                "folded h_index matches body.h_index at INDEX cert time ({timing})"
            ),
        )
    } else {
        (
            INDEX_HASH_MISMATCH,
            format!(
                "folded h_index {} != body.h_index {} (timing {timing})",
                hex::encode(folded),
                hex::encode(body_h_index),
            ),
        )
    };

    IndexAttestationResult {
        outcome,
        timing,
        detail,
        module_hash_hex: Some(hex::encode(verified.certified_module_hash)),
        index_cert_time_ns: Some(verified.certificate_time_ns),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn mainnet_mh_cert() -> &'static [u8] {
        include_bytes!("../../testdata/mainnet_module_hash_certificate.bin")
    }

    fn a1_commitment_cert() -> &'static [u8] {
        include_bytes!("../../testdata/A1_certificate.bin")
    }

    fn nns_trust() -> &'static [u8] {
        zombie_core::nns_keys::lookup_key(zombie_core::nns_keys::active_key_id())
            .expect("active NNS key")
            .der_bytes
    }

    fn mainnet_verified() -> ModuleHashOutcome {
        let canister = Principal::from_text("nq4qv-wqaaa-aaaaf-bhdgq-cai").unwrap();
        crate::v2_certificate::verify_certificate_over_module_hash(mainnet_mh_cert(), canister, nns_trust())
            .expect("mainnet module_hash cert must verify")
    }

    #[test]
    fn timing_routine_within_one_hour() {
        let commit = 1_000_000_000_000u64;
        let commitment_cert = commit + 10;
        let index_cert = commitment_cert + ATTESTATION_DELAY_NS;
        assert_eq!(
            timing_qualifier(index_cert, commitment_cert, commit),
            TIMING_ROUTINE
        );
    }

    #[test]
    fn timing_delay_exceeded_before_24h() {
        let commit = 1_000_000_000_000u64;
        let commitment_cert = commit + 10;
        let index_cert = commitment_cert + ATTESTATION_DELAY_NS + 1;
        assert_eq!(
            timing_qualifier(index_cert, commitment_cert, commit),
            TIMING_DELAY_EXCEEDED
        );
    }

    #[test]
    fn timing_outside_completion_window_past_24h() {
        let commit = 1_000_000_000_000u64;
        let commitment_cert = commit + 10;
        let index_cert = commit + COMPLETION_WINDOW_NS + 1;
        assert_eq!(
            timing_qualifier(index_cert, commitment_cert, commit),
            TIMING_OUTSIDE_COMPLETION_WINDOW
        );
    }

    #[test]
    fn timing_predates_commitment_is_timing_not_outcome() {
        assert_eq!(
            timing_qualifier(10, 20, 1),
            TIMING_PREDATES_COMMITMENT
        );
    }

    #[test]
    fn timing_predates_takes_precedence_over_outside_window() {
        // INDEX before commitment AND also >24h after receipt_committed_at → PREDATES wins.
        let commit = 1_000_000_000_000u64;
        let index_cert = commit + COMPLETION_WINDOW_NS + 10;
        let commitment_cert = index_cert + 1;
        assert_eq!(
            timing_qualifier(index_cert, commitment_cert, commit),
            TIMING_PREDATES_COMMITMENT
        );
    }

    #[test]
    fn timing_axis_labels_are_exact_wire_strings() {
        assert_eq!(TIMING_ROUTINE, "ROUTINE");
        assert_eq!(TIMING_DELAY_EXCEEDED, "DELAY_EXCEEDED");
        assert_eq!(TIMING_PREDATES_COMMITMENT, "PREDATES_COMMITMENT");
        assert_eq!(TIMING_OUTSIDE_COMPLETION_WINDOW, "OUTSIDE_COMPLETION_WINDOW");
        assert_eq!(TIMING_NOT_APPLICABLE, "NOT_APPLICABLE");
    }

    #[test]
    fn fold_h_index_is_not_raw_module_hash() {
        let id = Principal::from_slice(&[3u8; 10]);
        let mh = [7u8; 32];
        let folded = fold_h_index(id, &mh);
        assert_ne!(folded, mh);
        assert_eq!(folded, sha256_concat(&[H_INDEX_TAG, id.as_slice(), &mh]));
    }

    #[test]
    fn unavailable_when_no_evidence() {
        let id = Principal::from_slice(&[3u8; 10]);
        let r = evaluate(None, id, &[0u8; 32], 100, 50, &[]);
        assert_eq!(r.outcome, INDEX_ATTESTATION_UNAVAILABLE);
        assert_eq!(r.timing, TIMING_NOT_APPLICABLE);
    }

    #[test]
    fn mainnet_module_hash_cert_verifies_and_folds() {
        let cert = mainnet_mh_cert();
        let canister = Principal::from_text("nq4qv-wqaaa-aaaaf-bhdgq-cai").unwrap();
        let out = mainnet_verified();
        assert_eq!(out.certified_module_hash.len(), 32);
        let folded = fold_h_index(canister, &out.certified_module_hash);
        let r = evaluate(
            Some(cert),
            canister,
            &folded,
            out.certificate_time_ns.saturating_sub(1),
            out.certificate_time_ns.saturating_sub(1),
            nns_trust(),
        );
        assert_eq!(r.outcome, INDEX_HASH_MATCH_AT_CERT_TIME);
        assert_eq!(r.timing, TIMING_ROUTINE);

        let mismatch = evaluate(
            Some(cert),
            canister,
            &[0u8; 32],
            out.certificate_time_ns.saturating_sub(1),
            out.certificate_time_ns.saturating_sub(1),
            nns_trust(),
        );
        assert_eq!(mismatch.outcome, INDEX_HASH_MISMATCH);
    }

    /// Real mainnet cert + artificially early commitment times → DELAY_EXCEEDED /
    /// OUTSIDE_COMPLETION_WINDOW.
    #[test]
    fn mainnet_evaluate_timing_delay_exceeded_and_outside_window() {
        let cert = mainnet_mh_cert();
        let canister = Principal::from_text("nq4qv-wqaaa-aaaaf-bhdgq-cai").unwrap();
        let out = mainnet_verified();
        let folded = fold_h_index(canister, &out.certified_module_hash);
        let index_t = out.certificate_time_ns;

        let commitment_t = index_t - ATTESTATION_DELAY_NS - 1;
        let receipt_commit = index_t - (COMPLETION_WINDOW_NS / 2);
        let delay = evaluate(
            Some(cert),
            canister,
            &folded,
            commitment_t,
            receipt_commit,
            nns_trust(),
        );
        assert_eq!(delay.outcome, INDEX_HASH_MATCH_AT_CERT_TIME);
        assert_eq!(delay.timing, TIMING_DELAY_EXCEEDED);

        let late = evaluate(
            Some(cert),
            canister,
            &folded,
            index_t - 10,
            index_t - COMPLETION_WINDOW_NS - 1,
            nns_trust(),
        );
        assert_eq!(late.outcome, INDEX_HASH_MATCH_AT_CERT_TIME);
        assert_eq!(late.timing, TIMING_OUTSIDE_COMPLETION_WINDOW);
    }

    /// Spec §17.2: a late match is still MATCH, with OUTSIDE_COMPLETION_WINDOW timing.
    #[test]
    fn match_and_outside_window_coexist_not_unqualified() {
        let cert = mainnet_mh_cert();
        let canister = Principal::from_text("nq4qv-wqaaa-aaaaf-bhdgq-cai").unwrap();
        let out = mainnet_verified();
        let folded = fold_h_index(canister, &out.certified_module_hash);
        let r = evaluate(
            Some(cert),
            canister,
            &folded,
            out.certificate_time_ns - 10,
            out.certificate_time_ns - COMPLETION_WINDOW_NS - 1,
            nns_trust(),
        );
        assert_eq!(r.outcome, INDEX_HASH_MATCH_AT_CERT_TIME);
        assert_eq!(r.timing, TIMING_OUTSIDE_COMPLETION_WINDOW);
        assert!(!r.outcome.contains("DELAY"));
        assert!(!r.outcome.contains("OUTSIDE"));
    }

    /// Predate is a timing label; hash relationship remains MATCH/MISMATCH (orthogonal axes).
    #[test]
    fn predate_timing_keeps_match_outcome() {
        let cert = mainnet_mh_cert();
        let canister = Principal::from_text("nq4qv-wqaaa-aaaaf-bhdgq-cai").unwrap();
        let out = mainnet_verified();
        let folded = fold_h_index(canister, &out.certified_module_hash);
        let r = evaluate(
            Some(cert),
            canister,
            &folded,
            out.certificate_time_ns + 1_000_000, // commitment after INDEX → predate
            out.certificate_time_ns.saturating_sub(1),
            nns_trust(),
        );
        assert_eq!(r.outcome, INDEX_HASH_MATCH_AT_CERT_TIME);
        assert_eq!(r.timing, TIMING_PREDATES_COMMITMENT);
    }

    /// A1 commitment cert has `certified_data`, not `module_hash` → INVALID (not UNAVAILABLE).
    #[test]
    fn a1_commitment_cert_via_evaluate_is_invalid_not_unavailable() {
        let cert = a1_commitment_cert();
        let canister = Principal::from_text("iplx4-aiaaa-aaaap-quuuq-cai").unwrap();
        let r = evaluate(Some(cert), canister, &[0u8; 32], 100, 50, nns_trust());
        assert_eq!(
            r.outcome, INDEX_ATTESTATION_INVALID,
            "missing module_hash path after BLS ok must be INVALID, got {}: {}",
            r.outcome, r.detail
        );
        assert_eq!(r.timing, TIMING_NOT_APPLICABLE);
        assert!(
            r.detail.contains("module_hash"),
            "detail should mention module_hash: {}",
            r.detail
        );
    }

    #[test]
    fn verify_module_hash_rejects_garbage_and_tampered_signature() {
        let canister = Principal::from_text("nq4qv-wqaaa-aaaaf-bhdgq-cai").unwrap();
        let trust = nns_trust();

        let err = crate::v2_certificate::verify_certificate_over_module_hash(
            &[0xde, 0xad, 0xbe, 0xef],
            canister,
            trust,
        )
        .unwrap_err();
        assert!(
            err.contains("parse") || err.contains("CBOR") || err.contains("cbor"),
            "{err}"
        );

        let mut tampered = mainnet_mh_cert().to_vec();
        let mid = tampered.len() / 2;
        tampered[mid] ^= 0xFF;
        let err = crate::v2_certificate::verify_certificate_over_module_hash(&tampered, canister, trust)
            .unwrap_err();
        assert!(
            err.to_lowercase().contains("bls")
                || err.to_lowercase().contains("signature")
                || err.to_lowercase().contains("invalid")
                || err.to_lowercase().contains("parse")
                || err.to_lowercase().contains("cbor"),
            "unexpected tamper error: {err}"
        );
    }

    #[test]
    fn labels_match_sibling_open_chat_zd_when_present() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../../open-chatZD/backend/canisters/local_user_index/impl/src/model/cvdr_index_attestation.rs");
        if !path.exists() {
            eprintln!("skip cross-repo labels: {} not present", path.display());
            return;
        }
        let src = std::fs::read_to_string(&path).expect("read open-chatZD labels");
        for label in [
            INDEX_HASH_MATCH_AT_CERT_TIME,
            INDEX_HASH_MISMATCH,
            INDEX_ATTESTATION_UNAVAILABLE,
            INDEX_ATTESTATION_INVALID,
            TIMING_ROUTINE,
            TIMING_DELAY_EXCEEDED,
            TIMING_PREDATES_COMMITMENT,
            TIMING_OUTSIDE_COMPLETION_WINDOW,
            TIMING_NOT_APPLICABLE,
            "openchatzd.cvdr.portable_package",
        ] {
            assert!(
                src.contains(label),
                "open-chatZD cvdr_index_attestation.rs missing label `{label}`"
            );
        }
        assert!(src.contains("do not prove uninterrupted execution"));
        // Positive presence of the five-value axis is the contract; do not scan for
        // retired substrings here (sibling test helpers may mention them).
    }
}
