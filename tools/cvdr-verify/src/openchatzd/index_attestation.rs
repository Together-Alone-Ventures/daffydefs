//! OpenChatZD V3A — subnet-attested Index code identity (suite v5, Brief B1 R-2 / R-6; G step-5 rules).
//!
//! Evidence = the `read_state` certificate for `/canister/<index>/module_hash` captured by the
//! Index inside the protected deletion→evidence interval (`uninstall_completed_at` ..
//! `uninstall_completed_at + 24 h`), during which the Index upgrade interlock guarantees the same
//! code stayed installed. V3A therefore attests "subnet-attested installed module identity during
//! the finalization/certification window", bounded by that interlock.
//!
//! **Invariant (C2, Stef 2026-09-22 — the Index's store-gate and this verifier apply the same
//! certified-time comparison):** "V3A evidence is admissible only if the authenticated certificate
//! /time is ≤ uninstall_completed_at + 24 h, the receipt's captured code epoch is still current, and
//! no evidence has already been stored. Once the epoch changes, or the certificate time is outside
//! that window, V3A is permanently unavailable." Offline, the verifier sees the certified `/time`
//! and the hash-bound `uninstall_completed_at`; the epoch and first-wins conditions are enforced by
//! the Index at store time (an epoch change is observable here only as evidence that never arrives).
//!
//! **Exactly three outcomes** (G rule 2), decided from the point-C semantics:
//! - [`V3aOutcome::Pass`] — certificate BLS-authenticated under the SELECTED trust root, its `/time`
//!   inside the protected interval, and the displayed `index_module_hash` equals the certified one;
//! - [`V3aOutcome::PendingInProtectedWindow`] — no evidence yet, window still open;
//! - [`V3aOutcome::PermanentlyUnavailable`] — no evidence and the window has lapsed: no later
//!   evidence can be valid (the Index never captures after the window / across an upgrade).
//!
//! Everything else is a NAMED FAILURE (`INDEX_ATTESTATION_INVALID`, `INDEX_HASH_MISMATCH`), never an
//! outcome. Code identity is never inferred from the absence of evidence, and pending is never
//! collapsed into unavailable.
//!
//! `trust_root_key_id` is a SELECTOR, never evidence (G rule 1): it picks a verifier-configured root;
//! the certificate must authenticate under that root; string equality alone proves nothing.
//!
//! Timing labels (five-value axis) stay orthogonal and NON-GATING.

use candid::Principal;
use zombie_core::hashing::sha256_concat;

use super::body::{BodyVersion, ReceiptBody};
use super::package::IndexCodeIdentityEvidence;
use crate::v2_certificate::{self, ModuleHashOutcome};

/// b"OPENCHATZD_CVDR_H_INDEX_V1" — HISTORICAL (RECEIPT_BODY_V1 only; retired by R-2).
pub const H_INDEX_TAG: &[u8] = b"OPENCHATZD_CVDR_H_INDEX_V1";

/// Protected deletion→evidence interval (internal name): evidence must be captured within this of
/// `uninstall_completed_at`; after it the receipt is permanently V3A-unavailable.
pub const PROTECTED_WINDOW_NS: u64 = 86_400_000_000_000; // 24 hours
/// Attestation-delay threshold (timing axis, non-gating): INDEX cert `/time` − commitment cert `/time`.
pub const ATTESTATION_DELAY_NS: u64 = 3_600_000_000_000; // 1 hour
/// Completion window from `receipt_committed_at` (timing axis, non-gating).
pub const COMPLETION_WINDOW_NS: u64 = 86_400_000_000_000; // 24 hours

/// The three V3A outcomes — exact wire strings.
pub const V3A_PASS: &str = "V3A_PASS";
pub const V3A_PENDING_IN_PROTECTED_WINDOW: &str = "V3A_PENDING_IN_PROTECTED_WINDOW";
pub const V3A_PERMANENTLY_UNAVAILABLE: &str = "V3A_PERMANENTLY_UNAVAILABLE";
/// Named V3A failures (validity FAIL) — exact wire strings.
pub const INDEX_ATTESTATION_INVALID: &str = "INDEX_ATTESTATION_INVALID";
pub const INDEX_HASH_MISMATCH: &str = "INDEX_HASH_MISMATCH";

/// Orthogonal timing axis (non-gating). Exact wire strings.
pub const TIMING_ROUTINE: &str = "ROUTINE";
pub const TIMING_DELAY_EXCEEDED: &str = "DELAY_EXCEEDED";
pub const TIMING_PREDATES_COMMITMENT: &str = "PREDATES_COMMITMENT";
pub const TIMING_OUTSIDE_COMPLETION_WINDOW: &str = "OUTSIDE_COMPLETION_WINDOW";
pub const TIMING_NOT_APPLICABLE: &str = "NOT_APPLICABLE";

/// Allowed OpenChatZD-scoped claim (ratified wording, Stef 2026-09-22). Keep in sync with
/// OpenChatZD `cvdr_index_attestation.rs` / RTS / claims register.
pub const OCZD_SUPPORTED_CLAIM: &str = "OpenChatZD carries subnet-attested installed module identity \
during the finalization/certification window. The Index upgrade interlock bounds that window from \
uninstall to evidence capture: the same Index code stays installed until the module-hash certificate \
is stored, so the certified module hash is the code identity of the deleting Index.";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum V3aOutcome {
    Pass,
    PendingInProtectedWindow,
    PermanentlyUnavailable,
}

impl V3aOutcome {
    pub fn label(self) -> &'static str {
        match self {
            V3aOutcome::Pass => V3A_PASS,
            V3aOutcome::PendingInProtectedWindow => V3A_PENDING_IN_PROTECTED_WINDOW,
            V3aOutcome::PermanentlyUnavailable => V3A_PERMANENTLY_UNAVAILABLE,
        }
    }
}

/// Which configured root the V3A certificate was authenticated under (reported so a verdict
/// obtained under a non-production root can never pass as mainnet-attested by omission).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustRootUsed {
    /// The selector that picked it (`mainnet` | `non-production-test-root`).
    pub selector: String,
    pub non_production: bool,
    pub der_len: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V3aResult {
    /// `Ok(outcome)` = one of the three outcomes; `Err((named_error, detail))` = validity FAIL.
    pub outcome: Result<V3aOutcome, (&'static str, String)>,
    /// Always one of the five timing labels (non-gating).
    pub timing: &'static str,
    pub detail: String,
    pub certified_module_hash_hex: Option<String>,
    pub index_cert_time_ns: Option<u64>,
    pub trust_root: Option<TrustRootUsed>,
}

impl V3aResult {
    pub fn label(&self) -> &'static str {
        match &self.outcome {
            Ok(o) => o.label(),
            Err((name, _)) => name,
        }
    }
}

/// HISTORICAL: fold certified module_hash under H_INDEX_TAG with the INDEX principal (RECEIPT_BODY_V1).
pub fn fold_h_index(index_canister_id: Principal, module_hash: &[u8]) -> [u8; 32] {
    sha256_concat(&[H_INDEX_TAG, index_canister_id.as_slice(), module_hash])
}

/// Timing qualifier (non-gating). Always returns one of the five axis values.
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

/// No evidence: pending while the protected window is open at `now_ns`, permanently unavailable
/// once it has lapsed. Pure; the ONLY place "no evidence" is classified.
pub fn classify_absent_evidence(uninstall_completed_at_ns: u64, now_ns: u64) -> V3aOutcome {
    if uninstall_completed_at_ns > 0
        && now_ns.saturating_sub(uninstall_completed_at_ns) <= PROTECTED_WINDOW_NS
    {
        V3aOutcome::PendingInProtectedWindow
    } else {
        V3aOutcome::PermanentlyUnavailable
    }
}

/// Evaluate V3A for a parsed receipt body.
///
/// * `evidence` — the package's evidence, if any.
/// * `trust_root` — the configured root SELECTED by the package's `trust_root_key_id` (or, for
///   FrozenWire/V2 inputs, by the CLI). `None` = the selector could not be honoured (e.g. the
///   non-production selector without the fixture flag) — a named failure when evidence is present.
/// * `now_ns` — verifier clock, used only to split pending from permanently unavailable.
pub fn evaluate(
    evidence: Option<&IndexCodeIdentityEvidence>,
    body: &ReceiptBody,
    commitment_cert_time_ns: u64,
    now_ns: u64,
    trust_root: Option<(&[u8], TrustRootUsed)>,
) -> V3aResult {
    let absent = |detail: String| {
        let outcome = classify_absent_evidence(body.uninstall_completed_at_ns, now_ns);
        V3aResult {
            outcome: Ok(outcome),
            timing: TIMING_NOT_APPLICABLE,
            detail: match outcome {
                V3aOutcome::PendingInProtectedWindow => format!(
                    "{detail}; protected window open (uninstall_completed_at {} ns, now {} ns) — evidence may still be captured; code identity NOT established",
                    body.uninstall_completed_at_ns, now_ns
                ),
                _ => format!(
                    "{detail}; protected window lapsed (uninstall_completed_at {} ns, now {} ns) — no later evidence can be valid; code identity NOT established",
                    body.uninstall_completed_at_ns, now_ns
                ),
            },
            certified_module_hash_hex: None,
            index_cert_time_ns: None,
            trust_root: None,
        }
    };
    let Some(ev) = evidence else {
        return absent("no INDEX code-identity evidence in package".to_string());
    };
    if ev.certificate_bytes.is_empty() {
        return absent("INDEX evidence certificate_bytes is empty".to_string());
    }
    let fail = |name: &'static str, detail: String, trust_root: Option<TrustRootUsed>| V3aResult {
        outcome: Err((name, detail.clone())),
        timing: TIMING_NOT_APPLICABLE,
        detail,
        certified_module_hash_hex: None,
        index_cert_time_ns: None,
        trust_root,
    };
    let Some((der, used)) = trust_root else {
        return fail(
            INDEX_ATTESTATION_INVALID,
            "evidence present but the selected trust root is not available to this verifier (a \
             non-production selector needs the explicit fixture-root flag and a fixture root) — \
             the certificate cannot be authenticated"
                .to_string(),
            None,
        );
    };

    // BLS → NNS delegation → canister range → exact /canister/<index>/module_hash, under the SELECTED root.
    let verified: ModuleHashOutcome = match v2_certificate::verify_certificate_over_module_hash(
        &ev.certificate_bytes,
        body.index_canister_id,
        der,
    ) {
        Ok(o) => o,
        Err(e) => return fail(INDEX_ATTESTATION_INVALID, e, Some(used)),
    };

    // C2 invariant, certified-time comparison (identical to the Index's store-gate bound): the
    // certificate must post-date the uninstall and its /time must be ≤ uninstall + 24 h — outside
    // that window no qualifying evidence exists, so a certificate presented anyway is INVALID.
    let t = verified.certificate_time_ns;
    let u = body.uninstall_completed_at_ns;
    if u == 0 || t < u {
        return fail(
            INDEX_ATTESTATION_INVALID,
            format!("INDEX certificate /time {t} ns predates uninstall_completed_at {u} ns — outside the protected interval"),
            Some(used),
        );
    }
    if t - u > PROTECTED_WINDOW_NS {
        return fail(
            INDEX_ATTESTATION_INVALID,
            format!(
                "INDEX certificate /time {t} ns is {} ns after uninstall_completed_at {u} ns — beyond the 24 h protected window",
                t - u
            ),
            Some(used),
        );
    }

    let timing = timing_qualifier(t, commitment_cert_time_ns, body.receipt_committed_at_ns);
    let certified_hex = hex::encode(verified.certified_module_hash);

    // Equality: the DISPLAYED identity vs the AUTHENTICATED one.
    let mismatch = match body.version {
        BodyVersion::V2 => match ev.index_module_hash {
            Some(displayed) if displayed == verified.certified_module_hash => None,
            Some(displayed) => Some(format!(
                "displayed index_module_hash {} != certified module_hash {certified_hex}",
                hex::encode(displayed)
            )),
            None => {
                Some("RECEIPT_BODY_V2 evidence carries no index_module_hash to compare".to_string())
            }
        },
        BodyVersion::V1 => {
            let folded = fold_h_index(body.index_canister_id, &verified.certified_module_hash);
            match body.h_index {
                Some(h) if h == folded => None,
                Some(h) => Some(format!(
                    "folded h_index {} != body.h_index {}",
                    hex::encode(folded),
                    hex::encode(h)
                )),
                None => Some("RECEIPT_BODY_V1 without h_index".to_string()),
            }
        }
    };
    let root_note = if used.non_production {
        " — authenticated under a NON-PRODUCTION trust root (test verdict only)"
    } else {
        ""
    };
    match mismatch {
        None => V3aResult {
            outcome: Ok(V3aOutcome::Pass),
            timing,
            detail: format!(
                "certificate authenticated under selector '{}', /time inside the protected interval, \
                 displayed identity == certified module_hash {certified_hex} (timing {timing}){root_note}",
                used.selector
            ),
            certified_module_hash_hex: Some(certified_hex),
            index_cert_time_ns: Some(t),
            trust_root: Some(used),
        },
        Some(why) => V3aResult {
            outcome: Err((INDEX_HASH_MISMATCH, why.clone())),
            timing,
            detail: format!("{why} (timing {timing}){root_note}"),
            certified_module_hash_hex: Some(certified_hex),
            index_cert_time_ns: Some(t),
            trust_root: Some(used),
        },
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
    fn mainnet() -> (Principal, ModuleHashOutcome) {
        let canister = Principal::from_text("nq4qv-wqaaa-aaaaf-bhdgq-cai").unwrap();
        let out = crate::v2_certificate::verify_certificate_over_module_hash(
            mainnet_mh_cert(),
            canister,
            nns_trust(),
        )
        .expect("mainnet module_hash cert must verify");
        (canister, out)
    }
    fn used(non_production: bool) -> TrustRootUsed {
        TrustRootUsed {
            selector: if non_production {
                "non-production-test-root"
            } else {
                "mainnet"
            }
            .to_string(),
            non_production,
            der_len: nns_trust().len(),
        }
    }
    fn body_v2(index: Principal, uninstall_ns: u64) -> ReceiptBody {
        ReceiptBody {
            version: BodyVersion::V2,
            receipt_id: [1u8; 32],
            nonce: [2u8; 32],
            index_canister_id: index,
            user_canister_id: Principal::from_slice(&[9u8; 10]),
            record_id: [3u8; 32],
            deletion_seq: 1,
            h_user_pre: [4u8; 32],
            h_index: None,
            commitment: None,
            uninstall_completed_at_ns: uninstall_ns,
            receipt_committed_at_ns: uninstall_ns.saturating_add(1),
            targets_count: 0,
            targets_commitment: [5u8; 32],
        }
    }
    fn evidence(hash: [u8; 32]) -> IndexCodeIdentityEvidence {
        IndexCodeIdentityEvidence {
            certificate_bytes: mainnet_mh_cert().to_vec(),
            index_module_hash: Some(hash),
        }
    }

    #[test]
    fn labels_are_exact_wire_strings() {
        assert_eq!(V3A_PASS, "V3A_PASS");
        assert_eq!(
            V3A_PENDING_IN_PROTECTED_WINDOW,
            "V3A_PENDING_IN_PROTECTED_WINDOW"
        );
        assert_eq!(V3A_PERMANENTLY_UNAVAILABLE, "V3A_PERMANENTLY_UNAVAILABLE");
        assert_eq!(INDEX_ATTESTATION_INVALID, "INDEX_ATTESTATION_INVALID");
        assert_eq!(INDEX_HASH_MISMATCH, "INDEX_HASH_MISMATCH");
        for t in [
            TIMING_ROUTINE,
            TIMING_DELAY_EXCEEDED,
            TIMING_PREDATES_COMMITMENT,
            TIMING_OUTSIDE_COMPLETION_WINDOW,
            TIMING_NOT_APPLICABLE,
        ] {
            assert!(!t.is_empty());
        }
        assert!(OCZD_SUPPORTED_CLAIM.contains("subnet-attested installed module identity during the finalization/certification window"));
        assert!(OCZD_SUPPORTED_CLAIM
            .contains("upgrade interlock bounds that window from uninstall to evidence capture"));
        assert!(
            !OCZD_SUPPORTED_CLAIM.contains("protected deletion→evidence interval"),
            "internal name must not appear in the claim"
        );
    }

    /// G rule 2: absence of evidence is PENDING inside the window, PERMANENTLY_UNAVAILABLE after —
    /// never a pass, never a failure, never collapsed.
    #[test]
    fn absent_evidence_is_pending_then_permanently_unavailable() {
        let u = 1_000_000_000_000u64;
        assert_eq!(
            classify_absent_evidence(u, u),
            V3aOutcome::PendingInProtectedWindow
        );
        assert_eq!(
            classify_absent_evidence(u, u + PROTECTED_WINDOW_NS),
            V3aOutcome::PendingInProtectedWindow
        );
        assert_eq!(
            classify_absent_evidence(u, u + PROTECTED_WINDOW_NS + 1),
            V3aOutcome::PermanentlyUnavailable
        );
        assert_eq!(
            classify_absent_evidence(0, u),
            V3aOutcome::PermanentlyUnavailable,
            "no uninstall anchor => unavailable"
        );
        let body = body_v2(Principal::from_slice(&[3u8; 10]), u);
        let pending = evaluate(None, &body, u + 5, u + 10, Some((nns_trust(), used(false))));
        assert_eq!(pending.outcome, Ok(V3aOutcome::PendingInProtectedWindow));
        assert_eq!(pending.timing, TIMING_NOT_APPLICABLE);
        assert!(pending.detail.contains("NOT established"));
        let gone = evaluate(
            None,
            &body,
            u + 5,
            u + PROTECTED_WINDOW_NS + 1,
            Some((nns_trust(), used(false))),
        );
        assert_eq!(gone.outcome, Ok(V3aOutcome::PermanentlyUnavailable));
        assert_ne!(pending.label(), gone.label());
    }

    /// Real mainnet certificate: PASS iff authenticated under the selected root, in the protected
    /// interval, and the displayed hash equals the certified one.
    #[test]
    fn mainnet_evidence_passes_and_mismatch_is_named_failure() {
        let (canister, out) = mainnet();
        let u = out.certificate_time_ns - 1_000;
        let body = body_v2(canister, u);
        let ok = evaluate(
            Some(&evidence(out.certified_module_hash)),
            &body,
            u + 1,
            u + 2,
            Some((nns_trust(), used(false))),
        );
        assert_eq!(ok.outcome, Ok(V3aOutcome::Pass), "{}", ok.detail);
        assert_eq!(ok.timing, TIMING_ROUTINE);
        assert_eq!(
            ok.certified_module_hash_hex.as_deref(),
            Some(hex::encode(out.certified_module_hash).as_str())
        );
        assert!(!ok.detail.contains("NON-PRODUCTION"));

        let bad = evaluate(
            Some(&evidence([0u8; 32])),
            &body,
            u + 1,
            u + 2,
            Some((nns_trust(), used(false))),
        );
        assert_eq!(bad.outcome.as_ref().unwrap_err().0, INDEX_HASH_MISMATCH);
        assert!(bad.outcome.is_err());
    }

    /// The protected interval gates: a certificate before the uninstall or after the 24 h window is
    /// INVALID — it cannot name the deleting code.
    #[test]
    fn certificate_outside_protected_interval_is_invalid() {
        let (canister, out) = mainnet();
        let t = out.certificate_time_ns;
        let ev = evidence(out.certified_module_hash);
        let before = evaluate(
            Some(&ev),
            &body_v2(canister, t + 1),
            t,
            t + 2,
            Some((nns_trust(), used(false))),
        );
        assert_eq!(
            before.outcome.as_ref().unwrap_err().0,
            INDEX_ATTESTATION_INVALID
        );
        assert!(before.detail.contains("predates uninstall"));
        let late = evaluate(
            Some(&ev),
            &body_v2(canister, t - PROTECTED_WINDOW_NS - 1),
            t,
            t + 2,
            Some((nns_trust(), used(false))),
        );
        assert_eq!(
            late.outcome.as_ref().unwrap_err().0,
            INDEX_ATTESTATION_INVALID
        );
        assert!(late.detail.contains("beyond the 24 h protected window"));
        let no_anchor = evaluate(
            Some(&ev),
            &body_v2(canister, 0),
            t,
            t + 2,
            Some((nns_trust(), used(false))),
        );
        assert_eq!(
            no_anchor.outcome.as_ref().unwrap_err().0,
            INDEX_ATTESTATION_INVALID
        );
    }

    /// G rule 1: the selector is not evidence. The same certificate under a wrong configured root
    /// fails authentication; an unavailable root (non-production selector without the fixture
    /// flag) is a named failure; a non-production root is announced in the verdict detail.
    #[test]
    fn trust_root_is_a_selector_not_evidence() {
        let (canister, out) = mainnet();
        let u = out.certificate_time_ns - 1_000;
        let body = body_v2(canister, u);
        let ev = evidence(out.certified_module_hash);
        let mut wrong_root = nns_trust().to_vec();
        let last = wrong_root.len() - 1;
        wrong_root[last] ^= 0x01;
        let r = evaluate(
            Some(&ev),
            &body,
            u + 1,
            u + 2,
            Some((&wrong_root, used(true))),
        );
        assert_eq!(
            r.outcome.as_ref().unwrap_err().0,
            INDEX_ATTESTATION_INVALID,
            "{}",
            r.detail
        );
        let none = evaluate(Some(&ev), &body, u + 1, u + 2, None);
        assert_eq!(
            none.outcome.as_ref().unwrap_err().0,
            INDEX_ATTESTATION_INVALID
        );
        assert!(none.detail.contains("fixture-root flag"));
        // announced non-production root (mainnet DER stands in for a fixture root here)
        let announced = evaluate(
            Some(&ev),
            &body,
            u + 1,
            u + 2,
            Some((nns_trust(), used(true))),
        );
        assert_eq!(announced.outcome, Ok(V3aOutcome::Pass));
        assert!(announced.detail.contains("NON-PRODUCTION"));
        assert_eq!(
            announced.trust_root.as_ref().map(|t| t.non_production),
            Some(true)
        );
    }

    /// A1 commitment cert has `certified_data`, not `module_hash` → INVALID (not unavailable).
    #[test]
    fn a1_commitment_cert_is_invalid_not_unavailable() {
        let canister = Principal::from_text("iplx4-aiaaa-aaaap-quuuq-cai").unwrap();
        let ev = IndexCodeIdentityEvidence {
            certificate_bytes: a1_commitment_cert().to_vec(),
            index_module_hash: Some([0u8; 32]),
        };
        let r = evaluate(
            Some(&ev),
            &body_v2(canister, 1),
            1,
            2,
            Some((nns_trust(), used(false))),
        );
        assert_eq!(r.outcome.as_ref().unwrap_err().0, INDEX_ATTESTATION_INVALID);
        assert!(r.detail.contains("module_hash"), "{}", r.detail);
    }

    #[test]
    fn timing_axis_is_non_gating_and_exact() {
        let commit = 1_000_000_000_000u64;
        assert_eq!(
            timing_qualifier(commit + 10 + ATTESTATION_DELAY_NS, commit + 10, commit),
            TIMING_ROUTINE
        );
        assert_eq!(
            timing_qualifier(commit + 10 + ATTESTATION_DELAY_NS + 1, commit + 10, commit),
            TIMING_DELAY_EXCEEDED
        );
        assert_eq!(
            timing_qualifier(commit + COMPLETION_WINDOW_NS + 1, commit + 10, commit),
            TIMING_OUTSIDE_COMPLETION_WINDOW
        );
        assert_eq!(timing_qualifier(10, 20, 1), TIMING_PREDATES_COMMITMENT);
        // a PASS with an exceeded delay is still PASS: timing never gates
        let (canister, out) = mainnet();
        let u = out.certificate_time_ns - 1_000;
        let r = evaluate(
            Some(&evidence(out.certified_module_hash)),
            &body_v2(canister, u),
            out.certificate_time_ns - ATTESTATION_DELAY_NS - 1,
            u + 2,
            Some((nns_trust(), used(false))),
        );
        assert_eq!(r.outcome, Ok(V3aOutcome::Pass));
        assert_eq!(r.timing, TIMING_DELAY_EXCEEDED);
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
            V3A_PASS,
            V3A_PENDING_IN_PROTECTED_WINDOW,
            V3A_PERMANENTLY_UNAVAILABLE,
            INDEX_ATTESTATION_INVALID,
            INDEX_HASH_MISMATCH,
            TIMING_ROUTINE,
            TIMING_DELAY_EXCEEDED,
            TIMING_PREDATES_COMMITMENT,
            TIMING_OUTSIDE_COMPLETION_WINDOW,
            TIMING_NOT_APPLICABLE,
            "openchatzd.cvdr.portable_package",
            "subnet-attested installed module identity during the finalization/certification window",
        ] {
            assert!(src.contains(label), "open-chatZD cvdr_index_attestation.rs missing `{label}`");
        }
    }
}
