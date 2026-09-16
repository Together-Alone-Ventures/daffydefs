//! V3A — subnet-attested code identity (offline, embedded certificates) and
//! V3B — build provenance comparison.
//!
//! V3A validates the finalized receipt's stored `module_hash_certificate`
//! (a subnet `read_state` over `/canister/<id>/module_hash`) together with its
//! `bls_certificate`, against the explicit trust root. It attests the identity
//! of the deployed module at certification time; it does not establish which
//! code ran. The six checks and the timing rule are unchanged from v0.7.0:
//!
//! 1. both certificates validate against the trust root (BLS → NNS delegation);
//! 2. the module-hash certificate's path is exactly `/canister/<id>/module_hash`;
//! 3. the delegation's canister range covers the receipt's canister;
//! 4. the certified module hash equals the receipt's `module_hash`;
//! 5. `t(module_hash cert) ≥ t(bls cert)` — a negative delta is an ordering
//!    failure;
//! 6. a delta above `zombie_core::MAX_FINALIZATION_DELAY_NS` is
//!    `DELAY_EXCEEDED`: a downgrade, not a rejection.
//!
//! The bls certificate's `certified_data` is bound to the value V2 compares
//! for the line (v5: `deletion_event_hash`; v4: `certified_commitment`).

use candid::Principal;
use zombie_core::{AnyDeletionReceipt, ReceiptState, MAX_FINALIZATION_DELAY_NS};

use crate::report::{CheckOutcome, ProtocolLine, TimingFact, REASON_INCOMPLETE_FINALISATION};
use crate::trust_root::TrustRoot;
use crate::v2_certificate::{
    verify_certificate_over_certified_data, verify_certificate_over_module_hash,
};

pub const ERR_V3A_BLS_CERTIFICATE: &str = "v3a:bls-certificate";
pub const ERR_V3A_MODULE_HASH_CERTIFICATE: &str = "v3a:module-hash-certificate";
pub const ERR_V3A_MODULE_HASH_MISMATCH: &str = "v3a:module-hash-mismatch";
pub const ERR_V3A_ORDERING_FAILURE: &str = "v3a:ordering-failure";
pub const ERR_V3B_MODULE_HASH_MISMATCH: &str = "v3b:module-hash-mismatch";

pub const REASON_V3A_LINE_PREDATES: &str = "line predates module-hash certification";
pub const REASON_V3A_PENDING: &str = "pending — neither certificate embedded";
pub const REASON_V3B_NO_PROVENANCE: &str = "no build provenance supplied (--wasm-hash)";

/// Timing verdict labels (unchanged wire strings).
pub const TIMING_ROUTINE: &str = "ROUTINE";
pub const TIMING_DELAY_EXCEEDED: &str = "DELAY_EXCEEDED";
pub const TIMING_ORDERING_FAILURE: &str = "ORDERING_FAILURE";

/// Timing verdict from the two certificate `/time`s (pure; offline-testable).
/// The security bound is certificate time only — never the receipt's internal
/// deletion timestamp.
#[derive(Debug, Clone, PartialEq)]
pub enum TimingVerdict {
    Ordered { delta_ns: u64 },
    DelayExceeded { delta_ns: u64 },
    OrderingFailure { bls_ns: u64, module_ns: u64 },
}

/// t(module_hash cert) must be ≥ t(bls cert). A negative delta is an ordering
/// FAILURE (never a delay verdict). delta > MAX_FINALIZATION_DELAY_NS is
/// DELAY_EXCEEDED.
pub fn classify_timing(bls_time_ns: u64, module_time_ns: u64) -> TimingVerdict {
    if module_time_ns < bls_time_ns {
        return TimingVerdict::OrderingFailure {
            bls_ns: bls_time_ns,
            module_ns: module_time_ns,
        };
    }
    let delta_ns = module_time_ns - bls_time_ns;
    if delta_ns > MAX_FINALIZATION_DELAY_NS {
        TimingVerdict::DelayExceeded { delta_ns }
    } else {
        TimingVerdict::Ordered { delta_ns }
    }
}

/// V3A outcome plus its timing sub-result.
#[derive(Debug, Clone, PartialEq)]
pub struct V3aEvaluation {
    pub outcome: CheckOutcome,
    pub timing: Option<TimingFact>,
}

impl V3aEvaluation {
    fn only(outcome: CheckOutcome) -> Self {
        V3aEvaluation {
            outcome,
            timing: None,
        }
    }
}

struct V3aInputs<'a> {
    canister_id: Principal,
    module_hash: [u8; 32],
    bound_certified_data: [u8; 32],
    bls_certificate: &'a Option<Vec<u8>>,
    module_hash_certificate: &'a Option<Vec<u8>>,
}

/// V3A: offline archival attested-code-identity verification from the
/// receipt's embedded certificates alone. No agent, no live canister access.
pub fn verify_v3a(receipt: &AnyDeletionReceipt, trust_root: &TrustRoot) -> V3aEvaluation {
    let line = ProtocolLine::of(receipt);
    // v2/v3 predate subnet-attested identity — never classified by the
    // three-state rule (the historical misclassification this guards against).
    if !line.has_module_hash_certification() {
        return V3aEvaluation::only(CheckOutcome::not_evaluated(REASON_V3A_LINE_PREDATES));
    }
    match receipt.state() {
        ReceiptState::Pending => {
            return V3aEvaluation::only(CheckOutcome::not_evaluated(REASON_V3A_PENDING))
        }
        ReceiptState::InvalidIncompleteFinalization => {
            return V3aEvaluation::only(CheckOutcome::fail(
                REASON_INCOMPLETE_FINALISATION,
                Some("exactly one of bls_certificate / module_hash_certificate is present".into()),
            ))
        }
        ReceiptState::FinalizedCandidate => {}
    }
    let inputs = match receipt {
        AnyDeletionReceipt::V5(r) => V3aInputs {
            canister_id: r.canister_id,
            module_hash: r.module_hash,
            bound_certified_data: r.deletion_event_hash,
            bls_certificate: &r.bls_certificate,
            module_hash_certificate: &r.module_hash_certificate,
        },
        AnyDeletionReceipt::V4(r) => V3aInputs {
            canister_id: r.canister_id,
            module_hash: r.module_hash,
            bound_certified_data: r.certified_commitment,
            bls_certificate: &r.bls_certificate,
            module_hash_certificate: &r.module_hash_certificate,
        },
    };
    attested_identity(&inputs, trust_root)
}

fn attested_identity(inputs: &V3aInputs, trust_root: &TrustRoot) -> V3aEvaluation {
    let (Some(bls_cert), Some(mh_cert)) = (inputs.bls_certificate, inputs.module_hash_certificate)
    else {
        // Unreachable under FinalizedCandidate; fail closed.
        return V3aEvaluation::only(CheckOutcome::fail(
            REASON_INCOMPLETE_FINALISATION,
            Some("internal: FinalizedCandidate without both certificates".into()),
        ));
    };
    let root = trust_root.der();

    // Check 1 (bls) + 3 + certified_data binding; capture t(bls).
    let bls_time_ns = match verify_certificate_over_certified_data(
        bls_cert,
        inputs.canister_id,
        &inputs.bound_certified_data,
        root,
    ) {
        Ok(o) => o.certificate_time_ns,
        Err(e) => return V3aEvaluation::only(CheckOutcome::fail(ERR_V3A_BLS_CERTIFICATE, Some(e))),
    };

    // Checks 1 (module) + 2 (exact path) + 3; capture certified value + t(module).
    let mh = match verify_certificate_over_module_hash(mh_cert, inputs.canister_id, root) {
        Ok(o) => o,
        Err(e) => {
            return V3aEvaluation::only(CheckOutcome::fail(
                ERR_V3A_MODULE_HASH_CERTIFICATE,
                Some(e),
            ))
        }
    };

    // Check 4: certified module hash == receipt's embedded module_hash.
    if mh.certified_module_hash != inputs.module_hash {
        return V3aEvaluation::only(CheckOutcome::fail(
            ERR_V3A_MODULE_HASH_MISMATCH,
            Some(format!(
                "certified module_hash {} != receipt module_hash {}",
                hex::encode(mh.certified_module_hash),
                hex::encode(inputs.module_hash)
            )),
        ));
    }

    // Checks 5 & 6: ordering + delay threshold (certificate time is the bound).
    let verdict = classify_timing(bls_time_ns, mh.certificate_time_ns);
    let (label, delta_ns) = match verdict {
        TimingVerdict::Ordered { delta_ns } => (TIMING_ROUTINE, Some(delta_ns)),
        TimingVerdict::DelayExceeded { delta_ns } => (TIMING_DELAY_EXCEEDED, Some(delta_ns)),
        TimingVerdict::OrderingFailure { .. } => (TIMING_ORDERING_FAILURE, None),
    };
    let timing = Some(TimingFact::V3aFinalizationDelay {
        bls_certificate_time_ns: bls_time_ns,
        module_hash_certificate_time_ns: mh.certificate_time_ns,
        delta_secs: delta_ns.map(|d| d as f64 / 1e9),
        max_finalization_delay_secs: MAX_FINALIZATION_DELAY_NS / 1_000_000_000,
        verdict: label,
    });
    let outcome = match verdict {
        TimingVerdict::OrderingFailure { bls_ns, module_ns } => CheckOutcome::fail(
            ERR_V3A_ORDERING_FAILURE,
            Some(format!("t(module_hash cert)={module_ns} < t(bls cert)={bls_ns}")),
        ),
        // DELAY_EXCEEDED keeps its existing semantics: attested, downgraded in
        // the timing sub-result, not a rejection.
        _ => CheckOutcome::pass(format!(
            "subnet certificate attests module hash {} on canister {} at certificate time {} ns — the identity of the deployed module at certification time",
            hex::encode(mh.certified_module_hash),
            inputs.canister_id,
            mh.certificate_time_ns
        )),
    };
    V3aEvaluation { outcome, timing }
}

/// V3B: compare the receipt's `module_hash` with supplied build provenance.
/// NOT_EVALUATED unless provenance is supplied; never part of validity.
pub fn verify_v3b(receipt: &AnyDeletionReceipt, published_hash: Option<[u8; 32]>) -> CheckOutcome {
    let Some(published) = published_hash else {
        return CheckOutcome::not_evaluated(REASON_V3B_NO_PROVENANCE);
    };
    let module_hash = match receipt {
        AnyDeletionReceipt::V5(r) => r.module_hash,
        AnyDeletionReceipt::V4(r) => r.module_hash,
    };
    if module_hash == published {
        CheckOutcome::pass(format!(
            "receipt module_hash equals the supplied build hash {} (comparison only; no rebuild performed)",
            hex::encode(published)
        ))
    } else {
        CheckOutcome::fail(
            ERR_V3B_MODULE_HASH_MISMATCH,
            Some(format!(
                "receipt module_hash {} != supplied build hash {}",
                hex::encode(module_hash),
                hex::encode(published)
            )),
        )
    }
}

// ===========================================================================
// V3A corpus (offline, real mainnet certificates).
// ===========================================================================
#[cfg(test)]
mod v3a_tests {
    use super::*;
    use zombie_core::receipt::ProtocolVersion;
    use zombie_core::DeletionReceiptV4;

    const MH: [u8; 32] = [0x33; 32];

    fn mainnet() -> TrustRoot {
        TrustRoot::built_in("mainnet").unwrap()
    }

    /// A v4 receipt with the given certificate presence. Cert bytes are dummy —
    /// classification-only tests (Pending / Invalid / line) return before any
    /// BLS validation, so dummy bytes never reach the cert machinery.
    fn v4_receipt(bls: Option<Vec<u8>>, mh_cert: Option<Vec<u8>>) -> DeletionReceiptV4 {
        DeletionReceiptV4 {
            protocol_version: ProtocolVersion::V4.into(),
            receipt_id: [0x2A; 32],
            canister_id: Principal::from_text("aaaaa-aa").unwrap(),
            record_id: vec![0xAA, 0xBB],
            pre_state_hash: [0x11; 32],
            post_state_hash: [0x22; 32],
            tombstone_hash: [0x44; 32],
            deletion_event_hash: [0x55; 32],
            certified_commitment: [0x66; 32],
            module_hash: MH,
            timestamp: 1_000_000,
            deletion_seq: 1,
            bls_certificate: bls,
            trust_root_key_id: "mainnet".to_string(),
            module_hash_certificate: mh_cert,
        }
    }

    fn load_a1() -> (Principal, Vec<u8>) {
        let path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/a1_mainnet_cvdr.json");
        let raw = std::fs::read_to_string(&path).expect("A1 fixture present");
        let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
        let canister = Principal::from_text(v["canister_id"].as_str().unwrap()).unwrap();
        let cert = hex::decode(v["certificate_bytes"].as_str().unwrap()).unwrap();
        (canister, cert)
    }

    /// Load the REAL mainnet module-hash certificate captured over
    /// `/canister/5g26e.../module_hash` (operator capture, 15 Jul 2026).
    fn load_v4_module_hash_cert() -> (Principal, Vec<u8>, [u8; 32], u64) {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/v4/v4_module_hash_cert.json");
        let raw = std::fs::read_to_string(&path).expect("v4 module-hash fixture present");
        let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
        let canister = Principal::from_text(v["canister_id"].as_str().unwrap()).unwrap();
        let cert = hex::decode(v["certificate_bytes"].as_str().unwrap()).unwrap();
        let mut mh = [0u8; 32];
        mh.copy_from_slice(&hex::decode(v["certified_module_hash"].as_str().unwrap()).unwrap());
        let time_ns = v["certificate_time_ns"].as_u64().unwrap();
        (canister, cert, mh, time_ns)
    }

    // --- Case 2: WRONG PATH -------------------------------------------------
    // The A1 real mainnet cert is over /canister/<id>/certified_data. Feeding it
    // to the module_hash verifier MUST fail (a REAL, BLS-valid cert, so the
    // failure is the path, not the signature).
    #[test]
    fn case2_certificate_over_wrong_path_is_rejected() {
        let (canister, cert) = load_a1();
        let err = verify_certificate_over_module_hash(&cert, canister, mainnet().der())
            .expect_err("a certified_data-only cert must not pass the module_hash check");
        assert!(err.contains("module_hash not found"), "got: {err}");
    }

    // --- Case 5: WRONG ROOT / trust-root context ----------------------------
    #[test]
    fn case5_wrong_trust_root_fails_bls() {
        let (canister, cert) = load_a1();
        let wrong_der: Vec<u8> = vec![0u8; mainnet().der().len()];
        assert!(verify_certificate_over_module_hash(&cert, canister, &wrong_der).is_err());
    }

    // --- Cases 4 & 6: ordering failure (negative delta / stale certificate) --
    #[test]
    fn case4_negative_delta_is_ordering_failure() {
        let v = classify_timing(2_000, 1_999);
        assert!(
            matches!(v, TimingVerdict::OrderingFailure { .. }),
            "got {v:?}"
        );
    }

    #[test]
    fn case6_stale_module_cert_predating_commitment_is_ordering_failure() {
        let bls_t = 1_700_000_000_000_000_000u64;
        let module_t = bls_t - 10 * 1_000_000_000; // 10s earlier
        assert!(matches!(
            classify_timing(bls_t, module_t),
            TimingVerdict::OrderingFailure { .. }
        ));
    }

    // --- Case 10: delay threshold boundary ----------------------------------
    #[test]
    fn case10_delta_at_and_over_threshold() {
        let bls_t = 1_000_000_000u64;
        let at = bls_t + MAX_FINALIZATION_DELAY_NS;
        assert!(matches!(
            classify_timing(bls_t, at),
            TimingVerdict::Ordered { .. }
        ));
        let over = bls_t + MAX_FINALIZATION_DELAY_NS + 1;
        assert!(matches!(
            classify_timing(bls_t, over),
            TimingVerdict::DelayExceeded { .. }
        ));
        assert!(matches!(
            classify_timing(bls_t, bls_t),
            TimingVerdict::Ordered { delta_ns: 0 }
        ));
    }

    // --- Case 7: finalized-claim with exactly one certificate ---------------
    #[test]
    fn case7_incomplete_finalization_is_failed() {
        for r in [
            v4_receipt(Some(vec![0xDE, 0xAD]), None),
            v4_receipt(None, Some(vec![0xBE, 0xEF])),
        ] {
            let res = verify_v3a(&AnyDeletionReceipt::V4(r), &mainnet());
            assert_eq!(
                res.outcome.error(),
                Some(REASON_INCOMPLETE_FINALISATION),
                "{:?}",
                res.outcome
            );
        }
    }

    // --- Case 8: pending => not evaluated, non-attested ---------------------
    #[test]
    fn case8_pending_receipt_is_not_evaluated() {
        let res = verify_v3a(&AnyDeletionReceipt::V4(v4_receipt(None, None)), &mainnet());
        assert_eq!(res.outcome, CheckOutcome::not_evaluated(REASON_V3A_PENDING));
    }

    // --- Case 9 / regression: v2/v3 are never classified by v4 states -------
    #[test]
    fn case9_v2_v3_are_not_evaluated_never_attested() {
        for version in [ProtocolVersion::V2, ProtocolVersion::V3] {
            let mut r = v4_receipt(Some(vec![1]), None);
            r.protocol_version = version.into();
            let res = verify_v3a(&AnyDeletionReceipt::V4(r), &mainnet());
            assert_eq!(
                res.outcome,
                CheckOutcome::not_evaluated(REASON_V3A_LINE_PREDATES)
            );
        }
    }

    // --- Case 1: certified value != receipt.module_hash ---------------------
    #[test]
    fn case1_value_mismatch_is_failed() {
        let (canister, cert, pinned_hash, pinned_time_ns) = load_v4_module_hash_cert();
        let out = verify_certificate_over_module_hash(&cert, canister, mainnet().der())
            .expect("real mainnet module-hash certificate must validate");
        assert_eq!(out.certified_module_hash, pinned_hash);
        assert_eq!(out.certificate_time_ns, pinned_time_ns);
        assert_ne!(out.certified_module_hash, [0x00; 32]);
    }

    // --- Case 3: delegation range excludes the canister ---------------------
    #[test]
    fn case3_delegation_range_excludes_canister() {
        let (_canister, cert, _mh, _t) = load_v4_module_hash_cert();
        // rdmx6-jaaaa-aaaaa-aaadq-cai (Internet Identity) is on the NNS/root
        // subnet — outside the app-subnet range the 5g26e delegation proves.
        let out_of_range = Principal::from_text("rdmx6-jaaaa-aaaaa-aaadq-cai").unwrap();
        let err = verify_certificate_over_module_hash(&cert, out_of_range, mainnet().der())
            .expect_err("a cert whose delegation range excludes the canister must be rejected");
        assert!(
            err.contains("not authorized for this canister"),
            "got: {err}"
        );
    }

    // --- Positive: subnet-attested PASS (two real certs) --------------------
    // GENUINE mainnet finalized v4 receipt — DaffyDefs reference CVDR, both
    // real certificates, ordered within MAX_FINALIZATION_DELAY_NS.
    #[test]
    fn positive_subnet_attested_pass() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/v4/v4_finalized_mainnet.json");
        let receipt = crate::intake::read_receipt_file(path.to_str().unwrap())
            .expect("genuine v4 fixture loads");
        assert_eq!(receipt.state(), ReceiptState::FinalizedCandidate);

        let res = verify_v3a(&receipt, &mainnet());
        assert!(res.outcome.is_pass(), "{:?}", res.outcome);
        match res.timing {
            Some(TimingFact::V3aFinalizationDelay {
                delta_secs: Some(d),
                verdict,
                ..
            }) => {
                assert_eq!(verdict, TIMING_ROUTINE);
                assert!(d >= 0.0 && (d * 1e9) < MAX_FINALIZATION_DELAY_NS as f64);
            }
            other => panic!("expected a routine finalization delay, got {other:?}"),
        }
        assert!(crate::v1_transition::verify(&receipt).is_pass());

        // Check 4 on the genuine receipt: a different receipt module_hash fails.
        let AnyDeletionReceipt::V4(mut tampered) = receipt else {
            panic!("v4 fixture")
        };
        tampered.module_hash = [0u8; 32];
        let res = verify_v3a(&AnyDeletionReceipt::V4(tampered), &mainnet());
        assert_eq!(res.outcome.error(), Some(ERR_V3A_MODULE_HASH_MISMATCH));
    }

    #[test]
    fn v3b_is_not_evaluated_without_provenance_and_compares_when_supplied() {
        let r = AnyDeletionReceipt::V4(v4_receipt(None, None));
        assert_eq!(
            verify_v3b(&r, None),
            CheckOutcome::not_evaluated(REASON_V3B_NO_PROVENANCE)
        );
        assert!(verify_v3b(&r, Some(MH)).is_pass());
        assert_eq!(
            verify_v3b(&r, Some([0u8; 32])).error(),
            Some(ERR_V3B_MODULE_HASH_MISMATCH)
        );
    }
}
