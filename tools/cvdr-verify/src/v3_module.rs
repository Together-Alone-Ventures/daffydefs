use anyhow::Result;
use candid::Principal;
use ic_agent::Agent;
use zombie_core::receipt::DeletionReceipt;

pub enum V3Classification {
    Match,
    MismatchExpected,
    MismatchSuspicious,
    FullMatch,
    MismatchExpectedWithProvenance,
    Failed(String),
}

pub struct V3Result {
    pub classification: V3Classification,
}

#[allow(dead_code)]
impl V3Result {
    pub fn passed(&self) -> bool {
        // V3 doesn't have a hard pass/fail — only SUSPICIOUS is a concern
        !matches!(
            self.classification,
            V3Classification::MismatchSuspicious | V3Classification::Failed(_)
        )
    }

    pub fn summary(&self) -> String {
        match &self.classification {
            V3Classification::Match =>
                "V3: MATCH — canister code unchanged since deletion".to_string(),
            V3Classification::MismatchExpected =>
                "V3: MISMATCH-EXPECTED — canister upgraded since deletion \
                 (receipt remains valid under prior code version)".to_string(),
            V3Classification::MismatchSuspicious =>
                "V3: MISMATCH-SUSPICIOUS — receipt has dev zeros, \
                 cannot verify code provenance".to_string(),
            V3Classification::FullMatch =>
                "V3: FULL MATCH — code provenance confirmed end-to-end \
                 (on-chain == receipt == published)".to_string(),
            V3Classification::MismatchExpectedWithProvenance =>
                "V3: MISMATCH-EXPECTED with provenance — upgraded since deletion, \
                 but deletion-time code confirmed against published hash".to_string(),
            V3Classification::Failed(e) =>
                format!("V3: FAILED — {}", e),
        }
    }
}

/// Verify module hash: on-chain vs receipt, optionally vs published build.
pub async fn verify(
    agent: &Agent,
    canister_id: Principal,
    receipt: &DeletionReceipt,
    published_hash: Option<[u8; 32]>,
) -> V3Result {
    let receipt_hash = receipt.module_hash;
    let zeros = [0u8; 32];

    // Fetch current on-chain module hash
    let onchain_hash = match read_module_hash(agent, canister_id).await {
        Ok(h) => h,
        Err(e) => return V3Result {
            classification: V3Classification::Failed(
                format!("Could not read module hash: {}", e)
            ),
        },
    };

    // Three-way classification
    if receipt_hash == zeros {
        return V3Result { classification: V3Classification::MismatchSuspicious };
    }

    if onchain_hash == receipt_hash {
        match published_hash {
            Some(pub_hash) if pub_hash == receipt_hash => {
                V3Result { classification: V3Classification::FullMatch }
            }
            Some(_) => V3Result {
                classification: V3Classification::Failed(
                    "on-chain matches receipt but differs from published hash — investigate"
                        .to_string()
                ),
            },
            None => V3Result { classification: V3Classification::Match },
        }
    } else {
        match published_hash {
            Some(pub_hash) if pub_hash == receipt_hash => {
                V3Result { classification: V3Classification::MismatchExpectedWithProvenance }
            }
            _ => V3Result { classification: V3Classification::MismatchExpected },
        }
    }
}

/// Read the canister's current module hash via read_state.
async fn read_module_hash(agent: &Agent, canister_id: Principal) -> Result<[u8; 32]> {
    let hash_bytes = agent
        .read_state_canister_info(canister_id, "module_hash")
        .await
        .map_err(|e| anyhow::anyhow!("read_state module_hash failed: {}", e))?;

    hash_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("module_hash from IC is not 32 bytes"))
}

// ===========================================================================
// V3-A — archival attested-code-identity check (offline, embedded certificates)
// ===========================================================================
//
// V3-A validates the finalized receipt's *stored* `module_hash_certificate`
// (subnet read_state over /canister/<id>/module_hash) against its
// `bls_certificate`. It requires NO live canister access and so coexists with
// the live corroboration in `verify` above — archival verification from the
// exported artifact alone. Ops-integrity/attestation vocabulary only; V1 remains
// the transition-integrity gate.

use zombie_core::nns_keys;
use zombie_core::receipt::ReceiptState;
use zombie_core::MAX_FINALIZATION_DELAY_NS;

/// V3-A classification (ratified vocabulary).
#[derive(Debug, Clone, PartialEq)]
pub enum V3aClassification {
    /// V3-A pass: both certificates valid under the same IC root, path/value/
    /// range OK, and 0 ≤ t(module_hash) − t(bls) ≤ MAX_FINALIZATION_DELAY_NS.
    SubnetAttested { delta_secs: f64 },
    /// Valid, but the delay exceeds `MAX_FINALIZATION_DELAY_NS` — a downgrade
    /// (LateFinalized-style), never a rejection.
    DelayExceeded { delta_secs: f64 },
    /// Non-attested but benign: a v2/v3 receipt (predates V3-A), or a v4 receipt
    /// with no `module_hash_certificate`. Deployer-declared code identity.
    DeployerDeclared,
    /// `ReceiptState::Pending` (neither certificate). Export permitted; labelled
    /// non-attested. Not a failure.
    Pending,
    /// A certificate is present but a normative check failed (present-but-invalid
    /// — wrong value/canister/path/range/root, ordering failure, or incomplete
    /// finalization). A red flag, never a pass.
    Failed(String),
}

pub struct V3aResult {
    pub classification: V3aClassification,
}

impl V3aResult {
    fn of(classification: V3aClassification) -> Self {
        Self { classification }
    }

    /// A present-but-invalid certificate is a hard failure. Absent/pending/
    /// declared/late are non-attested but not process failures.
    pub fn passed(&self) -> bool {
        !matches!(self.classification, V3aClassification::Failed(_))
    }

    /// True only for a clean subnet-attested pass. Missing V3-A is never a pass.
    /// (Used by the corpus; the CLI report surfaces the full classification.)
    #[allow(dead_code)]
    pub fn attested(&self) -> bool {
        matches!(self.classification, V3aClassification::SubnetAttested { .. })
    }

    pub fn summary(&self) -> String {
        match &self.classification {
            V3aClassification::SubnetAttested { delta_secs } => format!(
                "V3-A: SUBNET-ATTESTED — code identity certified by the subnet \
                 (finalization delay {delta_secs:.1}s)"
            ),
            V3aClassification::DelayExceeded { delta_secs } => format!(
                "V3-A: DELAY_EXCEEDED — attested but finalized {delta_secs:.1}s after \
                 the commitment (> {}s threshold); downgrade, not rejection",
                MAX_FINALIZATION_DELAY_NS / 1_000_000_000
            ),
            V3aClassification::DeployerDeclared =>
                "V3-A: DEPLOYER-DECLARED — no subnet-attested module-hash certificate \
                 (non-attested)".to_string(),
            V3aClassification::Pending =>
                "V3-A: PENDING — receipt not finalized (neither certificate); \
                 non-attested, export permitted".to_string(),
            V3aClassification::Failed(e) =>
                format!("V3-A: FAILED — {e}"),
        }
    }
}

/// Timing verdict from the two certificate `/time`s (pure; offline-testable).
/// The security bound is certificate time only — never the receipt's internal
/// deletion timestamp.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum TimingVerdict {
    Ordered { delta_ns: u64 },
    DelayExceeded { delta_ns: u64 },
    OrderingFailure { bls_ns: u64, module_ns: u64 },
}

/// t(module_hash cert) must be ≥ t(bls cert). A negative delta is an ordering
/// FAILURE (never a delay verdict). delta > MAX_FINALIZATION_DELAY_NS is
/// DELAY_EXCEEDED.
pub(crate) fn classify_timing(bls_time_ns: u64, module_time_ns: u64) -> TimingVerdict {
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

/// V3-A: offline archival attested-code-identity verification from the receipt's
/// embedded certificates alone. No agent / no live canister access.
pub fn verify_v3a(receipt: &DeletionReceipt) -> V3aResult {
    // v2/v3 predate subnet-attested identity — never classified by the v4
    // three-state rule (the historical misclassification this guards against).
    if receipt.protocol_version != "mktd02-v4" {
        return V3aResult::of(V3aClassification::DeployerDeclared);
    }

    // Protocol-aware three-state rule (zombie-core `ReceiptState`), scoped to v4.
    match receipt.state() {
        ReceiptState::Pending => return V3aResult::of(V3aClassification::Pending),
        ReceiptState::InvalidIncompleteFinalization => {
            return V3aResult::of(V3aClassification::Failed(
                "incomplete finalization: exactly one of bls_certificate / \
                 module_hash_certificate is present"
                    .to_string(),
            ))
        }
        ReceiptState::FinalizedCandidate => { /* both present — run the six checks */ }
    }

    let (Some(bls_cert), Some(mh_cert)) =
        (&receipt.bls_certificate, &receipt.module_hash_certificate)
    else {
        // Unreachable under FinalizedCandidate; fail closed.
        return V3aResult::of(V3aClassification::Failed(
            "internal: FinalizedCandidate without both certificates".to_string(),
        ));
    };

    // Same trust-root context for both certificates.
    let trust_id = receipt.trust_root_key_id.trim();
    let Some(trust_key) = nns_keys::lookup_key(trust_id) else {
        return V3aResult::of(V3aClassification::Failed(format!(
            "unknown trust_root_key_id '{trust_id}'"
        )));
    };
    let root = trust_key.der_bytes;

    // Check 1 (bls) + 3 + certified_data == commitment; capture t(bls).
    let bls_time_ns =
        match crate::v2_certificate::verify_certificate_over_certified_data(
            bls_cert,
            receipt.canister_id,
            &receipt.certified_commitment,
            root,
        ) {
            Ok(o) => o.certificate_time_ns,
            Err(e) => {
                return V3aResult::of(V3aClassification::Failed(format!(
                    "bls_certificate: {e}"
                )))
            }
        };

    // Checks 1 (module) + 2 (exact path) + 3; capture certified value + t(module).
    let mh = match crate::v2_certificate::verify_certificate_over_module_hash(
        mh_cert,
        receipt.canister_id,
        root,
    ) {
        Ok(o) => o,
        Err(e) => {
            return V3aResult::of(V3aClassification::Failed(format!(
                "module_hash_certificate: {e}"
            )))
        }
    };

    // Check 4: certified module hash == receipt's embedded module_hash.
    if mh.certified_module_hash != receipt.module_hash {
        return V3aResult::of(V3aClassification::Failed(format!(
            "certified module_hash {} != receipt module_hash {}",
            hex::encode(mh.certified_module_hash),
            hex::encode(receipt.module_hash)
        )));
    }

    // Checks 5 & 6: ordering + delay threshold (certificate time is the bound).
    match classify_timing(bls_time_ns, mh.certificate_time_ns) {
        TimingVerdict::OrderingFailure { bls_ns, module_ns } => {
            V3aResult::of(V3aClassification::Failed(format!(
                "ordering failure: t(module_hash cert)={module_ns} < t(bls cert)={bls_ns}"
            )))
        }
        TimingVerdict::DelayExceeded { delta_ns } => V3aResult::of(
            V3aClassification::DelayExceeded {
                delta_secs: delta_ns as f64 / 1e9,
            },
        ),
        TimingVerdict::Ordered { delta_ns } => V3aResult::of(
            V3aClassification::SubnetAttested {
                delta_secs: delta_ns as f64 / 1e9,
            },
        ),
    }
}

// ===========================================================================
// V3-A corpus (offline). Cases needing a REAL module-hash certificate are
// #[ignore]d pending the operator's mainnet capture (see report / fixtures).
// ===========================================================================
#[cfg(test)]
mod v3a_tests {
    use super::*;
    use candid::Principal;
    use zombie_core::receipt::ProtocolVersion;

    const MH: [u8; 32] = [0x33; 32];

    /// A v4 receipt with the given certificate presence. Cert bytes are dummy —
    /// classification-only tests (Pending / Invalid / DeployerDeclared) return
    /// before any BLS validation, so dummy bytes never reach the cert machinery.
    fn v4_receipt(bls: Option<Vec<u8>>, mh_cert: Option<Vec<u8>>) -> DeletionReceipt {
        DeletionReceipt {
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
        use std::path::Path;
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/a1_mainnet_cvdr.json");
        let raw = std::fs::read_to_string(&path).expect("A1 fixture present");
        let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
        let canister = Principal::from_text(v["canister_id"].as_str().unwrap()).unwrap();
        let cert = hex::decode(v["certificate_bytes"].as_str().unwrap()).unwrap();
        (canister, cert)
    }

    /// Load the REAL mainnet module-hash certificate captured over
    /// `/canister/5g26e.../module_hash` (operator capture, 15 Jul 2026;
    /// see fixtures/README_V3A_PENDING.md). Returns the canister, the raw CBOR
    /// certificate bytes, the pinned certified module hash, and the pinned
    /// certificate `/time`.
    fn load_v4_module_hash_cert() -> (Principal, Vec<u8>, [u8; 32], u64) {
        use std::path::Path;
        let path =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/v4_module_hash_cert.json");
        let raw = std::fs::read_to_string(&path).expect("v4 module-hash fixture present");
        let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
        let canister = Principal::from_text(v["canister_id"].as_str().unwrap()).unwrap();
        let cert = hex::decode(v["certificate_bytes"].as_str().unwrap()).unwrap();
        let mut mh = [0u8; 32];
        mh.copy_from_slice(&hex::decode(v["certified_module_hash"].as_str().unwrap()).unwrap());
        let time_ns = v["certificate_time_ns"].as_u64().unwrap();
        (canister, cert, mh, time_ns)
    }

    // --- Case 2: WRONG PATH (write-first negative) --------------------------
    // The A1 real mainnet cert is over /canister/<id>/certified_data. Feeding it
    // to the module_hash verifier MUST fail: lookup_value is path-agnostic, so a
    // certificate over any other path can never be accepted as a module-hash
    // attestation. Uses a REAL, BLS-valid cert (so the failure is the path, not
    // the signature).
    #[test]
    fn case2_certificate_over_wrong_path_is_rejected() {
        let (canister, cert) = load_a1();
        let der = zombie_core::nns_keys::lookup_key("mainnet").unwrap().der_bytes;
        let res = crate::v2_certificate::verify_certificate_over_module_hash(&cert, canister, der);
        let err = res.expect_err("a certified_data-only cert must not pass the module_hash check");
        assert!(err.contains("module_hash not found"), "got: {err}");
    }

    // --- Case 5: WRONG ROOT / trust-root context ----------------------------
    #[test]
    fn case5_wrong_trust_root_fails_bls() {
        let (canister, cert) = load_a1();
        // A syntactically-plausible but wrong DER key (not the NNS root).
        let wrong_der: Vec<u8> = vec![0u8; zombie_core::nns_keys::lookup_key("mainnet").unwrap().der_bytes.len()];
        let res = crate::v2_certificate::verify_certificate_over_module_hash(&cert, canister, &wrong_der);
        assert!(res.is_err(), "cert must not validate under a wrong trust root");
    }

    // --- Cases 4 & 6: ordering failure (negative delta / stale certificate) --
    #[test]
    fn case4_negative_delta_is_ordering_failure() {
        // module-hash cert time strictly before bls cert time.
        let v = classify_timing(2_000, 1_999);
        assert!(matches!(v, TimingVerdict::OrderingFailure { .. }), "got {v:?}");
    }

    #[test]
    fn case6_stale_module_cert_predating_commitment_is_ordering_failure() {
        // "stale": module-hash cert captured well before the certified-data cert.
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
        // exactly at threshold => Ordered (clean).
        let at = bls_t + MAX_FINALIZATION_DELAY_NS;
        assert!(matches!(classify_timing(bls_t, at), TimingVerdict::Ordered { .. }));
        // one ns over => DelayExceeded (downgrade).
        let over = bls_t + MAX_FINALIZATION_DELAY_NS + 1;
        assert!(matches!(classify_timing(bls_t, over), TimingVerdict::DelayExceeded { .. }));
        // zero delta => Ordered.
        assert!(matches!(classify_timing(bls_t, bls_t), TimingVerdict::Ordered { delta_ns: 0 }));
    }

    // --- Case 7: finalized-claim with exactly one certificate ---------------
    #[test]
    fn case7_incomplete_finalization_is_failed() {
        // bls present, module-hash cert absent => ReceiptState::InvalidIncompleteFinalization.
        let r = v4_receipt(Some(vec![0xDE, 0xAD]), None);
        let res = verify_v3a(&r);
        assert!(matches!(res.classification, V3aClassification::Failed(_)), "got {:?}", res.classification);
        assert!(!res.passed(), "incomplete finalization must not pass");
        // the other permutation (module cert present, bls absent) is also Failed.
        let r2 = v4_receipt(None, Some(vec![0xBE, 0xEF]));
        assert!(matches!(verify_v3a(&r2).classification, V3aClassification::Failed(_)));
    }

    // --- Case 8: pending exported => permitted, non-attested ----------------
    #[test]
    fn case8_pending_receipt_is_pending_non_attested() {
        let r = v4_receipt(None, None);
        let res = verify_v3a(&r);
        assert_eq!(res.classification, V3aClassification::Pending);
        assert!(res.passed(), "pending export is permitted (not a process failure)");
        assert!(!res.attested(), "pending is non-attested");
    }

    // --- Case 9: missing V3-A => non-attested, never a pass -----------------
    #[test]
    fn case9_missing_v3a_is_never_attested() {
        // v4 with no certs (pending) and v2/v3 (declared) are all non-attested.
        assert!(!verify_v3a(&v4_receipt(None, None)).attested());
        let mut v3 = v4_receipt(Some(vec![1]), Some(vec![2]));
        v3.protocol_version = ProtocolVersion::V3.into();
        let res = verify_v3a(&v3);
        assert_eq!(res.classification, V3aClassification::DeployerDeclared);
        assert!(!res.attested(), "missing V3-A is never a pass");
    }

    // --- Regression: v2/v3 receipts are NOT classified by v4 states ---------
    #[test]
    fn regression_v2_v3_not_classified_by_v4_states() {
        // A v3 receipt that (structurally) carries a stray module cert must NOT
        // be run through the v4 three-state rule — it is DeployerDeclared, never
        // Invalid/Pending/Attested. (The historical misclassification.)
        let mut v3 = v4_receipt(Some(vec![1]), Some(vec![2]));
        v3.protocol_version = ProtocolVersion::V3.into();
        assert_eq!(verify_v3a(&v3).classification, V3aClassification::DeployerDeclared);

        let mut v2 = v4_receipt(None, None);
        v2.protocol_version = ProtocolVersion::V2.into();
        assert_eq!(verify_v3a(&v2).classification, V3aClassification::DeployerDeclared);
    }

    // --- Case 1: certified value != receipt.module_hash ---------------------
    // Uses the REAL, BLS-valid mainnet module-hash certificate. The certificate
    // machinery validates it end-to-end (BLS → NNS delegation → 5g26e range →
    // exact /module_hash path) and returns the subnet-certified value; check 4
    // (`verify_v3a`) then compares that value to `receipt.module_hash`. Here we
    // exercise the comparison at the certificate level (the same value the full
    // pipeline feeds into check 4): the certified value MATCHES the pinned true
    // hash and MISMATCHES a deliberately-wrong 32 bytes.
    #[test]
    fn case1_value_mismatch_is_failed() {
        let (canister, cert, pinned_hash, pinned_time_ns) = load_v4_module_hash_cert();
        let der = zombie_core::nns_keys::lookup_key("mainnet").unwrap().der_bytes;
        let out = crate::v2_certificate::verify_certificate_over_module_hash(&cert, canister, der)
            .expect("real mainnet module-hash certificate must validate");
        // Fixture integrity: the certificate certifies exactly the pinned hash
        // and /time recorded in fixtures/v4_module_hash_cert.json.
        assert_eq!(
            out.certified_module_hash, pinned_hash,
            "certified value {} != pinned fixture value {}",
            hex::encode(out.certified_module_hash),
            hex::encode(pinned_hash)
        );
        assert_eq!(
            out.certificate_time_ns, pinned_time_ns,
            "certificate /time {} != pinned fixture time {}",
            out.certificate_time_ns, pinned_time_ns
        );
        // Check-4 semantics: a receipt claiming a DIFFERENT module_hash mismatches
        // the certified value — the condition `verify_v3a` reports as Failed.
        let wrong: [u8; 32] = [0x00; 32];
        assert_ne!(
            out.certified_module_hash, wrong,
            "value-mismatch detection: certified {} must differ from a wrong receipt.module_hash",
            hex::encode(out.certified_module_hash)
        );
    }

    // --- Case 3: delegation range excludes the canister ---------------------
    // The REAL 5g26e module-hash certificate's delegation authorizes 5g26e's app
    // subnet. Presenting the SAME certificate but asserting a canister on a
    // DIFFERENT subnet (an NNS/root-subnet canister) must be rejected by the
    // delegation canister-range check — before any /module_hash lookup. This is
    // the V3-A-framed counterpart to v2_certificate's authorize_canister_ranges
    // unit tests, now over a real captured certificate.
    #[test]
    fn case3_delegation_range_excludes_canister() {
        let (_canister, cert, _mh, _t) = load_v4_module_hash_cert();
        let der = zombie_core::nns_keys::lookup_key("mainnet").unwrap().der_bytes;
        // rdmx6-jaaaa-aaaaa-aaadq-cai (Internet Identity) is on the NNS/root
        // subnet — outside the app-subnet range the 5g26e delegation proves.
        let out_of_range = Principal::from_text("rdmx6-jaaaa-aaaaa-aaadq-cai").unwrap();
        let err = crate::v2_certificate::verify_certificate_over_module_hash(
            &cert,
            out_of_range,
            der,
        )
        .expect_err("a cert whose delegation range excludes the canister must be rejected");
        assert!(
            err.contains("not authorized for this canister"),
            "expected a delegation range-authorization failure, got: {err}"
        );
    }

    // --- Positive: subnet-attested PASS (two real certs) --------------------
    // CONSTRAINED — cannot be built honestly at this time. The composite needs a
    // real `certified_data` (commitment) certificate over the SAME canister as a
    // real module-hash certificate. Source verification (per brief 2C / the C22
    // caveat) shows this is not obtainable for the DaffyDefs factory 5g26e:
    //   * `/canister/<id>/certified_data` is NOT externally readable via anonymous
    //     read_state (IC spec; helper module doc) — only the canister itself can
    //     expose its data_certificate;
    //   * the factory 5g26e exposes NO query returning a certificate
    //     (profile_factory.did: no state-hash / certificate method);
    //   * only a profile_canister exposes `mktd_get_state_hash()` (a real
    //     certified_data cert), but profile-canister IDs are per-user, created
    //     dynamically, not enumerable (list_all_profiles is admin-only), and
    //     minting one is a mutating update call — out of scope for a capture.
    // The genuine two-cert positive arrives from a DaffyDefs end-to-end finalized
    // receipt at Gate 2 (fixtures/v4_finalized_mainnet.json) — now landed; the test
    // below exercises it against the real artifact rather than by inspection.
    #[test]
    fn positive_subnet_attested_pass() {
        // GENUINE mainnet finalized v4 receipt — DaffyDefs Gate 2 ceremony
        // (2026-07-21) + R-a/R-b remediation. Carries a real bls (certified_data)
        // cert and a real module-hash cert over the ceremony profile canister
        // y5izv, ordered within MAX_FINALIZATION_DELAY_NS. Supersedes the deferred
        // composite (README §2). The certified module hash is the receipt's
        // deletion-time attested anchor 85a326cd (not the current live hash — the
        // canister was legitimately upgraded post-finalization).
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("fixtures/v4_finalized_mainnet.json");
        let receipt = crate::fetch::load_receipt_from_file(path.to_str().unwrap())
            .expect("genuine v4 finalized fixture loads");

        // Three-state: both certificates present => FinalizedCandidate.
        assert_eq!(
            receipt.state(),
            zombie_core::receipt::ReceiptState::FinalizedCandidate,
            "finalized v4 receipt with both certs must classify FinalizedCandidate"
        );

        // V3-A positive path: all six checks green => SUBNET-ATTESTED.
        let res = verify_v3a(&receipt);
        assert!(res.passed(), "V3-A positive must not be a failure");
        assert!(res.attested(), "genuine two-cert receipt must be SUBNET-ATTESTED");
        match res.classification {
            V3aClassification::SubnetAttested { delta_secs } => {
                assert!(delta_secs >= 0.0, "ordered: t(module_hash) >= t(commitment)");
                assert!(
                    (delta_secs * 1e9) < MAX_FINALIZATION_DELAY_NS as f64,
                    "finalization delay under MAX_FINALIZATION_DELAY_NS"
                );
            }
            other => panic!("expected SubnetAttested, got {other:?}"),
        }

        // Scope note: unlike the abandoned composite, the genuine artifact carries
        // the real preimages, so V1's state-transition recomputation also passes
        // end to end. Asserted here — the genuine receipt supports the full
        // pipeline, so this extends beyond the V3-positive scope the composite plan
        // was limited to.
        let v1 = crate::v1_transition::verify(&receipt, receipt.canister_id);
        assert!(
            v1.passed(),
            "genuine receipt supports the full V1 recomputation: {:?}",
            v1.details
        );
    }
}
