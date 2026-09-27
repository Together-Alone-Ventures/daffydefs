//! Cross-repo alignment fixtures + pipeline tests (suite v5).
//!
//! This module INDEPENDENTLY re-derives OpenChatZD's leaf-test unit vectors from the frozen
//! formulas and requires byte-equal recompute of CD's independently derived values. A disagreement
//! is a real layout drift and the assertion FAILS loudly (no fudging).
//!
//! CD anchors (historical RECEIPT_BODY_V1 vector, full byte equality):
//! - leaf               `7aeb124f69688671b350b80442705473c092dfecea8f8791c45375eff8f87c3e` (300-byte body)
//! - targets_commitment `a06af2c83778d1e4bbf685e99d8a0f01229d8a24ea41d8edae9d65e71b83b618`
//! - witness digest     `eb5c5b2195e62d996b84c9bcc8259d19a83786a2f59e0878cec84c811f669aa0` — the
//!   ic-certification DOCS-EXAMPLE tree, a known-good vector for the witness DECODE/digest machinery.
//!
//! RECEIPT_BODY_V2 vector (suite v5): built from the normative formulas (R-1 salted `record_id`,
//! R-4 body); a cross-repo byte anchor for it is recorded by OpenChatZD's
//! `published_body_is_v2_with_non_identifying_record_id` PocketIC test (same formulas).

use candid::Principal;
use ic_agent::hash_tree::{empty, fork, label, leaf, HashTree};
use zombie_core::hashing::sha256_concat;

use super::body::{self, BodyVersion, RECEIPTS_LABEL};
use super::index_attestation::{self, TrustRootUsed, V3aOutcome, PROTECTED_WINDOW_NS};
use super::package::{
    FrozenPackage, IndexCodeIdentityEvidence, PackageInput, PortablePackage, RevealPackage,
    PORTABLE_VERSION_V2, PORTABLE_VERSION_V3, TRUST_ROOT_MAINNET,
};
use super::{verify_offline_with, CertVerdict, Check, NowSource, Report, Validity};

// --- OpenChatZD encoders, re-derived from the normative formulas (test-only mirrors) ------------

const RECORD_ID_TAG_V1: &[u8] = b"OPENCHATZD_RECORD_ID_USER_V1";
const H_USER_TAG: &[u8] = b"OPENCHATZD_CVDR_H_USER_V1";
const COMMITMENT_TAG: &[u8] = b"OPENCHATZD_CVDR_COMMITMENT_V1";
const RECEIPT_ID_TAG: &[u8] = b"OPENCHATZD_CVDR_RECEIPT_V1";
const CVDR_ENCODER_VERSION: &[u8] = b"OPENCHATZD_CVDR_V1";

fn p(b: u8) -> Principal {
    Principal::from_slice(&[b; 10])
}

fn tagged(tag: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut all: Vec<&[u8]> = Vec::with_capacity(parts.len() + 1);
    all.push(tag);
    all.extend_from_slice(parts);
    sha256_concat(&all)
}

/// The executor module hash the historical unit vector's `h_index` commits to.
pub const UV_EXECUTOR_MODULE_HASH: [u8; 32] = [7u8; 32];
/// `record_salt` of the V2 unit vector (R-1).
pub const UV_RECORD_SALT: [u8; 32] = [0xC3u8; 32];
/// `uninstall_completed_at` (ns) of both unit vectors.
pub const UV_UNINSTALL_NS: u64 = 111;
pub const UV_COMMITTED_NS: u64 = 222;

pub struct UnitVector {
    pub version: BodyVersion,
    pub body: Vec<u8>,
    pub leaf: [u8; 32],
    pub receipt_id: [u8; 32],
    pub index_canister_id: Principal,
    pub user_canister_id: Principal,
    pub record_id: [u8; 32],
    pub targets_commitment: [u8; 32],
    pub salt: [u8; 32],
    pub targets: Vec<Principal>,
    pub receipt_committed_at_ns: u64,
    pub witness_bytes: Vec<u8>,
    pub tree_root: [u8; 32],
}

#[allow(clippy::too_many_arguments)]
fn finish_body(
    version: BodyVersion,
    receipt_id: [u8; 32],
    nonce: [u8; 32],
    index_id: Principal,
    user_id: Principal,
    record_id: [u8; 32],
    seq: u64,
    hu: [u8; 32],
    historical: Option<([u8; 32], [u8; 32])>,
    targets: &[Principal],
    tc: [u8; 32],
) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(version.tag());
    b.extend_from_slice(&receipt_id);
    b.extend_from_slice(&nonce);
    for pr in [index_id, user_id] {
        b.push(pr.as_slice().len() as u8);
        b.extend_from_slice(pr.as_slice());
    }
    b.extend_from_slice(&record_id);
    b.extend_from_slice(&seq.to_be_bytes());
    b.extend_from_slice(&hu);
    if let Some((hi, com)) = historical {
        b.extend_from_slice(&hi);
        b.extend_from_slice(&com);
    }
    b.extend_from_slice(&UV_UNINSTALL_NS.to_be_bytes());
    b.extend_from_slice(&UV_COMMITTED_NS.to_be_bytes());
    b.extend_from_slice(&(targets.len() as u32).to_be_bytes());
    b.extend_from_slice(&tc);
    b
}

fn synth(version: BodyVersion) -> UnitVector {
    let index_id = p(3);
    let user_id = p(2);
    let seq: u64 = 5;
    let nonce = [2u8; 32];
    let salt = [4u8; 32];
    let targets = vec![p(8), p(6)];
    let tc = body::targets_commitment(&salt, &targets, false).unwrap();
    let hu = tagged(H_USER_TAG, &[user_id.as_slice(), &[9u8; 32]]);
    let (record_id, historical) = match version {
        BodyVersion::V1 => {
            let record_id = tagged(RECORD_ID_TAG_V1, &[p(1).as_slice()]);
            let hi = body::h_index_for(index_id, &UV_EXECUTOR_MODULE_HASH);
            let com = tagged(
                COMMITMENT_TAG,
                &[
                    CVDR_ENCODER_VERSION,
                    &record_id,
                    &seq.to_be_bytes(),
                    &hu,
                    &hi,
                    user_id.as_slice(),
                ],
            );
            (record_id, Some((hi, com)))
        }
        // R-1: the UserId principal IS the user canister principal in OpenChatZD.
        BodyVersion::V2 => (super::record_id_v2(&UV_RECORD_SALT, user_id), None),
    };
    let receipt_id = tagged(RECEIPT_ID_TAG, &[&record_id, &seq.to_be_bytes(), &nonce]);
    let b = finish_body(
        version, receipt_id, nonce, index_id, user_id, record_id, seq, hu, historical, &targets, tc,
    );
    let leaf_hash = body::receipt_leaf(&b);
    let tree = label(
        RECEIPTS_LABEL,
        label(receipt_id.to_vec(), leaf(leaf_hash.to_vec())),
    );
    let witness_bytes = serde_cbor::to_vec(&tree).unwrap();
    let decoded: HashTree<Vec<u8>> = serde_cbor::from_slice(&witness_bytes).unwrap();
    UnitVector {
        version,
        body: b,
        leaf: leaf_hash,
        receipt_id,
        index_canister_id: index_id,
        user_canister_id: user_id,
        record_id,
        targets_commitment: tc,
        salt,
        targets,
        receipt_committed_at_ns: UV_COMMITTED_NS,
        witness_bytes,
        tree_root: decoded.digest(),
    }
}

/// Historical RECEIPT_BODY_V1 unit vector (CD-anchored).
pub fn synth_unit_vector() -> UnitVector {
    synth(BodyVersion::V1)
}
/// Suite-v5 RECEIPT_BODY_V2 unit vector.
pub fn synth_unit_vector_v2() -> UnitVector {
    synth(BodyVersion::V2)
}

fn synth_frozen(uv: &UnitVector, certificate_time: u64) -> FrozenPackage {
    FrozenPackage {
        receipt_body: uv.body.clone(),
        receipt_hash: uv.leaf,
        tree_root: uv.tree_root,
        witness_bytes: uv.witness_bytes.clone(),
        certificate_bytes: vec![0u8], // opaque to the injected cert stage
        certificate_time,
        root_key_der: None,
    }
}

fn frozen_input(uv: &UnitVector, certificate_time: u64) -> PackageInput {
    PackageInput::Frozen(synth_frozen(uv, certificate_time))
}

/// A PortablePackageV3 around the vector, carrying the given evidence.
fn v3_input(
    uv: &UnitVector,
    certificate_time: u64,
    evidence: IndexCodeIdentityEvidence,
) -> PackageInput {
    PackageInput::Portable(PortablePackage {
        version: PORTABLE_VERSION_V3,
        trust_root_key_id: Some(TRUST_ROOT_MAINNET.to_string()),
        frozen: synth_frozen(uv, certificate_time),
        frozen_exact_bytes: b"{}".to_vec(),
        index_evidence: Some(evidence),
    })
}

fn cert_ok(
    expect_canister: Principal,
    expect_root: [u8; 32],
    cert_time: u64,
) -> impl Fn(&[u8], Principal, &[u8; 32]) -> CertVerdict {
    move |_cert, canister, root| {
        if canister != expect_canister {
            return Err(format!(
                "V2 canister {} not covered by delegation",
                canister
            ));
        }
        if *root != expect_root {
            return Err("V2 certified_data != witness root".to_string());
        }
        Ok(cert_time)
    }
}

fn nns_trust() -> &'static [u8] {
    zombie_core::nns_keys::lookup_key("mainnet")
        .unwrap()
        .der_bytes
}
fn mainnet_used() -> TrustRootUsed {
    TrustRootUsed {
        selector: TRUST_ROOT_MAINNET.to_string(),
        non_production: false,
        der_len: nns_trust().len(),
    }
}
/// Verifier clock inside the unit vectors' protected window.
const NOW_IN_WINDOW: u64 = UV_UNINSTALL_NS + 10;
/// Verifier clock after the window lapsed.
const NOW_LAPSED: u64 = UV_UNINSTALL_NS + PROTECTED_WINDOW_NS + 1;

fn run(
    input: &PackageInput,
    reveal: Option<&RevealPackage>,
    cert_time: u64,
    now_ns: u64,
) -> Report {
    let uv_index = input.frozen();
    let parsed = body::ReceiptBody::parse(&uv_index.receipt_body).ok();
    let (canister, root) = match &parsed {
        Some(b) => (b.index_canister_id, uv_index.tree_root),
        None => (p(3), uv_index.tree_root),
    };
    verify_offline_with(
        input,
        reveal,
        24,
        None,
        &cert_ok(canister, root, cert_time),
        Some((nns_trust(), mainnet_used())),
        now_ns,
        NowSource::CliNowNs,
    )
}

fn check<'a>(r: &'a Report, rule: &str) -> &'a Check {
    &r.checks
        .iter()
        .find(|(n, _)| *n == rule)
        .unwrap_or_else(|| {
            panic!(
                "no check `{rule}` in {:?}",
                r.checks.iter().map(|(n, _)| *n).collect::<Vec<_>>()
            )
        })
        .1
}

// ============================================================================
// Drift checks: byte-equal recompute of CD's unit-vector values (historical V1) + V2 shape
// ============================================================================

#[test]
fn body_leaf_and_targets_match_cd_anchors() {
    let uv = synth_unit_vector();
    assert_eq!(
        uv.body.len(),
        300,
        "RECEIPT_BODY_V1 must be 300 bytes with 10-byte principals"
    );
    assert_eq!(
        hex::encode(uv.leaf),
        "7aeb124f69688671b350b80442705473c092dfecea8f8791c45375eff8f87c3e",
        "leaf != CD anchor (full byte equality) — RECEIPT_BODY_V1 layout drift"
    );
    assert_eq!(
        hex::encode(uv.targets_commitment),
        "a06af2c83778d1e4bbf685e99d8a0f01229d8a24ea41d8edae9d65e71b83b618",
        "targets_commitment != CD anchor (full byte equality) — TARGETS_COMMITMENT_V1 drift"
    );
}

/// RECEIPT_BODY_V2 = V1 − {h_index, commitment}: 236 bytes with 10-byte principals; the verifier's
/// parser round-trips every displayed field; `record_id` is the salted derivation (R-1), and
/// `receipt_id` recomputes from the displayed fields (R-5).
#[test]
fn v2_body_shape_and_formulas() {
    let uv = synth_unit_vector_v2();
    assert_eq!(uv.body.len(), 236);
    let b = body::ReceiptBody::parse(&uv.body).unwrap();
    assert_eq!((b.version, uv.version), (BodyVersion::V2, BodyVersion::V2));
    assert_eq!(b.record_id, uv.record_id);
    assert_eq!(
        b.record_id,
        super::record_id_v2(&UV_RECORD_SALT, uv.user_canister_id)
    );
    assert_ne!(
        b.record_id,
        tagged(RECORD_ID_TAG_V1, &[uv.user_canister_id.as_slice()]),
        "not the retired UserId-only derivation"
    );
    assert_eq!(
        body::receipt_id_for(&b.record_id, b.deletion_seq, &b.nonce),
        b.receipt_id
    );
    assert_eq!((b.h_index, b.commitment), (None, None));
    assert_eq!(b.uninstall_completed_at_ns, UV_UNINSTALL_NS);
    println!("RECEIPT_BODY_V2 unit-vector leaf: {}", hex::encode(uv.leaf));
}

#[test]
fn docs_example_witness_digest_matches() {
    let lf = |v: &[u8]| -> HashTree<Vec<u8>> { leaf(v.to_vec()) };
    let e = || -> HashTree<Vec<u8>> { empty() };
    let tree: HashTree<Vec<u8>> = fork(
        fork(
            label(
                b"a".to_vec(),
                fork(
                    fork(label(b"x".to_vec(), lf(b"hello")), e()),
                    label(b"y".to_vec(), lf(b"world")),
                ),
            ),
            label(b"b".to_vec(), lf(b"good")),
        ),
        fork(
            label(b"c".to_vec(), e()),
            label(b"d".to_vec(), lf(b"morning")),
        ),
    );
    assert_eq!(
        hex::encode(tree.digest()),
        "eb5c5b2195e62d996b84c9bcc8259d19a83786a2f59e0878cec84c811f669aa0"
    );
    assert_eq!(
        hex::encode(serde_cbor::to_vec(&tree).unwrap()),
        "8301830183024161830183018302417882034568656c6c6f810083024179820345776f726c6483024162820344676f6f648301830241638100830241648203476d6f726e696e67"
    );
}

#[test]
fn witness_decode_locates_leaf_and_recomputes_root() {
    for uv in [synth_unit_vector(), synth_unit_vector_v2()] {
        let out = super::witness::decode_and_locate(&uv.witness_bytes, &uv.receipt_id).unwrap();
        assert_eq!(out.leaf_value, uv.leaf);
        assert_eq!(out.root, uv.tree_root);
    }
}

// ============================================================================
// V1 — dispatch: package version ↔ body tag (G rule 3)
// ============================================================================

#[test]
fn v3_package_with_v1_body_is_malformed_and_vice_versa() {
    let v1 = synth_unit_vector();
    let ev = IndexCodeIdentityEvidence {
        certificate_bytes: vec![1],
        index_module_hash: Some([1u8; 32]),
    };
    let r = run(&v3_input(&v1, 300, ev.clone()), None, 300, NOW_IN_WINDOW);
    assert_eq!(r.validity, Validity::Fail);
    assert_eq!(r.reason.as_deref(), Some("v1:version-tag-mismatch"));
    assert!(
        matches!(check(&r, "V1 package version ↔ body tag"), Check::Fail(m) if m.contains("malformed"))
    );

    let v2 = synth_unit_vector_v2();
    let mut hist = v3_input(&v2, 300, ev);
    if let PackageInput::Portable(p) = &mut hist {
        p.version = PORTABLE_VERSION_V2;
        p.trust_root_key_id = None;
    }
    let r = run(&hist, None, 300, NOW_IN_WINDOW);
    assert_eq!(r.reason.as_deref(), Some("v1:version-tag-mismatch"));

    // FrozenWire takes either body.
    for uv in [synth_unit_vector(), synth_unit_vector_v2()] {
        let r = run(&frozen_input(&uv, 300), None, 300, NOW_IN_WINDOW);
        assert!(matches!(
            check(&r, "V1 package version ↔ body tag"),
            Check::Pass(_)
        ));
    }
}

#[test]
fn unknown_body_tag_is_malformed() {
    let uv = synth_unit_vector_v2();
    let mut pkg = synth_frozen(&uv, 300);
    pkg.receipt_body[..26].copy_from_slice(b"OPENCHATZD_RECEIPT_BODY_V9");
    let r = run(&PackageInput::Frozen(pkg), None, 300, NOW_IN_WINDOW);
    assert_eq!(
        (r.validity, r.reason.as_deref()),
        (Validity::Fail, Some("v1:body-malformed"))
    );
}

// ============================================================================
// V1 / V2 rejects — each rule, on the live V2 body
// ============================================================================

#[test]
fn receipt_id_mismatch_fails_before_witness() {
    let uv = synth_unit_vector_v2();
    let mut pkg = synth_frozen(&uv, 300);
    pkg.receipt_body[26] ^= 0xff; // first byte of embedded receipt_id
    let r = run(&PackageInput::Frozen(pkg), None, 300, NOW_IN_WINDOW);
    assert_eq!(
        (r.validity, r.reason.as_deref()),
        (Validity::Fail, Some("v1:receipt-id"))
    );
    assert!(
        r.checks.iter().all(|(n, _)| !n.starts_with("V2")),
        "V2 must not run after a receipt_id mismatch"
    );
}

#[test]
fn receipt_hash_ne_leaf_fails() {
    let uv = synth_unit_vector_v2();
    let mut pkg = synth_frozen(&uv, 300);
    pkg.receipt_hash = [0u8; 32];
    let r = run(&PackageInput::Frozen(pkg), None, 300, NOW_IN_WINDOW);
    assert_eq!(r.validity, Validity::Fail);
    assert!(matches!(
        check(&r, "V1 leaf == receipt_hash"),
        Check::Fail(_)
    ));
}

#[test]
fn witness_root_ne_tree_root_fails() {
    let uv = synth_unit_vector_v2();
    let mut pkg = synth_frozen(&uv, 300);
    pkg.tree_root = [0u8; 32];
    let r = run(&PackageInput::Frozen(pkg), None, 300, NOW_IN_WINDOW);
    assert_eq!(r.validity, Validity::Fail);
    assert!(matches!(
        check(&r, "V2 witness root == tree_root"),
        Check::Fail(_)
    ));
}

#[test]
fn cert_certified_data_ne_witness_root_and_range_miss_fail() {
    let uv = synth_unit_vector_v2();
    let input = frozen_input(&uv, 300);
    let bad_root = verify_offline_with(
        &input,
        None,
        24,
        None,
        &cert_ok(uv.index_canister_id, [0u8; 32], 300),
        Some((nns_trust(), mainnet_used())),
        NOW_IN_WINDOW,
        NowSource::CliNowNs,
    );
    assert_eq!(bad_root.validity, Validity::Fail);
    let range_miss = verify_offline_with(
        &input,
        None,
        24,
        None,
        &cert_ok(p(99), uv.tree_root, 300),
        Some((nns_trust(), mainnet_used())),
        NOW_IN_WINDOW,
        NowSource::CliNowNs,
    );
    assert_eq!(range_miss.validity, Validity::Fail);
}

#[test]
fn cert_time_mismatch_fails() {
    let uv = synth_unit_vector_v2();
    let r = run(&frozen_input(&uv, 300), None, 301, NOW_IN_WINDOW);
    assert_eq!(r.validity, Validity::Fail);
    assert!(matches!(
        check(&r, "V2 certificate_time == cert /time"),
        Check::Fail(_)
    ));
}

// ============================================================================
// V3A — three outcomes drive the grade; window/timing never gate (G rule 2)
// ============================================================================

#[test]
fn frozen_only_is_incomplete_pending_then_permanently_unavailable() {
    let uv = synth_unit_vector_v2();
    let cert_time = uv.receipt_committed_at_ns + 3_000_000_000;
    let pending = run(
        &frozen_input(&uv, cert_time),
        None,
        cert_time,
        NOW_IN_WINDOW,
    );
    assert_eq!(pending.validity, Validity::Incomplete);
    assert_eq!(pending.reason.as_deref(), Some(super::REASON_V3A_PENDING));
    assert_eq!(
        pending.v3a.as_ref().unwrap().outcome,
        Ok(V3aOutcome::PendingInProtectedWindow)
    );

    let gone = run(&frozen_input(&uv, cert_time), None, cert_time, NOW_LAPSED);
    assert_eq!(
        gone.validity,
        Validity::Incomplete,
        "never PASS, never FAIL"
    );
    assert_eq!(
        gone.reason.as_deref(),
        Some(super::REASON_V3A_PERMANENTLY_UNAVAILABLE)
    );
    assert_eq!(
        gone.v3a.as_ref().unwrap().outcome,
        Ok(V3aOutcome::PermanentlyUnavailable)
    );
    assert_ne!(
        pending.reason, gone.reason,
        "pending and unavailable are never collapsed"
    );
}

#[test]
fn late_finalization_is_reported_but_never_gates() {
    let uv = synth_unit_vector_v2();
    let cert_time = uv.receipt_committed_at_ns + 25 * 3_600_000_000_000;
    let r = run(
        &frozen_input(&uv, cert_time),
        None,
        cert_time,
        NOW_IN_WINDOW,
    );
    assert_eq!(
        r.validity,
        Validity::Incomplete,
        "late tier is non-gating; grade comes from V1/V2/V3A only"
    );
    assert!(r
        .window_note
        .as_deref()
        .unwrap()
        .contains("late finalization (non-gating)"));
}

/// V3 package with garbage evidence: V3A is a NAMED failure (never an outcome) => FAIL.
#[test]
fn v3_with_unauthenticatable_evidence_fails_named() {
    let uv = synth_unit_vector_v2();
    let ev = IndexCodeIdentityEvidence {
        certificate_bytes: vec![0xde, 0xad],
        index_module_hash: Some([1u8; 32]),
    };
    let r = run(&v3_input(&uv, 300, ev), None, 300, NOW_IN_WINDOW);
    assert_eq!(r.validity, Validity::Fail);
    assert_eq!(
        r.reason.as_deref(),
        Some("V3A subnet-attested Index code identity")
    );
    assert_eq!(
        r.v3a.as_ref().unwrap().label(),
        index_attestation::INDEX_ATTESTATION_INVALID
    );
}

/// V3 package with a REAL mainnet module_hash certificate: PASS end to end with the injected V2
/// stage (the real V2 BLS path is exercised on real data in `a1_real_mainnet_certificate_bls_path`).
#[test]
fn v3_with_real_certificate_passes() {
    let canister = Principal::from_text("nq4qv-wqaaa-aaaaf-bhdgq-cai").unwrap();
    let cert: &[u8] = include_bytes!("../../testdata/mainnet_module_hash_certificate.bin");
    let out =
        crate::v2_certificate::verify_certificate_over_module_hash(cert, canister, nns_trust())
            .unwrap();
    // A V2 body whose Index is the mainnet canister and whose uninstall precedes the certificate.
    let uninstall = out.certificate_time_ns - 1_000;
    let seq = 5u64;
    let nonce = [2u8; 32];
    let user = p(2);
    let record_id = super::record_id_v2(&UV_RECORD_SALT, user);
    let receipt_id = tagged(RECEIPT_ID_TAG, &[&record_id, &seq.to_be_bytes(), &nonce]);
    let hu = tagged(H_USER_TAG, &[user.as_slice(), &[9u8; 32]]);
    let targets = vec![p(8), p(6)];
    let tc = body::targets_commitment(&[4u8; 32], &targets, false).unwrap();
    let mut b = finish_body(
        BodyVersion::V2,
        receipt_id,
        nonce,
        canister,
        user,
        record_id,
        seq,
        hu,
        None,
        &targets,
        tc,
    );
    // patch the two timestamps to real values (uninstall, committed)
    let ts_off = b.len() - 32 - 4 - 8 - 8;
    b[ts_off..ts_off + 8].copy_from_slice(&uninstall.to_be_bytes());
    b[ts_off + 8..ts_off + 16].copy_from_slice(&(uninstall + 1).to_be_bytes());
    let leaf_hash = body::receipt_leaf(&b);
    let tree = label(
        RECEIPTS_LABEL,
        label(receipt_id.to_vec(), leaf(leaf_hash.to_vec())),
    );
    let witness_bytes = serde_cbor::to_vec(&tree).unwrap();
    let root = serde_cbor::from_slice::<HashTree<Vec<u8>>>(&witness_bytes)
        .unwrap()
        .digest();
    let frozen = FrozenPackage {
        receipt_body: b,
        receipt_hash: leaf_hash,
        tree_root: root,
        witness_bytes,
        certificate_bytes: vec![0],
        certificate_time: uninstall + 2,
        root_key_der: None,
    };
    let input = PackageInput::Portable(PortablePackage {
        version: PORTABLE_VERSION_V3,
        trust_root_key_id: Some(TRUST_ROOT_MAINNET.to_string()),
        frozen,
        frozen_exact_bytes: b"{}".to_vec(),
        index_evidence: Some(IndexCodeIdentityEvidence {
            certificate_bytes: cert.to_vec(),
            index_module_hash: Some(out.certified_module_hash),
        }),
    });
    let r = verify_offline_with(
        &input,
        None,
        24,
        None,
        &cert_ok(canister, root, uninstall + 2),
        Some((nns_trust(), mainnet_used())),
        out.certificate_time_ns + 5,
        NowSource::CliNowNs,
    );
    r.render();
    assert_eq!((r.validity, r.reason.clone()), (Validity::Pass, None));
    assert_eq!(r.v3a.as_ref().unwrap().outcome, Ok(V3aOutcome::Pass));

    // Same package with a wrong displayed index_module_hash => INDEX_HASH_MISMATCH => FAIL.
    let mut bad = input.clone();
    if let PackageInput::Portable(p) = &mut bad {
        p.index_evidence.as_mut().unwrap().index_module_hash = Some([0u8; 32]);
    }
    let r = verify_offline_with(
        &bad,
        None,
        24,
        None,
        &cert_ok(canister, root, uninstall + 2),
        Some((nns_trust(), mainnet_used())),
        out.certificate_time_ns + 5,
        NowSource::CliNowNs,
    );
    assert_eq!(r.validity, Validity::Fail);
    assert_eq!(
        r.v3a.as_ref().unwrap().label(),
        index_attestation::INDEX_HASH_MISMATCH
    );

    // --expect-module-hash gates against the CERTIFIED hash on a V2 body.
    let r = verify_offline_with(
        &input,
        None,
        24,
        Some([0u8; 32]),
        &cert_ok(canister, root, uninstall + 2),
        Some((nns_trust(), mainnet_used())),
        out.certificate_time_ns + 5,
        NowSource::CliNowNs,
    );
    assert_eq!(r.validity, Validity::Fail);
    assert!(matches!(
        check(&r, "expect: Index module hash"),
        Check::Fail(_)
    ));
    let r = verify_offline_with(
        &input,
        None,
        24,
        Some(out.certified_module_hash),
        &cert_ok(canister, root, uninstall + 2),
        Some((nns_trust(), mainnet_used())),
        out.certificate_time_ns + 5,
        NowSource::CliNowNs,
    );
    assert_eq!(r.validity, Validity::Pass);
}

// ============================================================================
// RevealWire v2 — targets_commitment + record_id_v2 (authorised linkage)
// ============================================================================

#[test]
fn reveal_v2_recomputes_targets_and_record_id() {
    let uv = synth_unit_vector_v2();
    let cert_time = uv.receipt_committed_at_ns + 3_000_000_000;
    let mut sorted = uv.targets.clone();
    sorted.sort_by(|a, b| a.as_slice().cmp(b.as_slice()));
    let reveal = RevealPackage {
        salt: uv.salt,
        record_salt: Some(UV_RECORD_SALT),
        targets: sorted.clone(),
    };
    let r = run(
        &frozen_input(&uv, cert_time),
        Some(&reveal),
        cert_time,
        NOW_IN_WINDOW,
    );
    assert!(matches!(
        check(&r, "V1 reveal: targets_commitment"),
        Check::Pass(_)
    ));
    assert!(matches!(
        check(&r, "V1 reveal: record_id_v2"),
        Check::Pass(_)
    ));
    assert_eq!(
        r.validity,
        Validity::Incomplete,
        "reveal never changes the grade beyond its own checks"
    );

    let wrong_record_salt = RevealPackage {
        salt: uv.salt,
        record_salt: Some([0xFF; 32]),
        targets: sorted.clone(),
    };
    let r = run(
        &frozen_input(&uv, cert_time),
        Some(&wrong_record_salt),
        cert_time,
        NOW_IN_WINDOW,
    );
    assert_eq!(r.validity, Validity::Fail);
    assert!(matches!(
        check(&r, "V1 reveal: record_id_v2"),
        Check::Fail(_)
    ));

    let v1_reveal = RevealPackage {
        salt: uv.salt,
        record_salt: None,
        targets: sorted,
    };
    let r = run(
        &frozen_input(&uv, cert_time),
        Some(&v1_reveal),
        cert_time,
        NOW_IN_WINDOW,
    );
    assert_eq!(
        r.validity,
        Validity::Fail,
        "a V2 body needs a RevealWire v2 to link"
    );

    let wrong_salt = RevealPackage {
        salt: [0xFF; 32],
        record_salt: Some(UV_RECORD_SALT),
        targets: uv.targets.clone(),
    };
    let r = run(
        &frozen_input(&uv, cert_time),
        Some(&wrong_salt),
        cert_time,
        NOW_IN_WINDOW,
    );
    assert_eq!(r.validity, Validity::Fail);
}

// ============================================================================
// Real mainnet certificate (A1) — the committed BLS→NNS→delegation→range path over real data.
// ============================================================================

#[test]
fn a1_real_mainnet_certificate_bls_path() {
    use crate::v2_certificate::verify_certificate_over_certified_data;
    use std::path::Path;
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/a1_mainnet_cvdr.json");
    let raw = std::fs::read_to_string(&path).expect("A1 fixture present");
    let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
    let canister = Principal::from_text(v["canister_id"].as_str().unwrap()).unwrap();
    let certified_data: [u8; 32] = hex::decode(v["certified_data"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let cert_bytes = hex::decode(v["certificate_bytes"].as_str().unwrap()).unwrap();
    let witness_bytes = hex::decode(v["witness_bytes"].as_str().unwrap()).unwrap();
    let wtree: HashTree<Vec<u8>> = serde_cbor::from_slice(&witness_bytes).unwrap();
    assert_eq!(wtree.digest(), certified_data);
    let outcome =
        verify_certificate_over_certified_data(&cert_bytes, canister, &certified_data, nns_trust())
            .expect("real mainnet certificate must verify");
    assert!(outcome.certificate_time_ns > 0);
}

// ============================================================================
// PocketIC end-to-end regression (historical V1 FrozenWire with a genuine PocketIC certificate).
// The fixture root is honoured ONLY via the non-production selector + explicit flag; without it the
// certificate cannot authenticate (FAIL). With it: V1 ∧ V2 pass; V3A has no evidence and the
// protected window (2026) has lapsed at wall-clock time => INCOMPLETE (permanently unavailable).
// ============================================================================

#[test]
fn pocketic_e2e_package_needs_opted_in_fixture_root_and_is_incomplete_without_evidence() {
    use super::{select_trust_root, verify_offline};
    use std::path::Path;
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/pocketic_e2e_cvdr.json");
    let input =
        PackageInput::from_path(path.to_str().unwrap()).expect("portable e2e package loads");
    let der = input
        .frozen()
        .root_key_der
        .clone()
        .expect("e2e fixture carries root_key_hex");
    let now = u64::MAX / 2;

    // Built-in mainnet root: the PocketIC certificate cannot authenticate => FAIL.
    let mainnet = select_trust_root(None, Some("mainnet"), false, Some(&der)).unwrap();
    let r = verify_offline(&input, None, 24, None, &mainnet, now, NowSource::CliNowNs);
    assert_eq!(r.validity, Validity::Fail, "no silent trust anchor");

    // Non-production selector WITHOUT the flag: refused at selection.
    assert!(select_trust_root(
        None,
        Some(super::package::TRUST_ROOT_NON_PRODUCTION),
        false,
        Some(&der)
    )
    .is_err());

    // Non-production selector WITH the flag: V1 ∧ V2 pass under the fixture root; V3A absent + window lapsed.
    let fixture = select_trust_root(
        None,
        Some(super::package::TRUST_ROOT_NON_PRODUCTION),
        true,
        Some(&der),
    )
    .unwrap();
    assert!(fixture.used.non_production);
    let r = verify_offline(&input, None, 24, None, &fixture, now, NowSource::CliNowNs);
    r.render();
    assert_eq!(r.validity, Validity::Incomplete, "{:?}", r.reason);
    assert_eq!(
        r.reason.as_deref(),
        Some(super::REASON_V3A_PERMANENTLY_UNAVAILABLE)
    );
    assert!(matches!(
        check(&r, "V2 cert BLS+delegation+range+certified_data"),
        Check::Pass(_)
    ));
}
