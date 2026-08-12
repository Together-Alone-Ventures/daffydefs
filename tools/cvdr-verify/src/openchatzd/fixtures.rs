//! Cross-repo alignment fixtures (spec §2/§4/§5/§9).
//!
//! This module INDEPENDENTLY re-derives OpenChatZD's leaf-test unit vector from
//! the frozen spec and requires byte-equal recompute of CD's independently
//! derived values. Agreement across three implementations (OpenChatZD, CD,
//! CVDR-Verify) is the alignment guarantee; a disagreement is a real layout
//! drift and the assertion FAILS loudly — the exact failure this task exists to
//! catch (no fudging).
//!
//! CD anchors — asserted at FULL byte equality (they are 32-byte hashes):
//! - leaf               `7aeb124f69688671b350b80442705473c092dfecea8f8791c45375eff8f87c3e`
//!   (300-byte body, principals 10/10) — asserted in `body_leaf_and_targets_match_cd_anchors`
//! - targets_commitment `a06af2c83778d1e4bbf685e99d8a0f01229d8a24ea41d8edae9d65e71b83b618`
//!   — asserted in `body_leaf_and_targets_match_cd_anchors`
//! - witness digest     `eb5c5b2195e62d996b84c9bcc8259d19a83786a2f59e0878cec84c811f669aa0`
//!   — RESOLVED. This is the ic-certification
//!   DOCS-EXAMPLE tree (the IC interface-spec certification example), NOT the OpenChatZD
//!   receipt tree — a known-good vector for the witness DECODE/digest machinery, which CD
//!   reproduced byte-identical under ic-certification 3.1.0 and 3.2.0. It is anchored below
//!   as a shared fixture at full byte equality (`docs_example_witness_digest_matches`). The
//!   earlier "does not reproduce" was a category error (attempting to recompute it from
//!   OpenChatZD's receipt tree) — withdrawn.

use candid::Principal;
use ic_agent::hash_tree::{empty, fork, label, leaf, HashTree};
use zombie_core::hashing::sha256_concat;

use super::body::{self, RECEIPTS_LABEL};
use super::package::FrozenPackage;
use super::{verify_offline_with, CertVerdict, Report, Verdict};

// --- OpenChatZD encoders, re-derived from CVDR_BUILD_SPEC_V1.md §2 ------------
// (Test-only: constructs a realistic body/witness so the verifier's spec-pinned
// recomputes have something to bite on. NOT used by production verification —
// the verifier parses opaque body fields, it does not rebuild them.)

const RECORD_ID_TAG: &[u8] = b"OPENCHATZD_RECORD_ID_USER_V1";
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

/// The executor module hash the unit vector's `h_index` commits to. Because
/// `synth_unit_vector` builds `h_index` with the PRODUCTION `body::h_index_for`,
/// the CD leaf anchor `7aeb124f…` transitively pins `H_INDEX_TAG`'s preimage.
pub const UV_EXECUTOR_MODULE_HASH: [u8; 32] = [7u8; 32];

/// The frozen unit vector from OpenChatZD's `receipt_leaf_matches_formula_and_
/// binds_timestamps` test, independently constructed.
pub struct UnitVector {
    pub body: Vec<u8>,
    pub leaf: [u8; 32],
    pub receipt_id: [u8; 32],
    pub index_canister_id: Principal,
    pub targets_commitment: [u8; 32],
    pub salt: [u8; 32],
    pub targets: Vec<Principal>,
    pub receipt_committed_at_ns: u64,
    /// Single-leaf witness (rid → leaf) built with ic-agent HashTree constructors.
    pub witness_bytes: Vec<u8>,
    pub tree_root: [u8; 32],
}

pub fn synth_unit_vector() -> UnitVector {
    let index_id = p(3);
    let user_id = p(2);
    let record_id = tagged(RECORD_ID_TAG, &[p(1).as_slice()]);
    let hu = tagged(H_USER_TAG, &[user_id.as_slice(), &[9u8; 32]]);
    // Production encoder — so the CD leaf anchor also anchors `body::h_index_for`.
    let hi = body::h_index_for(index_id, &UV_EXECUTOR_MODULE_HASH);
    let seq: u64 = 5;
    let com = tagged(
        COMMITMENT_TAG,
        &[CVDR_ENCODER_VERSION, &record_id, &seq.to_be_bytes(), &hu, &hi, user_id.as_slice()],
    );
    let salt = [4u8; 32];
    let targets = vec![p(8), p(6)];
    let tc = body::targets_commitment(&salt, &targets, false).unwrap();
    let nonce = [2u8; 32];
    let receipt_id = tagged(RECEIPT_ID_TAG, &[&record_id, &seq.to_be_bytes(), &nonce]);

    // Build RECEIPT_BODY_V1 exactly per §2 (the mirror of OpenChatZD's builder).
    let mut b = Vec::new();
    b.extend_from_slice(body::RECEIPT_BODY_TAG);
    b.extend_from_slice(&receipt_id);
    b.extend_from_slice(&nonce);
    for pr in [index_id, user_id] {
        b.push(pr.as_slice().len() as u8);
        b.extend_from_slice(pr.as_slice());
    }
    b.extend_from_slice(&record_id);
    b.extend_from_slice(&seq.to_be_bytes());
    b.extend_from_slice(&hu);
    b.extend_from_slice(&hi);
    b.extend_from_slice(&com);
    b.extend_from_slice(&111u64.to_be_bytes()); // uninstall_completed_at
    b.extend_from_slice(&222u64.to_be_bytes()); // receipt_committed_at
    b.extend_from_slice(&(targets.len() as u32).to_be_bytes());
    b.extend_from_slice(&tc);

    let leaf_hash = body::receipt_leaf(&b);

    // Single-leaf witness over (receipt_id → leaf). ic-agent's HashTree digest
    // follows the IC hashing spec, byte-identical to ic-certification's RbTree
    // for a one-entry map nested under "receipts".
    let tree = label(RECEIPTS_LABEL, label(receipt_id.to_vec(), leaf(leaf_hash.to_vec())));
    let witness_bytes = serde_cbor::to_vec(&tree).unwrap();
    let decoded: HashTree<Vec<u8>> = serde_cbor::from_slice(&witness_bytes).unwrap();
    let tree_root = decoded.digest();

    UnitVector {
        body: b,
        leaf: leaf_hash,
        receipt_id,
        index_canister_id: index_id,
        targets_commitment: tc,
        salt,
        targets,
        receipt_committed_at_ns: 222,
        witness_bytes,
        tree_root,
    }
}

/// Assemble a synthetic [`FrozenPackage`] from the unit vector, so the pipeline
/// tests can drive `verify_offline_with` against an injectable cert stage.
fn synth_package(uv: &UnitVector, certificate_time: u64) -> FrozenPackage {
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

// A cert stage that behaves like a verified real certificate: it enforces the
// §9.3 `certified_data == witness_root` and §9.4 canister binding the same way
// the real BLS path does, then returns a caller-chosen `/time`. The REAL BLS
// path is exercised separately in `a1_real_mainnet_certificate_bls_path`.
fn cert_ok(expect_canister: Principal, expect_root: [u8; 32], cert_time: u64) -> impl Fn(&[u8], Principal, &[u8; 32]) -> CertVerdict {
    move |_cert, canister, root| {
        if canister != expect_canister {
            return Err(format!("§9.4 canister {} not covered", canister));
        }
        if *root != expect_root {
            return Err("§9.3 certified_data != witness root".to_string());
        }
        Ok(cert_time)
    }
}

fn verdict_of(report: &Report) -> Verdict {
    report.verdict
}

// ============================================================================
// Drift check: byte-equal recompute of CD's unit-vector values
// ============================================================================

#[test]
fn body_leaf_and_targets_match_cd_anchors() {
    let uv = synth_unit_vector();
    let leaf_hex = hex::encode(uv.leaf);
    let tc_hex = hex::encode(uv.targets_commitment);
    let root_hex = hex::encode(uv.tree_root);

    println!("RECEIPT_BODY_V1 length      : {} (CD: 300, principals 10/10)", uv.body.len());
    println!("leaf                        : {}  (asserted vs CD anchor below)", leaf_hex);
    println!("targets_commitment          : {}  (asserted vs CD anchor below)", tc_hex);
    println!("witness root (single-leaf)  : {}  (synth receipt-tree root; the eb5c5b21 docs-example anchor is a DIFFERENT tree, see docs_example_witness_digest_matches)", root_hex);

    // Load-bearing FROZEN layouts — FULL byte equality with CD's independently-derived values.
    assert_eq!(uv.body.len(), 300, "RECEIPT_BODY_V1 must be 300 bytes with 10-byte principals");
    assert_eq!(
        leaf_hex, "7aeb124f69688671b350b80442705473c092dfecea8f8791c45375eff8f87c3e",
        "leaf != CD anchor (full byte equality) — RECEIPT_BODY_V1 layout drift"
    );
    assert_eq!(
        tc_hex, "a06af2c83778d1e4bbf685e99d8a0f01229d8a24ea41d8edae9d65e71b83b618",
        "targets_commitment != CD anchor (full byte equality) — TARGETS_COMMITMENT_V1 drift"
    );
}

/// Shared known-good witness vector (CD anchor
/// `eb5c5b2195e62d996b84c9bcc8259d19a83786a2f59e0878cec84c811f669aa0`): the ic-certification
/// docs-example tree (IC interface-spec certification example). Proves our HashTree DECODE +
/// digest machinery is byte-identical to the reference. Full byte equality.
#[test]
fn docs_example_witness_digest_matches() {
    // fork(fork(labeled("a", fork(fork(labeled("x", leaf "hello"), empty), labeled("y", leaf "world"))),
    //           labeled("b", leaf "good")),
    //      fork(labeled("c", empty), labeled("d", leaf "morning")))
    // Concrete-typed leaf/empty helpers pin HashTree<Vec<u8>> (empty() is otherwise ambiguous).
    let lf = |v: &[u8]| -> HashTree<Vec<u8>> { leaf(v.to_vec()) };
    let e = || -> HashTree<Vec<u8>> { empty() };
    let tree: HashTree<Vec<u8>> = fork(
        fork(
            label(
                b"a".to_vec(),
                fork(fork(label(b"x".to_vec(), lf(b"hello")), e()), label(b"y".to_vec(), lf(b"world"))),
            ),
            label(b"b".to_vec(), lf(b"good")),
        ),
        fork(label(b"c".to_vec(), e()), label(b"d".to_vec(), lf(b"morning"))),
    );
    assert_eq!(
        hex::encode(tree.digest()),
        "eb5c5b2195e62d996b84c9bcc8259d19a83786a2f59e0878cec84c811f669aa0",
        "docs-example witness digest must match the reference (ic-certification 3.1.0/3.2.0)"
    );

    // And its CBOR encodes byte-for-byte as the CD-supplied 71-byte serialization.
    let cbor = hex::encode(serde_cbor::to_vec(&tree).unwrap());
    assert_eq!(
        cbor,
        "8301830183024161830183018302417882034568656c6c6f810083024179820345776f726c6483024162820344676f6f648301830241638100830241648203476d6f726e696e67",
        "docs-example CBOR must equal the full 71-byte CD-supplied serialization (full byte equality)"
    );
}

/// The witness DECODE/root/leaf-path logic is correct against a self-built witness (round-trips
/// through ic-agent's HashTree). The `eb5c5b2195e62d996b84c9bcc8259d19a83786a2f59e0878cec84c811f669aa0`
/// anchor is the ic-certification docs-example tree
/// (a DIFFERENT tree) and is asserted separately in `docs_example_witness_digest_matches`; this
/// test's single-leaf receipt tree has its own root, asserted byte-equal to the synth value.
#[test]
fn witness_decode_locates_leaf_and_recomputes_root() {
    let uv = synth_unit_vector();
    let out = super::witness::decode_and_locate(&uv.witness_bytes, &uv.receipt_id).unwrap();
    assert_eq!(out.leaf_value, uv.leaf, "witness leaf must equal receipt_hash (§9.1)");
    assert_eq!(out.root, uv.tree_root, "recomputed witness root must equal tree_root (§9.2)");
}

// ============================================================================
// §9 reject list — each rule exercised
// ============================================================================

#[test]
fn rule1_receipt_hash_ne_witness_leaf_rejects() {
    let uv = synth_unit_vector();
    let mut pkg = synth_package(&uv, 300);
    pkg.receipt_hash = [0x00; 32]; // no longer equals leaf(body) nor witness leaf
    let r = verify_offline_with(&pkg, None, 24, None, &cert_ok(uv.index_canister_id, uv.tree_root, 300));
    assert_eq!(verdict_of(&r), Verdict::Reject);
}

#[test]
fn rule2_witness_root_ne_tree_root_rejects() {
    let uv = synth_unit_vector();
    let mut pkg = synth_package(&uv, 300);
    pkg.tree_root = [0x00; 32]; // witness recomputes a different root
    let r = verify_offline_with(&pkg, None, 24, None, &cert_ok(uv.index_canister_id, uv.tree_root, 300));
    assert_eq!(verdict_of(&r), Verdict::Reject);
}

#[test]
fn rule3_cert_certified_data_ne_witness_root_rejects() {
    let uv = synth_unit_vector();
    let pkg = synth_package(&uv, 300);
    // cert stage insists certified_data == a DIFFERENT root → §9.3 fail.
    let r = verify_offline_with(&pkg, None, 24, None, &cert_ok(uv.index_canister_id, [0x00; 32], 300));
    assert_eq!(verdict_of(&r), Verdict::Reject);
}

#[test]
fn rule4_canister_not_in_range_rejects() {
    let uv = synth_unit_vector();
    let pkg = synth_package(&uv, 300);
    // cert stage rejects the index canister (delegation range miss) → §9.4.
    let r = verify_offline_with(&pkg, None, 24, None, &cert_ok(p(99), uv.tree_root, 300));
    assert_eq!(verdict_of(&r), Verdict::Reject);
}

#[test]
fn cert_time_mismatch_rejects() {
    let uv = synth_unit_vector();
    let pkg = synth_package(&uv, 300); // package says 300
    // cert stage reports a different /time (301) → packaging-integrity reject.
    let r = verify_offline_with(&pkg, None, 24, None, &cert_ok(uv.index_canister_id, uv.tree_root, 301));
    assert_eq!(verdict_of(&r), Verdict::Reject);
}

// ============================================================================
// §5 window tiers — VerifiedFinal vs LateFinalized (never merged)
// ============================================================================

#[test]
fn in_window_is_verified_final() {
    let uv = synth_unit_vector();
    // committed_at = 222; certificate_time within 24h window.
    let cert_time = uv.receipt_committed_at_ns + 3_000_000_000; // +3s
    let pkg = synth_package(&uv, cert_time);
    let r = verify_offline_with(&pkg, None, 24, None, &cert_ok(uv.index_canister_id, uv.tree_root, cert_time));
    assert_eq!(verdict_of(&r), Verdict::VerifiedFinal);
}

#[test]
fn out_of_window_is_late_finalized_not_promoted() {
    let uv = synth_unit_vector();
    // 25h after commit → past the 24h window, but cryptographically valid.
    let cert_time = uv.receipt_committed_at_ns + 25 * 3_600_000_000_000;
    let pkg = synth_package(&uv, cert_time);
    let r = verify_offline_with(&pkg, None, 24, None, &cert_ok(uv.index_canister_id, uv.tree_root, cert_time));
    assert_eq!(verdict_of(&r), Verdict::LateFinalized,
        "a late-but-valid package is LateFinalized, NEVER promoted to VerifiedFinal");
}

// ============================================================================
// Reveal package — TARGETS_COMMITMENT_V1 recompute
// ============================================================================

#[test]
fn reveal_package_recomputes_targets_commitment() {
    use super::package::RevealPackage;
    let uv = synth_unit_vector();
    let cert_time = uv.receipt_committed_at_ns + 3_000_000_000;
    let pkg = synth_package(&uv, cert_time);
    let reveal = RevealPackage { salt: uv.salt, targets: {
        // supply ascending (sorted) — reveal packages are pre-sorted
        let mut t = uv.targets.clone();
        t.sort_by(|a, b| a.as_slice().cmp(b.as_slice()));
        t
    }};
    let r = verify_offline_with(&pkg, Some(&reveal), 24, None, &cert_ok(uv.index_canister_id, uv.tree_root, cert_time));
    assert_eq!(verdict_of(&r), Verdict::VerifiedFinal, "correct reveal must keep the happy-path verdict");

    // wrong salt → reveal check fails → reject
    let bad = RevealPackage { salt: [0xFF; 32], targets: uv.targets.clone() };
    let r2 = verify_offline_with(&pkg, Some(&bad), 24, None, &cert_ok(uv.index_canister_id, uv.tree_root, cert_time));
    assert_eq!(verdict_of(&r2), Verdict::Reject);
}

// ============================================================================
// Full-package happy path: all §9 checks + window green → VerifiedFinal
// (certificate stage stands in for the real BLS path, which is validated on
//  real mainnet data in `a1_real_mainnet_certificate_bls_path`).
// ============================================================================

#[test]
fn full_package_pass_verified_final() {
    let uv = synth_unit_vector();
    let cert_time = uv.receipt_committed_at_ns + 5_000_000_000;
    let pkg = synth_package(&uv, cert_time);
    let report = verify_offline_with(&pkg, None, 24, None, &cert_ok(uv.index_canister_id, uv.tree_root, cert_time));
    report.render();
    assert_eq!(verdict_of(&report), Verdict::VerifiedFinal);
}

// ============================================================================
// Real mainnet certificate (A1 spike capture) — the committed BLS→NNS→
// delegation→canister-range path over real data. Completes A1's stubbed "G2".
// ============================================================================

#[test]
fn a1_real_mainnet_certificate_bls_path() {
    use crate::v2_certificate::verify_certificate_over_certified_data;
    use std::path::Path;

    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/a1_mainnet_cvdr.json");
    let raw = std::fs::read_to_string(&path).expect("A1 fixture present");
    let v: serde_json::Value = serde_json::from_str(&raw).unwrap();

    let canister = Principal::from_text(v["canister_id"].as_str().unwrap()).unwrap();
    let certified_data: [u8; 32] =
        hex::decode(v["certified_data"].as_str().unwrap()).unwrap().try_into().unwrap();
    let cert_bytes = hex::decode(v["certificate_bytes"].as_str().unwrap()).unwrap();
    let witness_bytes = hex::decode(v["witness_bytes"].as_str().unwrap()).unwrap();

    // Real witness recompute: HashTree digest == certified_data (§9.2/§9.3 on
    // real data). NOTE: A1 keys b"cvdr" (flat), not ["receipts",id].
    let wtree: HashTree<Vec<u8>> = serde_cbor::from_slice(&witness_bytes).unwrap();
    assert_eq!(wtree.digest(), certified_data, "real witness must reconstruct certified_data");

    // Real BLS→NNS→delegation→canister-range path over certified_data, mainnet key.
    let der = zombie_core::nns_keys::lookup_key("mainnet").unwrap().der_bytes;
    let outcome = verify_certificate_over_certified_data(&cert_bytes, canister, &certified_data, der)
        .expect("real mainnet certificate must verify (BLS + delegation + range + certified_data)");
    println!(
        "A1 real cert: BLS verified, certified_data matches, canister {} in range, /time = {} ns",
        canister, outcome.certificate_time_ns
    );
    assert!(outcome.certificate_time_ns > 0);
}

// ============================================================================
// PocketIC end-to-end regression (CD's failing invocation). A REAL VerifiedFinal
// artifact: the open-chatZD PocketIC test exports a portable six-field frozen
// package (genuine PocketIC certificate binding a real receipts-tree root) + the
// PocketIC NNS root key. Verifying it to VerifiedFinal requires opting the fixture
// root key in — and MUST reject without it (no silent trust anchor).
// ============================================================================

#[test]
fn pocketic_e2e_package_verifies_final_only_with_opted_in_fixture_root_key() {
    use super::package::FrozenPackage;
    use super::NnsCertVerifier;
    use std::path::Path;

    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/pocketic_e2e_cvdr.json");
    let pkg = FrozenPackage::from_path(path.to_str().unwrap()).expect("portable e2e package loads");
    let der = pkg.root_key_der.clone().expect("e2e fixture carries root_key_hex");

    // WITHOUT the opt-in (built-in mainnet roots): the PocketIC certificate cannot verify → Reject.
    let default_verifier = NnsCertVerifier { trust_root_key_id: None, explicit_der: None };
    let default_report = super::verify_offline_with(&pkg, None, 24, None, &default_verifier);
    assert_eq!(
        default_report.verdict,
        Verdict::Reject,
        "no silent trust anchor: the PocketIC cert must NOT verify under built-in NNS roots"
    );

    // WITH the opted-in fixture root key: full real BLS→NNS→delegation→range + §9 + window → final.
    let opted_in = NnsCertVerifier { trust_root_key_id: None, explicit_der: Some(der) };
    let report = super::verify_offline_with(&pkg, None, 24, None, &opted_in);
    assert_eq!(
        report.verdict,
        Verdict::VerifiedFinal,
        "PocketIC e2e package must be VerifiedFinal with the opted-in fixture root key"
    );
}

// ============================================================================
// --expect-module-hash: the h_index gate (v0.5.1)
//
// Before v0.5.1 the only module-hash surface was a display-only
// `--corroborate-h-index`. The gate below is what makes a module-hash claim
// load-bearing: it is OFFLINE (no read_state) and it REJECTS on mismatch.
// ============================================================================

/// The text of the `h_index` check line, whatever its outcome.
fn h_index_check<'a>(report: &'a Report) -> &'a super::Check {
    &report
        .checks
        .iter()
        .find(|(rule, _)| *rule == "h_index: binds expected module")
        .expect("the h_index check is always emitted")
        .1
}

#[test]
fn expect_module_hash_mismatch_rejects_with_distinct_reason() {
    let uv = synth_unit_vector();
    let cert_time = uv.receipt_committed_at_ns + 3_000_000_000;
    let pkg = synth_package(&uv, cert_time);

    // A module hash the receipt does NOT commit to — everything else is the happy path.
    let wrong = [0xAB; 32];
    assert_ne!(wrong, UV_EXECUTOR_MODULE_HASH);
    let r = verify_offline_with(
        &pkg,
        None,
        24,
        Some(wrong),
        &cert_ok(uv.index_canister_id, uv.tree_root, cert_time),
    );

    assert_eq!(
        verdict_of(&r),
        Verdict::Reject,
        "a receipt that does not commit to the expected module must be REJECTED"
    );
    assert_ne!(r.verdict.exit_code(), 0, "a mismatch must exit NON-ZERO");

    // Distinct reason, not a generic failure: the reject names H_INDEX_MISMATCH and
    // both hashes, so the operator can tell it apart from a §9.1–§9.4 or window failure.
    let check = h_index_check(&r);
    assert!(check.is_fail(), "the h_index check must FAIL, not merely inform");
    let text = check.text();
    assert!(text.contains("H_INDEX_MISMATCH"), "reason must be distinct: {text}");
    assert!(text.contains(&hex::encode(wrong)), "reason must name the expected hash: {text}");
    assert!(
        text.contains(&hex::encode(uv.index_canister_id.as_slice())) || text.contains(&uv.index_canister_id.to_text()),
        "reason must name the principal folded into h_index: {text}"
    );
}

#[test]
fn expect_module_hash_match_passes() {
    let uv = synth_unit_vector();
    let cert_time = uv.receipt_committed_at_ns + 3_000_000_000;
    let pkg = synth_package(&uv, cert_time);

    let r = verify_offline_with(
        &pkg,
        None,
        24,
        Some(UV_EXECUTOR_MODULE_HASH),
        &cert_ok(uv.index_canister_id, uv.tree_root, cert_time),
    );

    assert_eq!(
        verdict_of(&r),
        Verdict::VerifiedFinal,
        "the correct module hash must keep the happy-path verdict"
    );
    assert_eq!(r.verdict.exit_code(), 0);
    assert!(matches!(h_index_check(&r), super::Check::Pass(_)), "the gate must PASS on a match");
}

#[test]
fn expect_module_hash_absent_leaves_verdict_unchanged() {
    let uv = synth_unit_vector();
    let cert_time = uv.receipt_committed_at_ns + 3_000_000_000;
    let pkg = synth_package(&uv, cert_time);

    let gated = verify_offline_with(
        &pkg,
        None,
        24,
        Some(UV_EXECUTOR_MODULE_HASH),
        &cert_ok(uv.index_canister_id, uv.tree_root, cert_time),
    );
    let ungated = verify_offline_with(
        &pkg,
        None,
        24,
        None,
        &cert_ok(uv.index_canister_id, uv.tree_root, cert_time),
    );
    assert_eq!(
        verdict_of(&ungated),
        verdict_of(&gated),
        "absent expectation must not change the verdict a correct expectation yields"
    );

    // Same for a package that is LateFinalized: the gate must not perturb the tier.
    let late_time = uv.receipt_committed_at_ns + 25 * 3_600_000_000_000;
    let late_pkg = synth_package(&uv, late_time);
    let late = verify_offline_with(
        &late_pkg,
        None,
        24,
        None,
        &cert_ok(uv.index_canister_id, uv.tree_root, late_time),
    );
    assert_eq!(verdict_of(&late), Verdict::LateFinalized);

    // And absence is reported as informational — NEVER as "hash verified".
    let check = h_index_check(&ungated);
    assert!(matches!(check, super::Check::Info(_)), "absence must be Info, never Pass");
    assert!(!check.is_fail(), "absence must not fail the verdict");
    let text = check.text();
    assert!(text.contains("NOT verified"), "absence must say nothing was verified: {text}");
}

/// A mismatched module hash rejects even when the certificate is late: the gate is
/// independent of the §5 window tier, and Reject outranks LateFinalized.
#[test]
fn expect_module_hash_mismatch_rejects_a_late_package_too() {
    let uv = synth_unit_vector();
    let late_time = uv.receipt_committed_at_ns + 25 * 3_600_000_000_000;
    let pkg = synth_package(&uv, late_time);
    let r = verify_offline_with(
        &pkg,
        None,
        24,
        Some([0xAB; 32]),
        &cert_ok(uv.index_canister_id, uv.tree_root, late_time),
    );
    assert_eq!(verdict_of(&r), Verdict::Reject, "Reject outranks LateFinalized");
    assert_ne!(r.verdict.exit_code(), 0);
}
