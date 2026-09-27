//! OpenChatZD suite-v5 vector corpus (Brief B1 §2 step 6; open-chatZD plan Step 9) driven through
//! the real CLI. The corpus is generated and hash-gated in open-chatZD
//! (`docs/test-vectors/openchatzd-v5/`, `local_user_index_canister_impl::model::cvdr_vectors`);
//! this crate carries a byte-identical mirror at `tests/fixtures/v5-openchatzd/corpus/` whose
//! `manifest.json` pins each file's SHA-256 (see `PROVENANCE.md` there). Expected values are read
//! from the vector JSON; none is restated here. Offline.
//!
//! Positive vectors pin that the verifier's recompute of `receipt_id`, `record_id_v2` (via a
//! RevealWire v2), `RECEIPT_BODY_V2` parse + leaf and the canonical PortablePackageV3 / FrozenWire
//! encodings agree with the canister's formulas. Negative vectors pin the named V1 rejections
//! (tag / version dispatch, prefix matches, altered receipt_id, identifying record_id, altered
//! body field). The certificate-level negative (displayed `index_module_hash` ≠ certified →
//! `INDEX_HASH_MISMATCH`) runs over the genuine PocketIC fixture in `openchatzd_v3_e2e.rs`.

mod support;

use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use support::corpus::check_sha256;

const DIR: &str = "tests/fixtures/v5-openchatzd/corpus";

fn crate_path(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(rel)
}

/// Read a corpus file, hash-gated against `manifest.json`.
fn vector(name: &str) -> Value {
    let manifest: Value = serde_json::from_slice(
        &std::fs::read(crate_path(&format!("{DIR}/manifest.json"))).unwrap(),
    )
    .unwrap();
    let bytes = std::fs::read(crate_path(&format!("{DIR}/{name}")))
        .unwrap_or_else(|e| panic!("{name}: {e}"));
    let pinned = manifest["files"][name]
        .as_str()
        .unwrap_or_else(|| panic!("{name} is not in manifest.json"));
    check_sha256(&bytes, pinned).unwrap_or_else(|e| panic!("{name}: {e}"));
    serde_json::from_slice(&bytes).unwrap()
}

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_mktd02-verify"))
        .args(args)
        .output()
        .expect("binary runs")
}

fn text(o: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

/// Unique per call: tests run as parallel threads of one process, so a per-process name would race.
fn tmp(name: &str, bytes: &[u8]) -> String {
    static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = N.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let path = std::env::temp_dir().join(format!(
        "oczd_corpus_{}_{n}_{name}.json",
        std::process::id()
    ));
    std::fs::write(&path, bytes).unwrap();
    path.to_str().unwrap().to_string()
}

fn s(v: &Value) -> &str {
    v.as_str().expect("string field")
}

/// pv5-004's canonical PortablePackageV3 with `frozen.receipt_body` (and optionally `receipt_hash`,
/// `version`, `schema`) replaced — the nested FrozenWire is re-encoded with the same canonical order.
fn package_with(body_hex: &str, mutate: impl FnOnce(&mut Value, &mut Value)) -> String {
    let pv4 = vector("pv5-004-canonical_package.json");
    let mut outer: Value =
        serde_json::from_str(s(&pv4["expected"]["portable_package_v3_canonical_json"])).unwrap();
    let mut frozen: Value =
        serde_json::from_str(s(&pv4["expected"]["frozen_wire_canonical_json"])).unwrap();
    frozen["receipt_body"] = Value::String(body_hex.to_string());
    mutate(&mut outer, &mut frozen);
    outer["frozen"] = Value::String(hex::encode(serde_json::to_vec(&frozen).unwrap()));
    tmp("pkg", &serde_json::to_vec(&outer).unwrap())
}

#[test]
fn every_manifest_file_is_present_and_hash_checked() {
    let manifest: Value = serde_json::from_slice(
        &std::fs::read(crate_path(&format!("{DIR}/manifest.json"))).unwrap(),
    )
    .unwrap();
    assert_eq!(manifest["corpus"], "openchatzd-v5");
    let files = manifest["files"].as_object().unwrap();
    assert_eq!(files.len(), 9, "4 positive + 5 negative");
    for name in files.keys() {
        vector(name);
    }
}

/// pv5-001 / pv5-002 / pv5-003 / pv5-004: the canonical FrozenWire (nesting the pv5-003 body and
/// leaf) parses; the verifier's recomputed `receipt_id` and displayed `record_id` equal the
/// vectors'; with the RevealWire v2 the `record_id_v2` and `targets_commitment` linkages PASS.
#[test]
fn positive_vectors_recompute_through_the_cli() {
    let pv1 = vector("pv5-001-receipt_id.json");
    let pv2 = vector("pv5-002-record_id_v2.json");
    let pv3 = vector("pv5-003-receipt_body_v2.json");
    let pv4 = vector("pv5-004-canonical_package.json");
    assert_eq!(pv3["derived"]["receipt_id"], pv1["expected"]["receipt_id"]);
    assert_eq!(pv3["derived"]["record_id"], pv2["expected"]["record_id"]);
    assert_ne!(
        pv2["expected"]["record_id"],
        pv2["must_not_equal"]["retired_v1_derivation"]
    );

    let frozen_json = s(&pv4["expected"]["frozen_wire_canonical_json"]);
    let frozen: Value = serde_json::from_str(frozen_json).unwrap();
    assert_eq!(
        frozen["receipt_body"], pv3["expected"]["receipt_body"],
        "pv5-004 nests the pv5-003 body"
    );
    assert_eq!(
        frozen["receipt_hash"], pv3["expected"]["leaf"],
        "pv5-004 nests the pv5-003 leaf"
    );
    check_sha256(
        frozen_json.as_bytes(),
        s(&pv4["expected"]["frozen_wire_sha256"]),
    )
    .unwrap();
    let portable_json = s(&pv4["expected"]["portable_package_v3_canonical_json"]);
    check_sha256(
        portable_json.as_bytes(),
        s(&pv4["expected"]["portable_package_v3_sha256"]),
    )
    .unwrap();

    let pkg = tmp("pv4", portable_json.as_bytes());
    let reveal = tmp(
        "reveal",
        s(&pv4["expected"]["reveal_wire_v2_canonical_json"]).as_bytes(),
    );
    let out = run(&["--package", &pkg, "--reveal", &reveal]);
    let t = text(&out);
    // The certificate is a placeholder, so V2 fails and validity is FAIL: only the V1 recompute
    // lines are pinned here (the real certificate path is `openchatzd_v3_e2e.rs`).
    assert_eq!(out.status.code(), Some(1), "{t}");
    assert!(t.contains("Package: PortablePackageV3 (live)"), "{t}");
    assert!(
        t.contains(&format!(
            "Gate B nested FrozenWire bytes sha256: {}",
            s(&pv4["expected"]["frozen_wire_sha256"])
        )),
        "{t}"
    );
    assert!(t.contains("Parsed RECEIPT_BODY_V2:"), "{t}");
    assert!(
        t.contains(&format!(
            "receipt_id            : {}",
            s(&pv1["expected"]["receipt_id"])
        )),
        "{t}"
    );
    assert!(
        t.contains(&format!(
            "record_id             : {}",
            s(&pv2["expected"]["record_id"])
        )),
        "{t}"
    );
    assert!(
        t.contains(&format!(
            "targets_commitment    : {}",
            s(&pv3["derived"]["targets_commitment"])
        )),
        "{t}"
    );
    for line in [
        "[PASS] V1 package version ↔ body tag",
        "[PASS] V1 body: tag dispatch + parse",
        "[PASS] V1 receipt_id recompute",
        "[PASS] V1 leaf == receipt_hash",
        "[PASS] V1 reveal: targets_commitment",
        "[PASS] V1 reveal: record_id_v2",
    ] {
        assert!(t.contains(line), "missing `{line}` in:\n{t}");
    }
}

/// nv5-001: exact tag / version dispatch — a V1 body under a V3 package is a version↔tag mismatch;
/// the V1 layout under the V2 tag and a future tag are malformed bodies; version `30` and a
/// prefix-matching schema are malformed packages (never a prefix match).
#[test]
fn nv5_001_old_tag_and_prefix_dispatch() {
    let nv = vector("nv5-001-old_tag_and_prefix_dispatch.json");
    for case in nv["cases"].as_array().unwrap() {
        let name = s(&case["name"]);
        let pkg = package_with(s(&case["receipt_body"]), |outer, _| {
            outer["version"] = case["package_version"].clone();
            if let Some(schema) = case.get("schema") {
                outer["schema"] = schema.clone();
            }
        });
        let out = run(&["--package", &pkg]);
        let t = text(&out);
        assert_ne!(out.status.code(), Some(0), "{name}: {t}");
        match s(&case["expect"]) {
            "v1:version-tag-mismatch" => {
                assert!(
                    t.contains("[FAIL] V1 package version ↔ body tag"),
                    "{name}: {t}"
                );
                assert!(
                    t.contains("validity: FAIL (v1:version-tag-mismatch)"),
                    "{name}: {t}"
                );
            }
            "v1:body-malformed" => {
                assert!(
                    t.contains("[FAIL] V1 body: tag dispatch + parse"),
                    "{name}: {t}"
                );
                assert!(
                    t.contains("validity: FAIL (v1:body-malformed)"),
                    "{name}: {t}"
                );
            }
            "malformed" => {
                assert!(
                    t.contains("must be exactly 3") || t.contains("unrecognised package schema"),
                    "{name}: {t}"
                );
                assert!(
                    !t.contains("Parsed RECEIPT_BODY"),
                    "{name}: malformed package must not be parsed: {t}"
                );
            }
            other => panic!("unknown expectation {other}"),
        }
    }
}

/// nv5-002: a flipped `receipt_id` or `nonce` byte fails the receipt_id recompute, named.
#[test]
fn nv5_002_altered_receipt_id() {
    let nv = vector("nv5-002-altered_receipt_id.json");
    for case in nv["cases"].as_array().unwrap() {
        let name = s(&case["name"]);
        assert_eq!(s(&case["expect"]), "v1:receipt-id");
        let pkg = package_with(s(&case["receipt_body"]), |_, _| {});
        let out = run(&["--package", &pkg]);
        let t = text(&out);
        assert_eq!(out.status.code(), Some(1), "{name}: {t}");
        assert!(t.contains("[FAIL] V1 receipt_id recompute"), "{name}: {t}");
        assert!(t.contains("validity: FAIL (v1:receipt-id)"), "{name}: {t}");
    }
}

/// nv5-003: a V2 body whose `record_id` is the retired UserId-only derivation still recomputes its
/// `receipt_id`; the RevealWire v2 linkage check is what exposes it.
#[test]
fn nv5_003_identifying_record_id_is_exposed_by_the_reveal_linkage() {
    let nv = vector("nv5-003-identifying_record_id.json");
    let pv3 = vector("pv5-003-receipt_body_v2.json");
    let leaf = {
        // the vector body is self-consistent apart from record_id: recompute its leaf so that only
        // the reveal check can fail
        let body = hex::decode(s(&nv["receipt_body"])).unwrap();
        hex::encode(zombie_core::hashing::sha256(
            &[b"OPENCHATZD_RECEIPT_LEAF_V1".as_slice(), &body].concat(),
        ))
    };
    assert_ne!(leaf, s(&pv3["expected"]["leaf"]));
    let pkg = package_with(s(&nv["receipt_body"]), |_, frozen| {
        frozen["receipt_hash"] = Value::String(leaf.clone());
    });
    let reveal = tmp("reveal3", s(&nv["reveal_wire_v2"]).as_bytes());
    let out = run(&["--package", &pkg, "--reveal", &reveal]);
    let t = text(&out);
    assert_eq!(out.status.code(), Some(1), "{t}");
    assert!(t.contains("[PASS] V1 receipt_id recompute"), "{t}");
    assert!(t.contains("[PASS] V1 leaf == receipt_hash"), "{t}");
    assert!(t.contains("[PASS] V1 reveal: targets_commitment"), "{t}");
    assert!(t.contains("[FAIL] V1 reveal: record_id_v2"), "{t}");
}

/// nv5-004: h_index / commitment inside the preimage (the V1 layout) under a V3 package is a
/// version↔tag mismatch. The mismatched-evidence case is certificate-level and is pinned over the
/// genuine PocketIC fixture (`openchatzd_v3_e2e::tampered_displayed_module_hash_fails_named_...`).
#[test]
fn nv5_004_module_hash_in_preimage_is_a_version_tag_mismatch() {
    let nv = vector("nv5-004-module_hash_in_preimage_or_mismatched_evidence.json");
    let cases = nv["cases"].as_array().unwrap();
    let preimage = &cases[0];
    assert_eq!(s(&preimage["expect"]), "v1:version-tag-mismatch");
    let pkg = package_with(s(&preimage["receipt_body"]), |_, _| {});
    let out = run(&["--package", &pkg]);
    let t = text(&out);
    assert_eq!(out.status.code(), Some(1), "{t}");
    assert!(t.contains("Parsed RECEIPT_BODY_V1:"), "{t}");
    assert!(t.contains("h_index (historical)"), "{t}");
    assert!(
        t.contains("validity: FAIL (v1:version-tag-mismatch)"),
        "{t}"
    );
    assert_eq!(
        s(&cases[1]["expect"]),
        "INDEX_HASH_MISMATCH",
        "pinned by openchatzd_v3_e2e over the PocketIC fixture"
    );
}

/// nv5-005: a flipped body field outside the receipt_id preimage (`h_user_pre`) leaves the
/// receipt_id recompute passing and fails the leaf check, named.
#[test]
fn nv5_005_altered_body_field_fails_the_leaf_check() {
    let nv = vector("nv5-005-altered_body_field.json");
    let case = &nv["cases"][0];
    let pkg = package_with(s(&case["receipt_body"]), |_, _| {});
    let out = run(&["--package", &pkg]);
    let t = text(&out);
    assert_eq!(out.status.code(), Some(1), "{t}");
    assert!(t.contains("[PASS] V1 receipt_id recompute"), "{t}");
    assert!(t.contains("[FAIL] V1 leaf == receipt_hash"), "{t}");
    assert!(
        t.contains("validity: FAIL (V1 leaf == receipt_hash)"),
        "{t}"
    );
}
