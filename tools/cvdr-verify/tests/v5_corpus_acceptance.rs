//! Corpus acceptance: the countersigned mktd02-v5 corpus, read at the pinned
//! zombie-core rev and hash-gated, driven through the verifier.
//!
//! Loading and the hash gate are `tests/support/corpus.rs` (exercised on its own
//! by `tests/v5_corpus_hash_gate.rs`): the zombie-core rev this crate's graph
//! pins (which must be the spec's 2237238) is read from cargo's git database,
//! the manifest must be `countersigned`, and every file listed in
//! `countersignature.vector_file_sha256` must match its SHA-256.
//!
//! Scope is the verifier-reachable subset (Amendment 1 §A, F-4). Cases that are
//! not an intake or verification path of this verifier are recorded as N/A with
//! a reason in [`DISPOSITIONS`], never silently skipped. Expected values are
//! always taken from the vector JSON; none is restated here.

mod support;

use candid::Principal;
use mktd02_verify::intake::{decode_receipt_bytes, decode_receipt_json, IntakeError};
use mktd02_verify::report::{CheckOutcome, Validity, REASON_INCOMPLETE_FINALISATION};
use mktd02_verify::trust_root::TrustRoot;
use mktd02_verify::v1_transition::{
    historical_certified_commitment, historical_receipt_id, historical_tombstone_hash,
};
use mktd02_verify::verify::{verify_receipt, VerifyOptions};
use mktd02_verify::{v1_transition, v2_certificate};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;
use support::corpus::{load_signed_corpus, SignedCorpus};
use zombie_core::{
    check_certified_data_not_genesis, deletion_event_hash_v5, verify_v1_event_hash,
    AnyDeletionReceipt, DeletionReceiptV4, DeletionReceiptV5,
};

// ---------------------------------------------------------------------------
// Hash-gated corpus (shared loader)
// ---------------------------------------------------------------------------

struct Parsed {
    signed: SignedCorpus,
    json: BTreeMap<String, Value>,
}

fn corpus() -> &'static Parsed {
    static CORPUS: OnceLock<Parsed> = OnceLock::new();
    CORPUS.get_or_init(|| {
        let signed = load_signed_corpus();
        let json = signed
            .files
            .keys()
            .map(|rel| (rel.clone(), signed.json(rel)))
            .collect();
        Parsed { signed, json }
    })
}

fn v5(id: &str) -> &'static Value {
    let rel = format!("docs/test-vectors/v5/{id}.json");
    let v = corpus()
        .json
        .get(&rel)
        .unwrap_or_else(|| panic!("{rel} is not countersigned"));
    assert_eq!(v["id"], id);
    v
}

fn historical(name: &str) -> &'static Value {
    let rel = format!("docs/test-vectors/v4-historical/{name}.json");
    corpus()
        .json
        .get(&rel)
        .unwrap_or_else(|| panic!("{rel} is not countersigned"))
}

// ---------------------------------------------------------------------------
// Dispositions: every manifest id is exercised or N/A with a reason.
// ---------------------------------------------------------------------------

const NA_NOT_INTAKE: &str = "N/A — not an intake path; covered by zombie-core's own corpus tests";

/// (id, disposition). `test:` entries name the test below that drives the
/// vector through the verifier; `N/A` entries say why the verifier has no path.
const DISPOSITIONS: &[(&str, &str)] = &[
    ("gv5-001", "N/A — domain-separated digest primitive over a test tag; the verifier has no code path for arbitrary tags; covered by zombie-core's own corpus tests"),
    ("gv5-002", "test: digest_vectors_through_verifier_code_paths (tombstone_hash via the verifier's tombstone construction)"),
    ("gv5-003", "N/A — single-step event-hash vector with a free receipt_id operand; unreachable through V1, which checks receipt_id first; the construction is exercised by gv5-007/008 V1 PASS and nv5-010; covered by zombie-core's own corpus tests"),
    ("gv5-004", "test: digest_vectors_through_verifier_code_paths (receipt_id through V1 and the historical receipt_id)"),
    ("gv5-005", "test: digest_vectors_through_verifier_code_paths (genesis values refused by the V2 genesis check)"),
    ("gv5-006", "test: digest_vectors_through_verifier_code_paths (genesis refused, event hash not)"),
    ("gv5-007", "test: receipt_fixtures_parse_and_pass_v1 (intake JSON+CBOR, V1 PASS, FinalizedCandidate; V2/V3A not applied to synthetic certificate bytes)"),
    ("gv5-008", "test: receipt_fixtures_parse_and_pass_v1 (intake JSON+CBOR, V1 PASS, Pending -> INCOMPLETE)"),
    ("gv5-009", "test: receipt_state_cases_through_intake"),
    ("gv5-010", "N/A — tag-registry digests; the verifier has no code path for tag groups; covered by zombie-core's own corpus tests"),
    ("gv5-011", "N/A — engine salt/state-hash derivation; not a verifier path; covered by zombie-core and ICP-Delete-Leaf"),
    ("gv5-012", "test: tolerant_decode_equivalence_through_intake (parse-equivalence only; V1 not applied)"),
    ("nv5-001", "test: decode_layer_negatives_through_intake"),
    ("nv5-002", "test: decode_layer_negatives_through_intake (JSON and CBOR)"),
    ("nv5-003", "test: decode_layer_negatives_through_intake"),
    ("nv5-004", "test: decode_layer_negatives_through_intake"),
    ("nv5-005", NA_NOT_INTAKE),
    ("nv5-006", "test: verify_layer_negatives (check_certified_data_not_genesis at the function boundary with the vector's certified_data; no certificate fixture carries genesis)"),
    ("nv5-007", "test: decode_layer_negatives_through_intake (decode half, JSON and CBOR); serialise half N/A — not an intake path; covered by zombie-core's own corpus tests"),
    ("nv5-008", "N/A (both cases) — case 2 (v5 label into the v4 type) is not an intake path; case 1 (v4 label into the v5 type) is also not reachable: AnyDeletionReceipt routes a mktd02-v4 label to DeletionReceiptV4, so the 'not a mktd02-v5 receipt' refusal never arises from intake (the test asserts intake still refuses that input); covered by zombie-core's own corpus tests"),
    ("nv5-009", "test: verify_layer_negatives (through the verifier's V1 / verify_v1)"),
    ("nv5-010", "test: verify_layer_negatives (verify_v1_event_hash at the function boundary, because the vector's receipt_id is not derivable; and the presented hash through the verifier's V1 on a receipt with a derivable receipt_id)"),
    ("nv5-011a", "test: historical_decode_tolerance_through_intake"),
    ("nv5-011b", "test: historical_decode_tolerance_through_intake"),
    ("nv5-011c", "test: historical_decode_tolerance_through_intake"),
    ("v4h-certified-commitment", "test: historical_vectors_through_verifier_v1"),
    ("v4h-event-v1", "test: historical_vectors_through_verifier_v1"),
    ("v4h-v3-wire", "test: historical_vectors_through_verifier_v1 (JSON and CBOR intake agree)"),
    ("v4h-certified-tag", "N/A — retired-tag digest over an arbitrary part; the verifier uses the tag only inside certified_commitment (exercised by v4h-certified-commitment); covered by zombie-core's own corpus tests"),
];

#[test]
fn every_countersigned_vector_has_a_disposition() {
    let c = &corpus().signed;
    let manifest_ids: BTreeSet<String> = c.manifest_ids().into_iter().collect();
    let disposed: BTreeSet<String> = DISPOSITIONS.iter().map(|(id, _)| id.to_string()).collect();
    assert_eq!(
        manifest_ids, disposed,
        "every manifest vector is exercised or N/A, and nothing else"
    );
    // Every countersigned file was hash-checked by the loader.
    assert_eq!(c.files.len(), manifest_ids.len(), "files hash-checked");
    eprintln!("zombie-core corpus @ {} ({})", c.rev, c.git_db.display());
    eprintln!(
        "corpus commit (countersigned): {}",
        c.manifest["countersignature"]["corpus_commit_sha"]
    );
    for (id, disposition) in DISPOSITIONS {
        eprintln!("  {id:<26} {disposition}");
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn hex_bytes(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().expect("hex string")).expect("valid hex")
}

fn hex32(v: &Value) -> [u8; 32] {
    hex_bytes(v).try_into().expect("32 bytes")
}

fn principal_hex(v: &Value) -> Principal {
    Principal::from_slice(&hex_bytes(v))
}

fn rejected(result: Result<AnyDeletionReceipt, IntakeError>) -> String {
    match result {
        Err(IntakeError::Rejected(e)) => e,
        other => panic!("expected intake rejection, got {other:?}"),
    }
}

/// The gv5-012 canonical v5 receipt (the base the corpus's own negatives mutate).
fn canonical_json() -> Value {
    v5("gv5-012")["inputs"]["canonical"].clone()
}

fn canonical_receipt() -> DeletionReceiptV5 {
    match decode_receipt_json(canonical_json()).expect("canonical decodes") {
        AnyDeletionReceipt::V5(r) => r,
        other => panic!("expected v5, got {other:?}"),
    }
}

/// A receipt-fixture vector (gv5-007/008) as receipt wire JSON: its input
/// fields, with canister_id as text and receipt_id / deletion_event_hash taken
/// from the vector's expected block.
fn fixture_wire_json(vector: &Value) -> Value {
    let mut wire = vector["inputs"]["receipt"].clone();
    let obj = wire.as_object_mut().unwrap();
    let text = obj.remove("canister_id_text").expect("canister_id_text");
    obj.remove("canister_id_hex");
    obj.insert("canister_id".into(), text);
    obj.insert(
        "receipt_id".into(),
        vector["expected"]["receipt_id"].clone(),
    );
    obj.insert(
        "deletion_event_hash".into(),
        vector["expected"]["deletion_event_hash"].clone(),
    );
    wire
}

fn cbor_value(bytes: &[u8]) -> ciborium::Value {
    ciborium::from_reader(bytes).expect("CBOR")
}

fn cbor_bytes(value: &ciborium::Value) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::into_writer(value, &mut out).unwrap();
    out
}

fn mainnet_options() -> VerifyOptions {
    VerifyOptions {
        trust_root: TrustRoot::built_in("mainnet").unwrap(),
        published_module_hash: None,
    }
}

// ---------------------------------------------------------------------------
// Positive vectors
// ---------------------------------------------------------------------------

#[test]
fn receipt_fixtures_parse_and_pass_v1() {
    for id in ["gv5-007", "gv5-008"] {
        let vector = v5(id);
        let from_json = decode_receipt_json(fixture_wire_json(vector))
            .unwrap_or_else(|e| panic!("{id}: JSON intake: {e}"));
        let from_cbor = decode_receipt_bytes(&hex_bytes(&vector["expected"]["cbor_hex"]))
            .unwrap_or_else(|e| panic!("{id}: CBOR intake: {e}"));
        assert_eq!(from_json, from_cbor, "{id}: JSON and CBOR intake agree");
        assert!(
            matches!(from_cbor, AnyDeletionReceipt::V5(_)),
            "{id}: v5 line"
        );
        assert!(v1_transition::verify(&from_cbor).is_pass(), "{id}: V1 PASS");

        let facts = verify_receipt(&from_cbor, format!("corpus:{id}"), &mainnet_options());
        assert!(facts.checks.v1.is_pass());
        match id {
            "gv5-007" => {
                assert_eq!(format!("{:?}", from_cbor.state()), "FinalizedCandidate");
                // V2/V3A are not applied: the vector's certificate bytes are
                // synthetic placeholders (inputs.receipt.bls_certificate "aabbcc",
                // module_hash_certificate "ddee", trust_root_key_id "test-key"),
                // not IC certificates. The verifier refuses them by name and
                // never reports PASS.
                assert_eq!(
                    facts.checks.v2.error(),
                    Some(v2_certificate::ERR_V2_CERTIFICATE_PARSE)
                );
                assert_ne!(facts.validity.validity, Validity::Pass);
            }
            _ => {
                assert_eq!(format!("{:?}", from_cbor.state()), "Pending");
                assert_eq!(facts.validity.validity, Validity::Incomplete);
                assert!(matches!(facts.checks.v2, CheckOutcome::NotEvaluated { .. }));
                assert!(matches!(
                    facts.checks.v3a,
                    CheckOutcome::NotEvaluated { .. }
                ));
            }
        }
    }
}

#[test]
fn receipt_state_cases_through_intake() {
    let vector = v5("gv5-009");
    let base = fixture_wire_json(v5("gv5-007"));
    for (input, expected) in vector["inputs"]["certificate_cases"]
        .as_array()
        .unwrap()
        .iter()
        .zip(vector["expected"]["cases"].as_array().unwrap())
    {
        assert_eq!(input["name"], expected["name"]);
        let mut wire = base.clone();
        wire["bls_certificate"] = input["bls_certificate"].clone();
        wire["module_hash_certificate"] = input["module_hash_certificate"].clone();
        let receipt = decode_receipt_json(wire).expect("state case decodes");
        assert_eq!(
            format!("{:?}", receipt.state()),
            expected["state"],
            "{}",
            input["name"]
        );

        let facts = verify_receipt(&receipt, "corpus:gv5-009".into(), &mainnet_options());
        match expected["state"].as_str().unwrap() {
            "Pending" => assert_eq!(facts.validity.validity, Validity::Incomplete),
            "InvalidIncompleteFinalization" => {
                assert_eq!(facts.validity.validity, Validity::Fail);
                assert_eq!(
                    facts.validity.reason.as_deref(),
                    Some(REASON_INCOMPLETE_FINALISATION)
                );
            }
            _ => assert_ne!(
                facts.validity.validity,
                Validity::Pass,
                "synthetic certificates"
            ),
        }
    }
}

#[test]
fn tolerant_decode_equivalence_through_intake() {
    let vector = v5("gv5-012");
    let canonical = decode_receipt_json(canonical_json()).expect("canonical decodes");
    for (case, expected) in vector["inputs"]["tolerated"]
        .as_array()
        .unwrap()
        .iter()
        .zip(vector["expected"]["cases"].as_array().unwrap())
    {
        assert_eq!(case["name"], expected["name"]);
        let mut candidate = canonical_json();
        for (key, value) in case["overrides"].as_object().unwrap() {
            candidate[key] = value.clone();
        }
        let decoded = decode_receipt_json(candidate).expect("tolerated input decodes");
        assert_eq!(
            decoded == canonical,
            expected["equals_canonical"].as_bool().unwrap(),
            "{}",
            case["name"]
        );
    }
}

#[test]
fn digest_vectors_through_verifier_code_paths() {
    // gv5-002: tombstone_hash via the verifier's tombstone construction.
    let v = v5("gv5-002");
    assert_eq!(
        historical_tombstone_hash(
            &principal_hex(&v["inputs"]["canister_id_hex"]),
            v["inputs"]["timestamp"].as_u64().unwrap(),
            v["inputs"]["deletion_seq"].as_u64().unwrap(),
        ),
        hex32(&v["expected"]["tombstone_hash"])
    );

    // gv5-004: receipt_id through the verifier's V1 (v5) and historical receipt_id.
    let v = v5("gv5-004");
    let canister = principal_hex(&v["inputs"]["canister_id_hex"]);
    let seq = v["inputs"]["deletion_seq"].as_u64().unwrap();
    for (record_hex, case) in v["inputs"]["record_id_cases_hex"]
        .as_array()
        .unwrap()
        .iter()
        .zip(v["expected"]["cases"].as_array().unwrap())
    {
        assert_eq!(record_hex, &case["record_id_hex"]);
        let expected_id = hex32(&case["receipt_id"]);
        let mut r = canonical_receipt();
        r.canister_id = canister;
        r.record_id = hex_bytes(record_hex);
        r.deletion_seq = seq;
        r.receipt_id = expected_id;
        r.deletion_event_hash = deletion_event_hash_v5(
            &r.pre_state_hash,
            &r.post_state_hash,
            &r.receipt_id,
            r.timestamp,
            &r.module_hash,
            r.deletion_seq,
        );
        assert!(v1_transition::verify(&AnyDeletionReceipt::V5(r.clone())).is_pass());
        r.receipt_id[0] ^= 0xff;
        assert_eq!(
            v1_transition::verify(&AnyDeletionReceipt::V5(r)).error(),
            Some(zombie_core::ERR_V1_RECEIPT_ID_MISMATCH)
        );

        let v3_line = DeletionReceiptV4 {
            protocol_version: "mktd02-v3".into(),
            receipt_id: [0; 32],
            canister_id: canister,
            record_id: hex_bytes(record_hex),
            pre_state_hash: [0; 32],
            post_state_hash: [0; 32],
            tombstone_hash: [0; 32],
            deletion_event_hash: [0; 32],
            certified_commitment: [0; 32],
            module_hash: [0; 32],
            timestamp: 0,
            deletion_seq: seq,
            bls_certificate: None,
            trust_root_key_id: String::new(),
            module_hash_certificate: None,
        };
        assert_eq!(historical_receipt_id(&v3_line), expected_id);
    }

    // gv5-005: every genesis value is refused by the check V2 runs.
    let v = v5("gv5-005");
    for (canister_hex, case) in v["inputs"]["canister_id_cases_hex"]
        .as_array()
        .unwrap()
        .iter()
        .zip(v["expected"]["cases"].as_array().unwrap())
    {
        assert_eq!(canister_hex, &case["canister_id_hex"]);
        assert_eq!(
            check_certified_data_not_genesis(
                &principal_hex(canister_hex),
                &hex_bytes(&case["genesis_certified_data"])
            ),
            Err(zombie_core::ERR_NO_DELETION_CERTIFIED)
        );
    }

    // gv5-006: genesis refused; the deletion event hash is not.
    let v = v5("gv5-006");
    let canister = principal_hex(&v["inputs"]["canister_id_hex"]);
    let genesis = hex_bytes(&v["expected"]["genesis_certified_data"]);
    let event = hex_bytes(&v["expected"]["deletion_event_hash"]);
    assert!(check_certified_data_not_genesis(&canister, &genesis).is_err());
    assert_eq!(check_certified_data_not_genesis(&canister, &event), Ok(()));
    assert_eq!(
        genesis != event,
        v["expected"]["different"].as_bool().unwrap()
    );
}

// ---------------------------------------------------------------------------
// Negative vectors
// ---------------------------------------------------------------------------

#[test]
fn decode_layer_negatives_through_intake() {
    // nv5-001: retired key, exact named error, every value.
    let v = v5("nv5-001");
    assert_eq!(v["expected"]["layer"], v["inputs"]["operation"]);
    for (case, expected) in v["inputs"]["cases"]
        .as_array()
        .unwrap()
        .iter()
        .zip(v["expected"]["cases"].as_array().unwrap())
    {
        let mut value = canonical_json();
        value[v["inputs"]["field"].as_str().unwrap()] = case["value"].clone();
        assert_eq!(
            rejected(decode_receipt_json(value)),
            expected["error"],
            "{}",
            case["name"]
        );
    }

    // nv5-002: unknown keys, JSON (prefix) and CBOR (contains).
    let v = v5("nv5-002");
    assert_eq!(v["expected"]["layer"], v["inputs"]["operation"]);
    let prefix = v["expected"]["error_prefix"].as_str().unwrap();
    let formats: Vec<&str> = v["inputs"]["formats"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f.as_str().unwrap())
        .collect();
    let base_cbor = hex_bytes(&v5("gv5-007")["expected"]["cbor_hex"]);
    for key in v["inputs"]["unknown_keys"].as_array().unwrap() {
        let key = key.as_str().unwrap();
        if formats.contains(&"json") {
            let mut value = canonical_json();
            value[key] = json!(1);
            let e = rejected(decode_receipt_json(value));
            assert!(e.starts_with(prefix), "{key}: {e}");
        }
        if formats.contains(&"cbor") {
            let mut value = cbor_value(&base_cbor);
            value.as_map_mut().unwrap().push((
                ciborium::Value::Text(key.into()),
                ciborium::Value::Integer(1.into()),
            ));
            let e = rejected(decode_receipt_bytes(&cbor_bytes(&value)));
            assert!(e.contains(prefix), "{key}: {e}");
        }
    }

    // nv5-003: the retired key alongside an unknown key: structural error first.
    let v = v5("nv5-003");
    assert_eq!(v["expected"]["layer"], v["inputs"]["operation"]);
    let mut value = canonical_json();
    for (key, item) in v["inputs"]["fields"].as_object().unwrap() {
        value[key] = item.clone();
    }
    let e = rejected(decode_receipt_json(value));
    assert!(
        e.starts_with(v["expected"]["error_prefix"].as_str().unwrap()),
        "{e}"
    );

    // nv5-004: zero event hash, exact named error.
    let v = v5("nv5-004");
    assert_eq!(v["expected"]["layer"], v["inputs"]["operation"]);
    let mut value = canonical_json();
    for (key, item) in v["inputs"]["mutation"].as_object().unwrap() {
        value[key] = item.clone();
    }
    assert_eq!(rejected(decode_receipt_json(value)), v["expected"]["error"]);

    // nv5-007 (decode half): near-miss v5 labels, JSON and CBOR.
    let v = v5("nv5-007");
    assert_eq!(v["expected"]["layer"], "decode_and_serialise");
    for case in v["expected"]["cases"].as_array().unwrap() {
        assert!(v["inputs"]["labels"]
            .as_array()
            .unwrap()
            .contains(&case["label"]));
        let label = case["label"].as_str().unwrap();
        let fragment = case["error"].as_str().unwrap();
        let mut value = canonical_json();
        value["protocol_version"] = json!(label);
        let e = rejected(decode_receipt_json(value));
        assert!(e.contains(fragment), "{label:?} JSON: {e}");

        let mut cbor = cbor_value(&base_cbor);
        for (k, val) in cbor.as_map_mut().unwrap().iter_mut() {
            if k.as_text() == Some("protocol_version") {
                *val = ciborium::Value::Text(label.into());
            }
        }
        let e = rejected(decode_receipt_bytes(&cbor_bytes(&cbor)));
        assert!(e.contains(fragment), "{label:?} CBOR: {e}");
    }

    // nv5-008 case 1 is N/A (see DISPOSITIONS): intake routes a mktd02-v4 label
    // to the v4 type. The v5-shaped input with that label is still refused.
    let v = v5("nv5-008");
    let case1 = &v["inputs"]["cases"][0];
    assert_eq!(case1["name"], "v4_label_to_v5_type");
    let mut value = canonical_json();
    value["protocol_version"] = case1["label"].clone();
    let e = rejected(decode_receipt_json(value));
    assert!(
        !e.contains(v["expected"]["cases"][0]["error"].as_str().unwrap()),
        "intake unexpectedly produced the v5-type refusal: {e}"
    );
}

#[test]
fn verify_layer_negatives() {
    // nv5-009: presented receipt_id through the verifier's V1.
    let v = v5("nv5-009");
    assert_eq!(v["expected"]["layer"], "verify");
    let input = &v["inputs"]["valid_receipt_id_inputs"];
    let mut r = canonical_receipt();
    r.canister_id = principal_hex(&input["canister_id_hex"]);
    r.record_id = hex_bytes(&input["record_id_hex"]);
    r.deletion_seq = input["deletion_seq"].as_u64().unwrap();
    r.receipt_id = hex32(&v["inputs"]["presented_receipt_id"]);
    assert_eq!(r.receipt_id, hex32(&v["expected"]["presented_receipt_id"]));
    assert_eq!(
        v1_transition::verify(&AnyDeletionReceipt::V5(r.clone())).error(),
        v["expected"]["error"].as_str()
    );
    // The recomputed id is accepted by the receipt_id step (V1 moves on to the
    // event hash, which this receipt does not carry).
    r.receipt_id = hex32(&v["expected"]["recomputed_receipt_id"]);
    assert_eq!(
        v1_transition::verify(&AnyDeletionReceipt::V5(r)).error(),
        Some(zombie_core::ERR_V1_EVENT_HASH_MISMATCH)
    );

    // nv5-010: event-hash step at the function boundary (receipt_id not derivable).
    let v = v5("nv5-010");
    assert_eq!(v["expected"]["layer"], "verify");
    let input = &v["inputs"]["valid_event_inputs"];
    let mut r = canonical_receipt();
    r.pre_state_hash = hex32(&input["pre_state_hash"]);
    r.post_state_hash = hex32(&input["post_state_hash"]);
    r.receipt_id = hex32(&input["receipt_id"]);
    r.timestamp = input["timestamp"].as_u64().unwrap();
    r.module_hash = hex32(&input["module_hash"]);
    r.deletion_seq = input["deletion_seq"].as_u64().unwrap();
    r.deletion_event_hash = hex32(&v["inputs"]["presented_deletion_event_hash"]);
    assert_eq!(
        verify_v1_event_hash(&r),
        Err(v["expected"]["error"].as_str().unwrap())
    );
    r.deletion_event_hash = hex32(&v["expected"]["recomputed_deletion_event_hash"]);
    assert_eq!(verify_v1_event_hash(&r), Ok(()));
    // The presented hash through the verifier's V1, on a receipt whose
    // receipt_id is derivable (the canonical base's inputs).
    let mut r = canonical_receipt();
    r.receipt_id = zombie_core::compute_receipt_id(&r.canister_id, &r.record_id, r.deletion_seq);
    r.deletion_event_hash = hex32(&v["inputs"]["presented_deletion_event_hash"]);
    assert_eq!(
        v1_transition::verify(&AnyDeletionReceipt::V5(r)).error(),
        v["expected"]["error"].as_str()
    );

    // nv5-006: the V2 genesis check at the function boundary.
    let v = v5("nv5-006");
    assert_eq!(v["expected"]["layer"], v["inputs"]["operation"]);
    assert_eq!(
        check_certified_data_not_genesis(
            &principal_hex(&v["inputs"]["canister_id_hex"]),
            &hex_bytes(&v["expected"]["certified_data"])
        ),
        Err(v["expected"]["error"].as_str().unwrap())
    );
}

#[test]
fn historical_decode_tolerance_through_intake() {
    let wire = historical("v3-wire");
    let base: Value =
        serde_json::from_str(wire["expected"]["json_text"].as_str().unwrap()).unwrap();
    for id in ["nv5-011a", "nv5-011b", "nv5-011c"] {
        let v = v5(id);
        assert_eq!(v["expected"]["layer"], v["inputs"]["operation"]);
        assert_eq!(
            v["expected"]["protocol_version"],
            v["inputs"]["protocol_version"]
        );
        let mut value = base.clone();
        value["protocol_version"] = v["inputs"]["protocol_version"].clone();
        if v["inputs"]["protocol_version"] == "mktd02-v2" {
            // A v2 receipt carries its counter as `nonce` and a subnet_id (the
            // verifier's historical intake requires a valid one).
            let obj = value.as_object_mut().unwrap();
            let seq = obj.remove("deletion_seq").unwrap();
            obj.insert("nonce".into(), seq);
            obj.insert("subnet_id".into(), json!("2vxsx-fae"));
        }
        value[v["inputs"]["unknown_key"].as_str().unwrap()] = json!(1);
        let result = match decode_receipt_json(value) {
            Ok(AnyDeletionReceipt::V4(_)) => "accepted",
            Ok(AnyDeletionReceipt::V5(_)) => "misrouted",
            Err(_) => "rejected",
        };
        assert_eq!(result, v["expected"]["result"], "{id}");
    }
}

#[test]
fn historical_vectors_through_verifier_v1() {
    let event = historical("event-v1");
    let commitment = historical("certified-commitment");
    // Same inputs in both vectors; the verifier's historical V1 recomputes both.
    assert_eq!(event["inputs"], commitment["inputs"]);
    let input = &event["inputs"];
    let canister = Principal::from_text("aaaaa-aa").unwrap();
    let (timestamp, seq) = (
        input["timestamp"].as_u64().unwrap(),
        input["deletion_seq"].as_u64().unwrap(),
    );
    let post = hex32(&input["post_state_hash"]);
    let event_hash = hex32(&event["expected"]["deletion_event_hash"]);
    assert_eq!(
        event_hash,
        hex32(&commitment["expected"]["deletion_event_hash"])
    );
    assert_eq!(
        historical_certified_commitment(&post, &event_hash),
        hex32(&commitment["expected"]["certified_commitment"])
    );
    let mut receipt = DeletionReceiptV4 {
        protocol_version: "mktd02-v2".into(),
        receipt_id: zombie_core::receipt::compute_receipt_id_v2(&canister, seq),
        canister_id: canister,
        record_id: Vec::new(),
        pre_state_hash: hex32(&input["pre_state_hash"]),
        post_state_hash: post,
        tombstone_hash: historical_tombstone_hash(&canister, timestamp, seq),
        deletion_event_hash: event_hash,
        certified_commitment: hex32(&commitment["expected"]["certified_commitment"]),
        module_hash: hex32(&input["module_hash"]),
        timestamp,
        deletion_seq: seq,
        bls_certificate: None,
        trust_root_key_id: String::new(),
        module_hash_certificate: None,
    };
    assert!(v1_transition::verify(&AnyDeletionReceipt::V4(receipt.clone())).is_pass());
    receipt.certified_commitment[31] ^= 1;
    assert_eq!(
        v1_transition::verify(&AnyDeletionReceipt::V4(receipt)).error(),
        Some(v1_transition::ERR_V1_HIST_CERTIFIED_COMMITMENT)
    );

    // v3 wire: JSON and CBOR intake of the frozen golden agree.
    let wire = historical("v3-wire");
    let from_json =
        decode_receipt_bytes(wire["expected"]["json_text"].as_str().unwrap().as_bytes())
            .expect("v3 JSON golden decodes");
    let from_cbor = decode_receipt_bytes(&hex_bytes(&wire["expected"]["cbor_hex"]))
        .expect("v3 CBOR golden decodes");
    assert_eq!(from_json, from_cbor);
    assert!(
        matches!(from_json, AnyDeletionReceipt::V4(ref r) if r.protocol_version == "mktd02-v3")
    );
}
