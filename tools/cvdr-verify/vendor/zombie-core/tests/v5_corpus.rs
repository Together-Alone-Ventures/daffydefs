//! Implementation cross-check for the published MKTd02-v5 JSON corpus.
//!
//! This is the code leg of the comparison, not a spec-derived or independent
//! derivation. Expected values are always loaded from the corpus files.

use candid::Principal;
use serde_json::{json, Value};
use std::fs;
use std::path::PathBuf;
use zombie_core::hashing::{
    hash_with_tag, TAG_CERTIFIED, TAG_EVENT, TAG_MANIFEST, TAG_RECEIPT, TAG_RECEIPT_V3, TAG_SALT,
    TAG_TOMBSTONE_HASH,
};
use zombie_core::{
    check_certified_data_not_genesis, compute_receipt_id, deletion_event_hash_v1,
    deletion_event_hash_v5, genesis_certified_data, sha256_concat, verify_v1, verify_v1_event_hash,
    AnyDeletionReceipt, DeletionReceiptV4, DeletionReceiptV5, TAG_EVENT_V2, TAG_GENESIS,
};

fn corpus(name: &str) -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("docs/test-vectors/v5")
        .join(format!("{name}.json"));
    serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap()
}

fn historical(name: &str) -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("docs/test-vectors/v4-historical")
        .join(format!("{name}.json"));
    serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap()
}

fn bytes(value: &Value) -> Vec<u8> {
    hex::decode(value.as_str().unwrap()).unwrap()
}

fn array32(value: &Value) -> [u8; 32] {
    bytes(value).try_into().unwrap()
}

fn principal(hex_value: &Value) -> Principal {
    Principal::from_slice(&bytes(hex_value))
}

fn expected_hex(vector: &Value, key: &str) -> Vec<u8> {
    bytes(&vector["expected"][key])
}

fn v5_receipt(vector: &Value) -> DeletionReceiptV5 {
    let source = &vector["inputs"]["receipt"];
    let expected = &vector["expected"];
    DeletionReceiptV5 {
        protocol_version: source["protocol_version"].as_str().unwrap().into(),
        receipt_id: array32(&expected["receipt_id"]),
        canister_id: principal(&source["canister_id_hex"]),
        record_id: bytes(&source["record_id"]),
        pre_state_hash: array32(&source["pre_state_hash"]),
        post_state_hash: array32(&source["post_state_hash"]),
        tombstone_hash: array32(&source["tombstone_hash"]),
        deletion_event_hash: array32(&expected["deletion_event_hash"]),
        module_hash: array32(&source["module_hash"]),
        timestamp: source["timestamp"].as_u64().unwrap(),
        deletion_seq: source["deletion_seq"].as_u64().unwrap(),
        bls_certificate: source["bls_certificate"]
            .as_str()
            .map(|_| bytes(&source["bls_certificate"])),
        trust_root_key_id: source["trust_root_key_id"].as_str().unwrap().into(),
        module_hash_certificate: source["module_hash_certificate"]
            .as_str()
            .map(|_| bytes(&source["module_hash_certificate"])),
    }
}

fn base_json() -> Value {
    corpus("gv5-012")["inputs"]["canonical"].clone()
}

#[test]
fn manifest_inventory_loads_every_json_vector() {
    let manifest_path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("docs/test-vectors/manifest.json");
    let manifest: Value =
        serde_json::from_str(&fs::read_to_string(manifest_path).unwrap()).unwrap();
    for category in ["positive", "negative_and_compatibility"] {
        for id in manifest["vectors"][category].as_array().unwrap() {
            let id = id.as_str().unwrap();
            let vector = corpus(id);
            assert_eq!(vector["id"], id);
            assert!(!vector["expected"].is_null(), "{id}");
        }
    }
    for entry in manifest["historical"].as_array().unwrap() {
        let id = entry["id"].as_str().unwrap();
        let filename = id.strip_prefix("v4h-").unwrap();
        let vector = historical(filename);
        assert_eq!(vector["id"], id);
        assert!(!vector["expected"].is_null(), "{id}");
        assert!(vector["status"].as_str().unwrap().starts_with("historical"));
    }
}

fn cbor_with_unknown(key: &str) -> Vec<u8> {
    let source = expected_hex(&corpus("gv5-007"), "cbor_hex");
    let mut value: ciborium::Value = ciborium::from_reader(source.as_slice()).unwrap();
    value.as_map_mut().unwrap().push((
        ciborium::Value::Text(key.into()),
        ciborium::Value::Integer(1.into()),
    ));
    let mut encoded = Vec::new();
    ciborium::into_writer(&value, &mut encoded).unwrap();
    encoded
}

fn v5_cbor(receipt: &DeletionReceiptV5) -> Vec<u8> {
    let mut encoded = Vec::new();
    ciborium::into_writer(receipt, &mut encoded).unwrap();
    encoded
}

/// Re-encode CBOR receipt bytes with only `protocol_version` replaced.
fn cbor_relabel(source: &[u8], label: &str) -> Vec<u8> {
    let mut value: ciborium::Value = ciborium::from_reader(source).unwrap();
    let entry = value
        .as_map_mut()
        .unwrap()
        .iter_mut()
        .find(|(key, _)| key.as_text() == Some("protocol_version"))
        .unwrap();
    entry.1 = ciborium::Value::Text(label.into());
    let mut encoded = Vec::new();
    ciborium::into_writer(&value, &mut encoded).unwrap();
    encoded
}

/// The implementation's decode message, taken out of ciborium's wrapper.
fn cbor_decode_err<T: serde::de::DeserializeOwned + std::fmt::Debug>(source: &[u8]) -> String {
    match ciborium::from_reader::<T, _>(source) {
        Err(ciborium::de::Error::Semantic(_, message)) => message,
        other => panic!("expected a semantic decode refusal, got {other:?}"),
    }
}

/// The implementation's serialise message, taken out of ciborium's wrapper.
fn cbor_serialise_err(receipt: &DeletionReceiptV5) -> String {
    match ciborium::into_writer(receipt, &mut Vec::new()) {
        Err(ciborium::ser::Error::Value(message)) => message,
        other => panic!("expected a serialise refusal, got {other:?}"),
    }
}

#[test]
fn positive_digest_vectors_match_implementation() {
    let v = corpus("gv5-001");
    let parts: Vec<Vec<u8>> = v["inputs"]["parts_hex"]
        .as_array()
        .unwrap()
        .iter()
        .map(bytes)
        .collect();
    let refs: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
    let mut tagged_parts = vec![v["inputs"]["tag_ascii"].as_str().unwrap().as_bytes()];
    tagged_parts.extend(refs);
    assert_eq!(
        sha256_concat(&tagged_parts),
        expected_hex(&v, "digest").as_slice()
    );

    let v = corpus("gv5-002");
    let input = &v["inputs"];
    let tombstone = zombie_core::tombstone_constant();
    assert_eq!(tombstone.as_slice(), expected_hex(&v, "tombstone_constant"));
    let ts = input["timestamp"].as_u64().unwrap().to_be_bytes();
    let seq = input["deletion_seq"].as_u64().unwrap().to_be_bytes();
    assert_eq!(
        hash_with_tag(
            TAG_TOMBSTONE_HASH,
            &[
                &bytes(&input["canister_id_hex"]),
                tombstone.as_slice(),
                &ts,
                &seq
            ]
        )
        .as_slice(),
        expected_hex(&v, "tombstone_hash")
    );

    let v = corpus("gv5-003");
    let input = &v["inputs"];
    for case in v["expected"]["cases"].as_array().unwrap() {
        let actual = deletion_event_hash_v5(
            &array32(&input["pre_state_hash"]),
            &array32(&input["post_state_hash"]),
            &array32(&input["receipt_id"]),
            input["timestamp"].as_u64().unwrap(),
            &array32(&input["module_hash"]),
            case["deletion_seq"].as_u64().unwrap(),
        );
        assert_eq!(actual.as_slice(), bytes(&case["deletion_event_hash"]));
    }

    let v = corpus("gv5-004");
    let input = &v["inputs"];
    let canister = principal(&input["canister_id_hex"]);
    for case in v["expected"]["cases"].as_array().unwrap() {
        assert_eq!(
            compute_receipt_id(
                &canister,
                &bytes(&case["record_id_hex"]),
                input["deletion_seq"].as_u64().unwrap()
            )
            .as_slice(),
            bytes(&case["receipt_id"])
        );
    }

    let v = corpus("gv5-005");
    for case in v["expected"]["cases"].as_array().unwrap() {
        assert_eq!(
            genesis_certified_data(&principal(&case["canister_id_hex"])).as_slice(),
            bytes(&case["genesis_certified_data"])
        );
    }

    let v = corpus("gv5-006");
    assert_eq!(v["expected"]["different"], true);
    assert_ne!(
        expected_hex(&v, "genesis_certified_data"),
        expected_hex(&v, "deletion_event_hash")
    );

    let v = corpus("gv5-011");
    let salt = hash_with_tag(TAG_SALT, &[&bytes(&v["inputs"]["canister_id_hex"])]);
    assert_eq!(salt.as_slice(), expected_hex(&v, "mktd_salt"));
    assert_eq!(
        sha256_concat(&[&salt, &bytes(&v["inputs"]["state_bytes_hex"])]).as_slice(),
        expected_hex(&v, "state_hash")
    );
}

#[test]
fn v5_receipt_wire_and_state_vectors_match() {
    for id in ["gv5-007", "gv5-008"] {
        let vector = corpus(id);
        let receipt = v5_receipt(&vector);
        let mut cbor = Vec::new();
        ciborium::into_writer(&receipt, &mut cbor).unwrap();
        assert_eq!(hex::encode(cbor), vector["expected"]["cbor_hex"]);
        assert_eq!(
            serde_json::to_string(&receipt).unwrap(),
            vector["expected"]["json_text"]
        );
        assert_eq!(
            format!("{:?}", receipt.state()),
            vector["expected"]["state"]
        );
    }

    let finalized = corpus("gv5-007");
    let cbor = expected_hex(&finalized, "cbor_hex");
    let value: ciborium::Value = ciborium::from_reader(cbor.as_slice()).unwrap();
    let map = value.as_map().unwrap();
    for field in [
        "receipt_id",
        "canister_id",
        "record_id",
        "pre_state_hash",
        "post_state_hash",
        "tombstone_hash",
        "deletion_event_hash",
        "module_hash",
        "bls_certificate",
        "module_hash_certificate",
    ] {
        let value = map
            .iter()
            .find(|(key, _)| key.as_text() == Some(field))
            .unwrap()
            .1
            .clone();
        assert!(
            matches!(value, ciborium::Value::Bytes(_)),
            "{field} is not a CBOR byte string"
        );
    }

    let vector = corpus("gv5-009");
    let template = v5_receipt(&corpus("gv5-007"));
    for (input, expected) in vector["inputs"]["certificate_cases"]
        .as_array()
        .unwrap()
        .iter()
        .zip(vector["expected"]["cases"].as_array().unwrap())
    {
        assert_eq!(input["name"], expected["name"]);
        let mut receipt = template.clone();
        receipt.bls_certificate = input["bls_certificate"]
            .as_str()
            .map(|_| bytes(&input["bls_certificate"]));
        receipt.module_hash_certificate = input["module_hash_certificate"]
            .as_str()
            .map(|_| bytes(&input["module_hash_certificate"]));
        assert_eq!(format!("{:?}", receipt.state()), expected["state"]);
    }
}

#[test]
fn tag_groups_and_goldens_match() {
    let v = corpus("gv5-010");
    let expected = &v["expected"];
    let v5 = [
        ("MKTD02_TOMBSTONE_HASH_V1", TAG_TOMBSTONE_HASH),
        ("MKTD02_EVENT_V2", TAG_EVENT_V2),
        ("MKTD02_RECEIPT_V3", TAG_RECEIPT_V3),
        ("MKTD02_GENESIS_V1", TAG_GENESIS),
        ("MKTD02_SALT_V1", TAG_SALT),
    ];
    let other = [
        ("MKTD02_EVENT_V1", TAG_EVENT),
        ("MKTD02_RECEIPT_V1", TAG_RECEIPT),
        ("MKTD02_MANIFEST_V1", TAG_MANIFEST),
    ];
    for (group, tags) in [
        ("v5_used", v5.as_slice()),
        ("active_other_lines", other.as_slice()),
    ] {
        let rows = expected[group].as_array().unwrap();
        assert_eq!(rows.len(), tags.len());
        for ((name, tag), row) in tags.iter().zip(rows) {
            assert_eq!(row["tag_ascii"], *name);
            assert_eq!(
                hash_with_tag(*tag, &[b"test"]).as_slice(),
                bytes(&row["digest"])
            );
        }
    }
}

#[test]
fn tolerant_decode_vector_matches_canonical_value() {
    let vector = corpus("gv5-012");
    let canonical: DeletionReceiptV5 =
        serde_json::from_value(vector["inputs"]["canonical"].clone()).unwrap();
    for case in vector["inputs"]["tolerated"].as_array().unwrap() {
        let mut candidate = vector["inputs"]["canonical"].clone();
        for (key, value) in case["overrides"].as_object().unwrap() {
            candidate[key] = value.clone();
        }
        let decoded: DeletionReceiptV5 = serde_json::from_value(candidate).unwrap();
        assert_eq!(decoded, canonical, "{}", case["name"]);
    }
    assert!(vector["expected"]["cases"]
        .as_array()
        .unwrap()
        .iter()
        .all(|case| case["equals_canonical"] == true));
}

#[test]
fn negative_vectors_match_named_layers_and_precedence() {
    let vector = corpus("nv5-001");
    assert_eq!(vector["expected"]["layer"], vector["inputs"]["operation"]);
    let mut base = base_json();
    for (case, expected) in vector["inputs"]["cases"]
        .as_array()
        .unwrap()
        .iter()
        .zip(vector["expected"]["cases"].as_array().unwrap())
    {
        base["certified_commitment"] = case["value"].clone();
        let err = serde_json::from_value::<DeletionReceiptV5>(base.clone())
            .unwrap_err()
            .to_string();
        assert_eq!(err, expected["error"]);
    }

    let vector = corpus("nv5-002");
    assert_eq!(vector["expected"]["layer"], vector["inputs"]["operation"]);
    let prefix = vector["expected"]["error_prefix"].as_str().unwrap();
    for key in vector["inputs"]["unknown_keys"].as_array().unwrap() {
        let key = key.as_str().unwrap();
        let mut value = base_json();
        value[key] = json!(1);
        let err = serde_json::from_value::<DeletionReceiptV5>(value.clone())
            .unwrap_err()
            .to_string();
        assert!(err.starts_with(prefix), "{err}");
        if vector["inputs"]["formats"]
            .as_array()
            .unwrap()
            .iter()
            .any(|format| format == "cbor")
        {
            let cbor = cbor_with_unknown(key);
            let err = ciborium::from_reader::<DeletionReceiptV5, _>(cbor.as_slice())
                .unwrap_err()
                .to_string();
            assert!(err.contains(prefix), "{err}");
        }
    }

    let vector = corpus("nv5-003");
    assert_eq!(vector["expected"]["layer"], vector["inputs"]["operation"]);
    let mut value = base_json();
    for (key, item) in vector["inputs"]["fields"].as_object().unwrap() {
        value[key] = item.clone();
    }
    assert!(serde_json::from_value::<DeletionReceiptV5>(value)
        .unwrap_err()
        .to_string()
        .starts_with(vector["expected"]["error_prefix"].as_str().unwrap()));

    let vector = corpus("nv5-004");
    assert_eq!(vector["expected"]["layer"], vector["inputs"]["operation"]);
    let mut value = base_json();
    for (key, item) in vector["inputs"]["mutation"].as_object().unwrap() {
        value[key] = item.clone();
    }
    assert_eq!(
        serde_json::from_value::<DeletionReceiptV5>(value)
            .unwrap_err()
            .to_string(),
        vector["expected"]["error"]
    );

    let vector = corpus("nv5-005");
    assert_eq!(vector["expected"]["layer"], vector["inputs"]["operation"]);
    let mut receipt: DeletionReceiptV5 = serde_json::from_value(base_json()).unwrap();
    receipt.deletion_event_hash = array32(&vector["inputs"]["mutation"]["deletion_event_hash"]);
    let err = serde_json::to_string(&receipt).unwrap_err().to_string();
    assert!(err.contains(vector["expected"]["error"].as_str().unwrap()));

    let vector = corpus("nv5-006");
    assert_eq!(vector["expected"]["layer"], vector["inputs"]["operation"]);
    let canister = principal(&vector["inputs"]["canister_id_hex"]);
    assert_eq!(
        check_certified_data_not_genesis(&canister, &genesis_certified_data(&canister)),
        Err(vector["expected"]["error"].as_str().unwrap())
    );
    assert_eq!(
        genesis_certified_data(&canister).as_slice(),
        expected_hex(&vector, "certified_data")
    );

    let vector = corpus("nv5-007");
    assert_eq!(vector["expected"]["layer"], vector["inputs"]["operation"]);
    let base_cbor = v5_cbor(&serde_json::from_value(base_json()).unwrap());
    for case in vector["expected"]["cases"].as_array().unwrap() {
        let label = case["label"].as_str().unwrap();
        let fragment = case["error"].as_str().unwrap();
        assert!(vector["inputs"]["labels"]
            .as_array()
            .unwrap()
            .contains(&case["label"]));

        // Decode: the v5 type directly and via dispatch, JSON and CBOR.
        let mut value = base_json();
        value["protocol_version"] = json!(label);
        let cbor = cbor_relabel(&base_cbor, label);
        let decode_errors = [
            serde_json::from_value::<DeletionReceiptV5>(value.clone())
                .unwrap_err()
                .to_string(),
            AnyDeletionReceipt::from_json_value(value).unwrap_err(),
            cbor_decode_err::<DeletionReceiptV5>(&cbor),
            AnyDeletionReceipt::from_cbor(&cbor).unwrap_err(),
        ];
        for err in decode_errors {
            assert!(err.contains(fragment), "{label:?}: {err}");
        }

        // Serialise: the same label on a v5 receipt, JSON and CBOR.
        let receipt = DeletionReceiptV5 {
            protocol_version: label.into(),
            ..serde_json::from_value(base_json()).unwrap()
        };
        let serialise_errors = [
            serde_json::to_string(&receipt).unwrap_err().to_string(),
            cbor_serialise_err(&receipt),
        ];
        for err in serialise_errors {
            assert!(err.contains(fragment), "{label:?}: {err}");
        }
    }

    let vector = corpus("nv5-008");
    assert_eq!(vector["expected"]["layer"], vector["inputs"]["operation"]);
    for (input, case) in vector["inputs"]["cases"]
        .as_array()
        .unwrap()
        .iter()
        .zip(vector["expected"]["cases"].as_array().unwrap())
    {
        assert_eq!(input["name"], case["name"]);
        assert_eq!(input["label"], case["label"]);
        let label = input["label"].as_str().unwrap();
        let frozen = case["error"].as_str().unwrap();
        match case["name"].as_str().unwrap() {
            // §7 fragment, substring position. Decoded only through
            // DeletionReceiptV5: AnyDeletionReceipt routes a v4 label to
            // DeletionReceiptV4 by design (§8.4), so it is not this refusal.
            "v4_label_to_v5_type" => {
                let mut value = base_json();
                value["protocol_version"] = json!(label);
                let base_cbor = v5_cbor(&serde_json::from_value(base_json()).unwrap());
                for err in [
                    serde_json::from_value::<DeletionReceiptV5>(value)
                        .unwrap_err()
                        .to_string(),
                    cbor_decode_err::<DeletionReceiptV5>(&cbor_relabel(&base_cbor, label)),
                ] {
                    assert!(err.contains(frozen), "{err}");
                }
            }
            // §8.4 prefix: the frozen v4 type's decode refusal begins with it.
            "v5_label_to_v4_type" => {
                let wire = historical("v3-wire");
                let mut value: Value =
                    serde_json::from_str(wire["expected"]["json_text"].as_str().unwrap()).unwrap();
                value["protocol_version"] = json!(label);
                let cbor = cbor_relabel(&expected_hex(&wire, "cbor_hex"), label);
                for err in [
                    serde_json::from_value::<DeletionReceiptV4>(value)
                        .unwrap_err()
                        .to_string(),
                    cbor_decode_err::<DeletionReceiptV4>(&cbor),
                ] {
                    assert!(err.starts_with(frozen), "{err}");
                }
            }
            name => panic!("unknown nv5-008 case {name}"),
        }
    }
}

#[test]
fn v1_mismatch_corpus_values_are_recomputed_by_code() {
    let v = corpus("nv5-009");
    assert_eq!(v["expected"]["layer"], "verify");
    assert_eq!(v["expected"]["matches"], false);
    let input = &v["inputs"]["valid_receipt_id_inputs"];
    // Fields outside the receipt_id preimage come from the canonical fixture;
    // verify_v1 rejects at step 1 without reading them.
    let receipt = DeletionReceiptV5 {
        receipt_id: array32(&v["inputs"]["presented_receipt_id"]),
        canister_id: principal(&input["canister_id_hex"]),
        record_id: bytes(&input["record_id_hex"]),
        deletion_seq: input["deletion_seq"].as_u64().unwrap(),
        ..serde_json::from_value(base_json()).unwrap()
    };
    assert_eq!(
        verify_v1(&receipt),
        Err(v["expected"]["error"].as_str().unwrap())
    );
    let actual = compute_receipt_id(
        &principal(&input["canister_id_hex"]),
        &bytes(&input["record_id_hex"]),
        input["deletion_seq"].as_u64().unwrap(),
    );
    assert_eq!(
        actual.as_slice(),
        bytes(&v["expected"]["recomputed_receipt_id"])
    );
    assert_ne!(
        actual.as_slice(),
        bytes(&v["expected"]["presented_receipt_id"])
    );

    let v = corpus("nv5-010");
    assert_eq!(v["expected"]["layer"], "verify");
    assert_eq!(v["expected"]["matches"], false);
    let input = &v["inputs"]["valid_event_inputs"];
    // A §3.4 single-step vector: its receipt_id is a given, not derivable
    // from any (canister_id, record_id), so it exercises the event-hash step
    // directly. verify_v1's ordering is proven by the unit tests.
    let receipt = DeletionReceiptV5 {
        pre_state_hash: array32(&input["pre_state_hash"]),
        post_state_hash: array32(&input["post_state_hash"]),
        receipt_id: array32(&input["receipt_id"]),
        timestamp: input["timestamp"].as_u64().unwrap(),
        module_hash: array32(&input["module_hash"]),
        deletion_seq: input["deletion_seq"].as_u64().unwrap(),
        deletion_event_hash: array32(&v["inputs"]["presented_deletion_event_hash"]),
        ..serde_json::from_value(base_json()).unwrap()
    };
    assert_eq!(
        verify_v1_event_hash(&receipt),
        Err(v["expected"]["error"].as_str().unwrap())
    );
    let actual = deletion_event_hash_v5(
        &array32(&input["pre_state_hash"]),
        &array32(&input["post_state_hash"]),
        &array32(&input["receipt_id"]),
        input["timestamp"].as_u64().unwrap(),
        &array32(&input["module_hash"]),
        input["deletion_seq"].as_u64().unwrap(),
    );
    assert_eq!(
        actual.as_slice(),
        bytes(&v["expected"]["recomputed_deletion_event_hash"])
    );
    assert_ne!(
        actual.as_slice(),
        bytes(&v["expected"]["presented_deletion_event_hash"])
    );
}

#[test]
fn historical_vectors_remain_frozen_and_tolerant() {
    let event = historical("event-v1");
    let input = &event["inputs"];
    assert_eq!(
        deletion_event_hash_v1(
            &array32(&input["pre_state_hash"]),
            &array32(&input["post_state_hash"]),
            input["timestamp"].as_u64().unwrap(),
            &array32(&input["module_hash"]),
            input["deletion_seq"].as_u64().unwrap()
        )
        .as_slice(),
        expected_hex(&event, "deletion_event_hash")
    );

    let certified = historical("certified-commitment");
    let expected = &certified["expected"];
    assert_eq!(
        TAG_CERTIFIED
            .hash_historical(&[
                &array32(&certified["inputs"]["post_state_hash"]),
                &array32(&expected["deletion_event_hash"])
            ])
            .as_slice(),
        bytes(&expected["certified_commitment"])
    );

    let certified_tag = historical("certified-tag");
    assert_eq!(
        TAG_CERTIFIED.hash_historical(&[&bytes(&certified_tag["inputs"]["part_hex"])]),
        array32(&certified_tag["expected"]["digest"])
    );

    let wire = historical("v3-wire");
    let receipt: DeletionReceiptV4 =
        serde_json::from_str(wire["expected"]["json_text"].as_str().unwrap()).unwrap();
    let mut cbor = Vec::new();
    ciborium::into_writer(&receipt, &mut cbor).unwrap();
    assert_eq!(hex::encode(cbor), wire["expected"]["cbor_hex"]);
    for id in ["nv5-011a", "nv5-011b", "nv5-011c"] {
        let vector = corpus(id);
        assert_eq!(vector["expected"]["layer"], vector["inputs"]["operation"]);
        assert_eq!(
            vector["expected"]["protocol_version"],
            vector["inputs"]["protocol_version"]
        );
        let label = vector["inputs"]["protocol_version"].as_str().unwrap();
        let fixture = DeletionReceiptV4 {
            protocol_version: label.into(),
            ..receipt.clone()
        };
        let mut value = serde_json::to_value(&fixture).unwrap();
        value[vector["inputs"]["unknown_key"].as_str().unwrap()] = json!(1);
        let actual = if serde_json::from_value::<DeletionReceiptV4>(value).is_ok() {
            "accepted"
        } else {
            "rejected"
        };
        assert_eq!(actual, vector["expected"]["result"], "{label}");
    }

    let v5_label = DeletionReceiptV4 {
        protocol_version: "mktd02-v5".into(),
        ..receipt
    };
    let err = serde_json::to_string(&v5_label).unwrap_err().to_string();
    assert!(
        err.contains("DeletionReceipt: unrecognised protocol_version"),
        "{err}"
    );
}
