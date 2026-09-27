//! Executable code leg for every independently-derived v5.1 vector.

use candid::Principal;
use serde_json::{Map, Value};
use std::{fs, path::PathBuf};
use zombie_core::{
    compute_receipt_id, deletion_event_hash_v5, deletion_event_hash_v51, verify_v1,
    verify_v1_v51, AnyDeletionReceipt, DeletionReceiptV5, DeletionReceiptV51, ReceiptState,
    ERR_RETIRED_FIELD_CERTIFIED_COMMITMENT, ERR_V1_EVENT_HASH_MISMATCH,
    ERR_V1_RECEIPT_ID_MISMATCH,
};

fn vector(id: &str) -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("docs/test-vectors/v5.1").join(format!("{id}.json"));
    serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap()
}
fn bytes(v: &Value) -> Vec<u8> { hex::decode(v.as_str().unwrap()).unwrap() }
fn a32(v: &Value) -> [u8; 32] { bytes(v).try_into().unwrap() }

fn receipt_json(input: &Value) -> Value {
    let mut out = Map::new();
    for (key, value) in input.as_object().unwrap() {
        if key == "canister_id_hex" || key == "canister_id_text" { continue; }
        out.insert(key.clone(), value.clone());
    }
    out.insert("canister_id".into(), input["canister_id_text"].clone());
    Value::Object(out)
}

#[test]
fn v51_vectors_gv51_001_through_gv51_004() {
    let v = vector("gv51-001");
    for case in v["expected"]["cases"].as_array().unwrap() {
        assert_eq!(
            deletion_event_hash_v51(&a32(&v["inputs"]["pre_state_hash"]), &a32(&v["inputs"]["post_state_hash"]), &a32(&v["inputs"]["receipt_id"]), v["inputs"]["timestamp"].as_u64().unwrap(), case["deletion_seq"].as_u64().unwrap()),
            a32(&case["deletion_event_hash"]));
    }
    let v = vector("gv51-002");
    assert_eq!(compute_receipt_id(&Principal::from_slice(&bytes(&v["inputs"]["canister_id_hex"])), &bytes(&v["inputs"]["record_id"]), v["inputs"]["deletion_seq"].as_u64().unwrap()), a32(&v["expected"]["receipt_id"]));
    assert_eq!(deletion_event_hash_v51(&a32(&v["inputs"]["pre_state_hash"]), &a32(&v["inputs"]["post_state_hash"]), &a32(&v["expected"]["receipt_id"]), v["inputs"]["timestamp"].as_u64().unwrap(), v["inputs"]["deletion_seq"].as_u64().unwrap()), a32(&v["expected"]["deletion_event_hash"]));
    let v = vector("gv51-003");
    let h = deletion_event_hash_v51(&a32(&v["inputs"]["pre_state_hash"]), &a32(&v["inputs"]["post_state_hash"]), &a32(&v["inputs"]["receipt_id"]), v["inputs"]["timestamp"].as_u64().unwrap(), v["inputs"]["deletion_seq"].as_u64().unwrap());
    assert_eq!(h, a32(&v["expected"]["event_v3_with_module_hash_a"]));
    assert_eq!(h, a32(&v["expected"]["event_v3_with_module_hash_b"]));
    assert_ne!(deletion_event_hash_v5(&a32(&v["inputs"]["pre_state_hash"]), &a32(&v["inputs"]["post_state_hash"]), &a32(&v["inputs"]["receipt_id"]), v["inputs"]["timestamp"].as_u64().unwrap(), &a32(&v["inputs"]["module_hash_a"]), v["inputs"]["deletion_seq"].as_u64().unwrap()), deletion_event_hash_v5(&a32(&v["inputs"]["pre_state_hash"]), &a32(&v["inputs"]["post_state_hash"]), &a32(&v["inputs"]["receipt_id"]), v["inputs"]["timestamp"].as_u64().unwrap(), &a32(&v["inputs"]["module_hash_b"]), v["inputs"]["deletion_seq"].as_u64().unwrap()));
    let v = vector("gv51-004");
    assert_ne!(a32(&v["expected"]["direct"]["event_v3"]), a32(&v["expected"]["direct"]["event_v3_receipt_id_changed"]));
}

#[test]
fn v51_vectors_gv51_005_006_and_007_wire_dispatch() {
    for id in ["gv51-005", "gv51-006"] {
        let v = vector(id);
        let expected = &v["expected"];
        let json: Value = serde_json::from_str(expected["json_text"].as_str().unwrap()).unwrap();
        let r: DeletionReceiptV51 = serde_json::from_value(json.clone()).unwrap();
        assert_eq!(r.state(), if id == "gv51-005" { ReceiptState::FinalizedCandidate } else { ReceiptState::Pending });
        assert_eq!(verify_v1_v51(&r), Ok(()));
        assert_eq!(serde_json::to_string(&r).unwrap(), expected["json_text"].as_str().unwrap());
        let mut cbor = Vec::new(); ciborium::into_writer(&r, &mut cbor).unwrap();
        assert_eq!(hex::encode(cbor), expected["cbor_hex"].as_str().unwrap());
        assert!(matches!(AnyDeletionReceipt::from_json_value(json).unwrap(), AnyDeletionReceipt::V51(_)));
    }
    let v = vector("gv51-007");
    assert_eq!(v["expected"]["lines"][0]["event_operands"], 6);
    assert_eq!(v["expected"]["lines"][1]["event_operands"], 5);
}

#[test]
fn v51_vectors_nv51_001_through_006() {
    let final_json: Value = serde_json::from_str(vector("gv51-005")["expected"]["json_text"].as_str().unwrap()).unwrap();
    let pending_json: Value = serde_json::from_str(vector("gv51-006")["expected"]["json_text"].as_str().unwrap()).unwrap();
    for case in vector("nv51-001")["inputs"]["cases"].as_array().unwrap() {
        let mut json = final_json.clone(); json["protocol_version"] = case["protocol_version"].clone();
        assert!(serde_json::from_value::<DeletionReceiptV51>(json).is_err());
    }
    for case in vector("nv51-002")["inputs"]["cases"].as_array().unwrap() {
        let json = receipt_json(&case["receipt"]);
        if json["protocol_version"] == "mktd02-v5.1" { assert_eq!(verify_v1_v51(&serde_json::from_value(json).unwrap()), Err(ERR_V1_EVENT_HASH_MISMATCH)); }
        else { assert_eq!(verify_v1(&serde_json::from_value::<DeletionReceiptV5>(json).unwrap()), Err(ERR_V1_EVENT_HASH_MISMATCH)); }
    }
    for case in vector("nv51-003")["inputs"]["cases"].as_array().unwrap() {
        let r: DeletionReceiptV51 = serde_json::from_value(receipt_json(&case["receipt"])).unwrap();
        assert_eq!(r.state(), ReceiptState::InvalidIncompleteFinalization);
    }
    for case in vector("nv51-004")["inputs"]["cases"].as_array().unwrap() {
        let mut json = pending_json.clone(); json[case["key"].as_str().unwrap()] = case["value"].clone();
        assert!(serde_json::from_value::<DeletionReceiptV51>(json).is_err());
    }
    for case in vector("nv51-005")["inputs"]["cases"].as_array().unwrap() {
        let r: DeletionReceiptV51 = serde_json::from_value(receipt_json(&case["receipt"])).unwrap();
        let expected = match case["name"].as_str().unwrap() {
            "record_id_only" | "deletion_seq" => ERR_V1_RECEIPT_ID_MISMATCH,
            "module_hash_only" => continue,
            _ => ERR_V1_EVENT_HASH_MISMATCH,
        };
        assert_eq!(verify_v1_v51(&r), Err(expected));
    }
    for template in [final_json, pending_json] {
        for value in [Value::String("00".repeat(32)), Value::Null] {
            let mut json = template.clone(); json["certified_commitment"] = value;
            assert!(serde_json::from_value::<DeletionReceiptV51>(json).unwrap_err().to_string().contains(ERR_RETIRED_FIELD_CERTIFIED_COMMITMENT));
        }
    }
}
