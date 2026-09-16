//! # Receipt Export
//!
//! - `to_cbor_bytes()` -- always available; deterministic CBOR encoding
//! - `to_json()` -- behind `#[cfg(feature = "json")]`
//! - `webhook_push()` -- behind `#[cfg(feature = "json")]`; template only
//!
//! Exported receipts are issued receipts of any line (v2–v4 or v5), so each
//! function takes an [`AnyDeletionReceipt`] and emits that line's own wire shape.

use zombie_core::AnyDeletionReceipt;

/// Serialise a receipt to deterministic CBOR bytes.
pub fn to_cbor_bytes(receipt: &AnyDeletionReceipt) -> Vec<u8> {
    let mut buf = Vec::new();
    let res = match receipt {
        AnyDeletionReceipt::V4(r) => ciborium::into_writer(r, &mut buf),
        AnyDeletionReceipt::V5(r) => ciborium::into_writer(r, &mut buf),
    };
    res.expect("MKTd02: CBOR encoding of receipt failed");
    buf
}

/// Serialise a receipt to JSON. Requires the `json` feature.
#[cfg(feature = "json")]
pub fn to_json(receipt: &AnyDeletionReceipt) -> String {
    match receipt {
        AnyDeletionReceipt::V4(r) => serde_json::to_string_pretty(r),
        AnyDeletionReceipt::V5(r) => serde_json::to_string_pretty(r),
    }
    .expect("MKTd02: JSON encoding of receipt failed")
}

/// Template for pushing a receipt to an external webhook via HTTP outcall.
/// Requires the `json` feature. This is a starting point; enterprises
/// should customise the payload format for their SIEM.
#[cfg(feature = "json")]
pub fn webhook_push(_receipt: &AnyDeletionReceipt, _url: &str) -> Result<(), String> {
    // Template: implement via ic_cdk::api::management_canister::http_request
    Err("webhook_push is a template; implement HTTP outcall for your use case".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use candid::Principal;
    use ciborium::value::Value;
    use zombie_core::{DeletionReceiptV4, DeletionReceiptV5, ProtocolVersion};

    fn v5_fixture() -> DeletionReceiptV5 {
        DeletionReceiptV5 {
            protocol_version: ProtocolVersion::V5.into(),
            receipt_id: [1u8; 32],
            canister_id: Principal::from_slice(&[1, 2, 3, 4]),
            record_id: vec![10, 11, 12],
            pre_state_hash: [2u8; 32],
            post_state_hash: [3u8; 32],
            tombstone_hash: [4u8; 32],
            deletion_event_hash: [5u8; 32],
            module_hash: [7u8; 32],
            timestamp: 1_000_000,
            deletion_seq: 7,
            bls_certificate: Some(vec![0xAA, 0xBB, 0xCC]),
            trust_root_key_id: "mainnet".into(),
            module_hash_certificate: Some(vec![1, 2, 3, 4]),
        }
    }

    fn v4_fixture() -> DeletionReceiptV4 {
        DeletionReceiptV4 {
            protocol_version: ProtocolVersion::V4.into(),
            receipt_id: [1u8; 32],
            canister_id: Principal::from_slice(&[1, 2, 3, 4]),
            record_id: vec![10, 11, 12],
            pre_state_hash: [2u8; 32],
            post_state_hash: [3u8; 32],
            tombstone_hash: [4u8; 32],
            deletion_event_hash: [5u8; 32],
            certified_commitment: [6u8; 32],
            module_hash: [7u8; 32],
            timestamp: 1_000_000,
            deletion_seq: 7,
            bls_certificate: Some(vec![0xAA, 0xBB, 0xCC]),
            trust_root_key_id: "mainnet".into(),
            module_hash_certificate: Some(vec![1, 2, 3, 4]),
        }
    }

    /// Pull one top-level field out of an exported receipt's CBOR.
    fn cbor_field(bytes: &[u8], name: &str) -> Value {
        let decoded: Value = ciborium::from_reader(bytes).expect("export must be valid CBOR");
        decoded
            .as_map()
            .expect("an exported receipt is a CBOR map")
            .iter()
            .find(|(k, _)| k.as_text() == Some(name))
            .map(|(_, v)| v.clone())
            .unwrap_or_else(|| panic!("exported receipt is missing {name}"))
    }

    /// L5: the pin's CBOR change reaches Leaf — every byte-valued field of an
    /// exported v5 receipt is a CBOR byte string (major type 2), carrying
    /// exactly the field's bytes. `Value::Bytes` is produced only by major
    /// type 2, so matching on it is the semantic check.
    #[test]
    fn l5_v5_export_emits_cbor_byte_strings() {
        let r = v5_fixture();
        let cbor = to_cbor_bytes(&AnyDeletionReceipt::V5(r.clone()));

        let expected: &[(&str, Vec<u8>)] = &[
            ("receipt_id", r.receipt_id.to_vec()),
            ("canister_id", r.canister_id.as_slice().to_vec()),
            ("record_id", r.record_id.clone()),
            ("pre_state_hash", r.pre_state_hash.to_vec()),
            ("post_state_hash", r.post_state_hash.to_vec()),
            ("tombstone_hash", r.tombstone_hash.to_vec()),
            ("deletion_event_hash", r.deletion_event_hash.to_vec()),
            ("module_hash", r.module_hash.to_vec()),
            ("bls_certificate", r.bls_certificate.clone().unwrap()),
            (
                "module_hash_certificate",
                r.module_hash_certificate.clone().unwrap(),
            ),
        ];

        for (name, payload) in expected {
            match cbor_field(&cbor, name) {
                Value::Bytes(b) => assert_eq!(
                    &b, payload,
                    "{name}: byte-string payload must equal the field value"
                ),
                other => panic!("{name}: expected a CBOR byte string, got {other:?}"),
            }
        }
    }

    /// L5: an absent optional stays CBOR `null` with its key present.
    #[test]
    fn l5_v5_export_keeps_absent_certificates_as_null() {
        let pending = DeletionReceiptV5 {
            bls_certificate: None,
            module_hash_certificate: None,
            ..v5_fixture()
        };
        let cbor = to_cbor_bytes(&AnyDeletionReceipt::V5(pending));
        for name in ["bls_certificate", "module_hash_certificate"] {
            assert!(
                matches!(cbor_field(&cbor, name), Value::Null),
                "{name}: an absent optional must export as CBOR null"
            );
        }
    }

    /// L5 control: the frozen v2–v4 export is unchanged — those fields are
    /// still CBOR arrays, so the v5 wire change did not reach the v4 path.
    #[test]
    fn l5_v4_export_still_emits_arrays() {
        let r = v4_fixture();
        let cbor = to_cbor_bytes(&AnyDeletionReceipt::V4(r));

        for name in [
            "receipt_id",
            "record_id",
            "pre_state_hash",
            "post_state_hash",
            "tombstone_hash",
            "deletion_event_hash",
            "certified_commitment",
            "module_hash",
            "bls_certificate",
        ] {
            assert!(
                matches!(cbor_field(&cbor, name), Value::Array(_)),
                "{name}: the frozen v4 export must stay a CBOR array"
            );
        }

        // The principal was always a byte string, on every line.
        assert!(matches!(cbor_field(&cbor, "canister_id"), Value::Bytes(_)));
    }
}
