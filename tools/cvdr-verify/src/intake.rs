//! Receipt intake: every receipt is decoded by `zombie_core::AnyDeletionReceipt`,
//! so the zombie-core types are what every check consumes and zombie-core's
//! named decode errors surface verbatim.
//!
//! - **File** (`--receipt-file`): JSON or CBOR. v5 JSON is zombie-core decode
//!   of the ratified wire (JSON numbers). v2–v4 JSON keeps the historical intake
//!   tolerance: decimal-string numerics are accepted and a v2 `subnet_id` must
//!   be a valid principal.
//! - **Network** (`--canister`/`--receipt-id`): the DaffyDefs `mktd_get_receipt`
//!   Candid response (hex `text` hashes) is converted by a typed adapter into the
//!   receipt wire, then decoded by `AnyDeletionReceipt`. Fetching a receipt is
//!   intake, not a live check.

use candid::{CandidType, Decode, Encode, Principal};
use ic_agent::Agent;
use serde::Deserialize;
use serde_json::{json, Map, Value};
use zombie_core::AnyDeletionReceipt;

/// Why intake produced no receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntakeError {
    /// The receipt bytes were read and refused. The message is the named error,
    /// verbatim from zombie-core where it originates there. Validity: FAIL.
    Rejected(String),
    /// The receipt could not be obtained (unreadable file, network failure).
    /// No verdict.
    Unavailable(String),
}

impl std::fmt::Display for IntakeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IntakeError::Rejected(m) | IntakeError::Unavailable(m) => f.write_str(m),
        }
    }
}

/// Named historical-intake refusal (v2 `subnet_id` validation).
pub const ERR_INTAKE_V2_SUBNET_ID: &str = "intake-historical:v2-subnet-id-invalid";
/// Named refusal for bytes that are neither a JSON object nor CBOR.
pub const ERR_INTAKE_MALFORMED_JSON: &str = "intake:malformed-json";

/// Read a receipt file (JSON or CBOR).
pub fn read_receipt_file(path: &str) -> Result<AnyDeletionReceipt, IntakeError> {
    let bytes = std::fs::read(path).map_err(|e| {
        IntakeError::Unavailable(format!("failed to read receipt file '{path}': {e}"))
    })?;
    decode_receipt_bytes(&bytes)
}

/// Decode receipt bytes: a JSON object if the first non-whitespace byte is `{`,
/// otherwise CBOR.
pub fn decode_receipt_bytes(bytes: &[u8]) -> Result<AnyDeletionReceipt, IntakeError> {
    let first = bytes.iter().find(|b| !b.is_ascii_whitespace());
    if first == Some(&b'{') {
        let value: Value = serde_json::from_slice(bytes)
            .map_err(|e| IntakeError::Rejected(format!("{ERR_INTAKE_MALFORMED_JSON}: {e}")))?;
        decode_receipt_json(value)
    } else {
        AnyDeletionReceipt::from_cbor(bytes).map_err(IntakeError::Rejected)
    }
}

/// Decode a JSON receipt value, applying historical tolerance to v2–v4 labels.
pub fn decode_receipt_json(mut value: Value) -> Result<AnyDeletionReceipt, IntakeError> {
    if let Some(label) = value
        .get("protocol_version")
        .and_then(Value::as_str)
        .map(str::to_owned)
    {
        if is_historical_label(&label) {
            apply_historical_tolerance(&mut value, &label)?;
        }
    }
    AnyDeletionReceipt::from_json_value(value).map_err(IntakeError::Rejected)
}

/// A label zombie-core decodes as `DeletionReceiptV4` (v2–v4 by prefix; the v5
/// label matches exactly and is checked first, as in zombie-core).
fn is_historical_label(label: &str) -> bool {
    label != "mktd02-v5"
        && ["mktd02-v4", "mktd02-v3", "mktd02-v2"]
            .iter()
            .any(|p| label.starts_with(p))
}

/// v2–v4 intake tolerance, unchanged from v0.7.0: decimal-string numerics become
/// JSON numbers (an unparseable string is left for zombie-core to refuse), and a
/// v2 receipt's `subnet_id` must be a valid principal.
fn apply_historical_tolerance(value: &mut Value, label: &str) -> Result<(), IntakeError> {
    let Some(object) = value.as_object_mut() else {
        return Ok(());
    };
    for key in ["timestamp", "deletion_seq", "nonce"] {
        if let Some(Value::String(s)) = object.get(key) {
            if let Ok(n) = s.trim().parse::<u64>() {
                object.insert(key.to_string(), json!(n));
            }
        }
    }
    if label.starts_with("mktd02-v2") {
        let subnet = object.get("subnet_id").and_then(Value::as_str);
        match subnet.map(Principal::from_text) {
            Some(Ok(_)) => {}
            Some(Err(e)) => {
                return Err(IntakeError::Rejected(format!(
                    "{ERR_INTAKE_V2_SUBNET_ID}: {e}"
                )))
            }
            None => {
                return Err(IntakeError::Rejected(format!(
                    "{ERR_INTAKE_V2_SUBNET_ID}: missing subnet_id"
                )))
            }
        }
    }
    Ok(())
}

/// The DaffyDefs `mktd_get_receipt` Candid response. An intake adapter only:
/// it is converted to the receipt wire by [`candid_response_to_wire`] and never
/// consumed by a check.
///
/// ```text
/// type MktdReceiptResponse = record {
///   protocol_version : text; receipt_id : text; canister_id : principal;
///   record_id : blob; pre_state_hash : text; post_state_hash : text;
///   tombstone_hash : text; deletion_event_hash : text;
///   certified_commitment : text; module_hash : text; timestamp : nat64;
///   deletion_seq : nat64; bls_certificate : opt blob; trust_root_key_id : text;
///   module_hash_certificate : opt blob;
/// };
/// ```
///
/// Decoded into this plain record rather than a zombie-core type because the
/// endpoint carries hashes as hex `text` (zombie-core's Candid type carries
/// `blob`) and because candid cannot decode serde-buffered (untagged/try_from)
/// types ("Not a valid visitor: ContentVisitor" with serde ≥ 1.0.220).
/// `certified_commitment` is optional so a v5 endpoint without it decodes; if a
/// v5 response carries it, zombie-core refuses the receipt by name.
#[derive(Debug, Clone, CandidType, Deserialize)]
pub struct MktdReceiptResponse {
    pub protocol_version: String,
    pub receipt_id: String,
    pub canister_id: Principal,
    pub record_id: Vec<u8>,
    pub pre_state_hash: String,
    pub post_state_hash: String,
    pub tombstone_hash: String,
    pub deletion_event_hash: String,
    #[serde(default)]
    pub certified_commitment: Option<String>,
    pub module_hash: String,
    pub timestamp: u64,
    pub deletion_seq: u64,
    pub bls_certificate: Option<Vec<u8>>,
    pub trust_root_key_id: String,
    #[serde(default)]
    pub module_hash_certificate: Option<Vec<u8>>,
}

/// Typed conversion of the Candid response into the receipt wire (JSON value).
/// Hex text passes through as hex, blobs become hex, numbers stay numbers; a v2
/// line carries its counter as `nonce`.
pub fn candid_response_to_wire(r: &MktdReceiptResponse) -> Value {
    let mut wire = Map::new();
    let mut put = |k: &str, v: Value| {
        wire.insert(k.to_string(), v);
    };
    put("protocol_version", json!(r.protocol_version));
    put("receipt_id", json!(r.receipt_id));
    put("canister_id", json!(r.canister_id.to_text()));
    put("record_id", json!(hex::encode(&r.record_id)));
    put("pre_state_hash", json!(r.pre_state_hash));
    put("post_state_hash", json!(r.post_state_hash));
    put("tombstone_hash", json!(r.tombstone_hash));
    put("deletion_event_hash", json!(r.deletion_event_hash));
    if let Some(c) = &r.certified_commitment {
        put("certified_commitment", json!(c));
    }
    put("module_hash", json!(r.module_hash));
    put("timestamp", json!(r.timestamp));
    let counter_key = if r.protocol_version.starts_with("mktd02-v2") {
        "nonce"
    } else {
        "deletion_seq"
    };
    put(counter_key, json!(r.deletion_seq));
    put(
        "bls_certificate",
        r.bls_certificate
            .as_ref()
            .map_or(Value::Null, |b| json!(hex::encode(b))),
    );
    put("trust_root_key_id", json!(r.trust_root_key_id));
    if !r.protocol_version.starts_with("mktd02-v2") && !r.protocol_version.starts_with("mktd02-v3")
    {
        put(
            "module_hash_certificate",
            r.module_hash_certificate
                .as_ref()
                .map_or(Value::Null, |b| json!(hex::encode(b))),
        );
    }
    Value::Object(wire)
}

/// Fetch a receipt from the canister by hex receipt id (`opt` response first,
/// then a non-optional decode for endpoint variation).
pub async fn fetch_receipt(
    agent: &Agent,
    canister_id: Principal,
    receipt_id_hex: &str,
) -> Result<AnyDeletionReceipt, IntakeError> {
    let arg = Encode!(&receipt_id_hex)
        .map_err(|e| IntakeError::Unavailable(format!("encode query args: {e}")))?;
    let response = agent
        .query(&canister_id, "mktd_get_receipt")
        .with_arg(arg)
        .call()
        .await
        .map_err(|e| IntakeError::Unavailable(format!("query mktd_get_receipt failed: {e}")))?;

    let wire = if let Ok(Some(r)) = Decode!(&response, Option<MktdReceiptResponse>) {
        r
    } else if let Ok(r) = Decode!(&response, MktdReceiptResponse) {
        r
    } else {
        return Err(IntakeError::Rejected(format!(
            "intake:candid-response-undecodable: canister {canister_id} mktd_get_receipt response does not match MktdReceiptResponse (or no receipt with that id)"
        )));
    };
    decode_receipt_json(candid_response_to_wire(&wire))
}

#[cfg(test)]
mod tests {
    use super::*;
    use zombie_core::receipt::ProtocolVersion;
    use zombie_core::DeletionReceiptV4;

    const V2_JSON: &str = r#"{
  "protocol_version": "mktd02-v2",
  "receipt_id": "1f213a0f2bf4992071a7f23e72d1942e564a4e871e3decce8ac8ee27d08f534b",
  "canister_id": "aaaaa-aa",
  "subnet_id": "2vxsx-fae",
  "pre_state_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "post_state_hash": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  "tombstone_hash": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
  "deletion_event_hash": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
  "certified_commitment": "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
  "module_hash": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
  "timestamp": "1000000",
  "nonce": "1",
  "bls_certificate": [1,2,3,4],
  "trust_root_key_id": "mainnet",
  "profile_canister": "aaaaa-aa"
}"#;

    fn v2_value() -> Value {
        serde_json::from_str(V2_JSON).unwrap()
    }

    fn v4(receipt: AnyDeletionReceipt) -> DeletionReceiptV4 {
        match receipt {
            AnyDeletionReceipt::V4(r) => r,
            other => panic!("expected a v2–v4 receipt, got {other:?}"),
        }
    }

    /// Hash fields survive a CBOR round-trip through zombie-core's frozen v4
    /// type and the verifier's CBOR intake.
    #[test]
    fn cbor_round_trip_through_intake() {
        let original = DeletionReceiptV4 {
            protocol_version: ProtocolVersion::V3.into(),
            receipt_id: [0x2A; 32],
            canister_id: Principal::from_text("aaaaa-aa").unwrap(),
            record_id: vec![0xAA, 0xBB],
            pre_state_hash: [0xAA; 32],
            post_state_hash: [0xBB; 32],
            tombstone_hash: [0xCC; 32],
            deletion_event_hash: [0xDD; 32],
            certified_commitment: [0xEE; 32],
            module_hash: [0xFF; 32],
            timestamp: 1_000_000,
            deletion_seq: 1,
            bls_certificate: None,
            trust_root_key_id: String::from("mainnet"),
            module_hash_certificate: None,
        };
        let mut buf = Vec::new();
        ciborium::into_writer(&original, &mut buf).expect("CBOR encode failed");
        assert_eq!(v4(decode_receipt_bytes(&buf).unwrap()), original);
    }

    #[test]
    fn historical_labels_accepted_and_unknown_label_refused_verbatim() {
        for label in ["mktd02-v2", "mktd02-v3", "mktd02-v4"] {
            assert!(is_historical_label(label));
        }
        let mut value = v2_value();
        value["protocol_version"] = json!("mktd02-vX");
        match decode_receipt_json(value) {
            Err(IntakeError::Rejected(e)) => {
                assert!(e.contains("unrecognised protocol_version"), "{e}")
            }
            other => panic!("expected rejection, got {other:?}"),
        }
    }

    /// v2 receipt_id golden vector — must remain stable for legacy receipts.
    #[test]
    fn golden_receipt_id_v2_matches_zombie_core() {
        let id = zombie_core::receipt::compute_receipt_id_v2(
            &Principal::from_text("aaaaa-aa").unwrap(),
            1,
        );
        assert_eq!(
            hex::encode(id),
            "1f213a0f2bf4992071a7f23e72d1942e564a4e871e3decce8ac8ee27d08f534b",
            "receipt_id derivation changed — breaks all existing receipts"
        );
    }

    #[test]
    fn file_receipt_v2_parses_integer_bls_array_and_decimal_strings() {
        let receipt = v4(decode_receipt_bytes(V2_JSON.as_bytes()).unwrap());
        assert_eq!(receipt.trust_root_key_id, "mainnet");
        assert_eq!(receipt.bls_certificate, Some(vec![1, 2, 3, 4]));
        assert_eq!(receipt.protocol_version, "mktd02-v2");
        assert_eq!((receipt.timestamp, receipt.deletion_seq), (1_000_000, 1));
        assert_eq!(receipt.record_id, Vec::<u8>::new());
    }

    /// The receipt's trust_root_key_id no longer selects a key, so a finalized
    /// receipt without it still decodes; the id is recorded and compared later.
    #[test]
    fn file_receipt_without_trust_root_key_id_decodes() {
        let mut value = v2_value();
        value.as_object_mut().unwrap().remove("trust_root_key_id");
        assert_eq!(
            v4(decode_receipt_json(value).unwrap()).trust_root_key_id,
            ""
        );
    }

    #[test]
    fn v2_subnet_id_is_still_validated() {
        let mut value = v2_value();
        value["subnet_id"] = json!("not a principal");
        match decode_receipt_json(value) {
            Err(IntakeError::Rejected(e)) => assert!(e.starts_with(ERR_INTAKE_V2_SUBNET_ID), "{e}"),
            other => panic!("expected rejection, got {other:?}"),
        }
        let mut value = v2_value();
        value.as_object_mut().unwrap().remove("subnet_id");
        assert!(matches!(
            decode_receipt_json(value),
            Err(IntakeError::Rejected(_))
        ));
    }

    #[test]
    fn file_receipt_v3_parses_record_id_deletion_seq_and_0x_hex() {
        let mut value = v2_value();
        let object = value.as_object_mut().unwrap();
        object.remove("subnet_id");
        object.remove("nonce");
        object.insert("protocol_version".into(), json!("mktd02-v3"));
        object.insert("record_id".into(), json!([1, 2, 3, 4]));
        object.insert("deletion_seq".into(), json!("7"));
        object.insert("bls_certificate".into(), json!("0x0a0b0c0d"));
        let receipt = v4(decode_receipt_json(value).unwrap());
        assert_eq!(receipt.protocol_version, "mktd02-v3");
        assert_eq!(receipt.deletion_seq, 7);
        assert_eq!(receipt.record_id, vec![1, 2, 3, 4]);
        assert_eq!(receipt.bls_certificate, Some(vec![0x0a, 0x0b, 0x0c, 0x0d]));
    }

    #[test]
    fn v5_json_is_strict_zombie_core_decode() {
        let mut value = v2_value();
        let object = value.as_object_mut().unwrap();
        object.remove("subnet_id");
        object.remove("nonce");
        object.remove("profile_canister");
        object.insert("protocol_version".into(), json!("mktd02-v5"));
        object.insert("record_id".into(), json!("0a0b"));
        object.insert("deletion_seq".into(), json!(7));
        object.insert("timestamp".into(), json!(1_000_000));
        // Carries the retired key: refused by name, verbatim.
        assert_eq!(
            decode_receipt_json(value.clone()),
            Err(IntakeError::Rejected(
                zombie_core::ERR_RETIRED_FIELD_CERTIFIED_COMMITMENT.to_string()
            ))
        );
        value
            .as_object_mut()
            .unwrap()
            .remove("certified_commitment");
        assert!(matches!(
            decode_receipt_json(value.clone()).unwrap(),
            AnyDeletionReceipt::V5(_)
        ));
        // Decimal strings are historical tolerance only: v5 refuses them.
        value["timestamp"] = json!("1000000");
        assert!(matches!(
            decode_receipt_json(value),
            Err(IntakeError::Rejected(_))
        ));
    }

    /// The DaffyDefs v4 endpoint shape (text certified_commitment, hex text
    /// hashes) decodes into the adapter and converts to the same receipt as the
    /// equivalent file.
    #[test]
    fn candid_adapter_converts_v4_endpoint_response() {
        #[derive(CandidType, serde::Serialize)]
        struct EndpointV4 {
            protocol_version: String,
            receipt_id: String,
            canister_id: Principal,
            record_id: Vec<u8>,
            pre_state_hash: String,
            post_state_hash: String,
            tombstone_hash: String,
            deletion_event_hash: String,
            certified_commitment: String,
            module_hash: String,
            timestamp: u64,
            deletion_seq: u64,
            bls_certificate: Option<Vec<u8>>,
            trust_root_key_id: String,
            module_hash_certificate: Option<Vec<u8>>,
        }
        let h = |c: char| c.to_string().repeat(64);
        let endpoint = EndpointV4 {
            protocol_version: "mktd02-v4".into(),
            receipt_id: h('1'),
            canister_id: Principal::from_text("aaaaa-aa").unwrap(),
            record_id: vec![0xAA, 0xBB],
            pre_state_hash: h('2'),
            post_state_hash: h('3'),
            tombstone_hash: h('4'),
            deletion_event_hash: h('5'),
            certified_commitment: h('6'),
            module_hash: h('7'),
            timestamp: 1_000_000,
            deletion_seq: 9,
            bls_certificate: Some(vec![1, 2]),
            trust_root_key_id: "mainnet".into(),
            module_hash_certificate: Some(vec![3, 4]),
        };
        let bytes = Encode!(&Some(endpoint)).unwrap();
        let decoded = Decode!(&bytes, Option<MktdReceiptResponse>)
            .unwrap()
            .unwrap();
        assert_eq!(
            decoded.certified_commitment.as_deref(),
            Some(h('6').as_str())
        );
        let receipt = v4(decode_receipt_json(candid_response_to_wire(&decoded)).unwrap());
        assert_eq!(receipt.certified_commitment, [0x66; 32]);
        assert_eq!(receipt.deletion_seq, 9);
        assert_eq!(receipt.module_hash_certificate, Some(vec![3, 4]));
        assert_eq!(receipt.record_id, vec![0xAA, 0xBB]);
    }
}
