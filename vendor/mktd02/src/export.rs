//! # Receipt Export
//!
//! - `to_cbor_bytes()` -- always available; deterministic CBOR encoding
//! - `to_json()` -- behind `#[cfg(feature = "json")]`
//! - `webhook_push()` -- behind `#[cfg(feature = "json")]`; template only

use zombie_core::DeletionReceipt;

/// Serialise a receipt to deterministic CBOR bytes.
pub fn to_cbor_bytes(receipt: &DeletionReceipt) -> Vec<u8> {
    let mut buf = Vec::new();
    ciborium::into_writer(receipt, &mut buf).expect("MKTd02: CBOR encoding of receipt failed");
    buf
}

/// Serialise a receipt to JSON. Requires the `json` feature.
#[cfg(feature = "json")]
pub fn to_json(receipt: &DeletionReceipt) -> String {
    serde_json::to_string_pretty(receipt).expect("MKTd02: JSON encoding of receipt failed")
}

/// Template for pushing a receipt to an external webhook via HTTP outcall.
/// Requires the `json` feature. This is a starting point; enterprises
/// should customise the payload format for their SIEM.
#[cfg(feature = "json")]
pub fn webhook_push(_receipt: &DeletionReceipt, _url: &str) -> Result<(), String> {
    // Template: implement via ic_cdk::api::management_canister::http_request
    Err("webhook_push is a template; implement HTTP outcall for your use case".into())
}
