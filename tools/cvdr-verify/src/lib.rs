//! MKTd02 receipt verification (library half of the `mktd02-verify` binary).
//!
//! Verification produces structured facts ([`report`]); presentation lives in
//! the provisional [`render`] module. The OpenChatZD package path stays in the
//! binary crate and reuses [`v2_certificate`].

#[cfg(feature = "live")]
pub mod diagnostics;
pub mod intake;
pub mod render;
pub mod report;
pub mod trust_root;
pub mod v1_transition;
pub mod v2_certificate;
pub mod v3_module;
#[cfg(feature = "live")]
pub mod v4_tombstone;
pub mod verify;

/// Verify a receipt supplied by browser code without performing any network I/O.
///
/// The API intentionally fixes the trust root to the built-in mainnet root and
/// leaves V3B unevaluated, matching the native `--json` path when no
/// `--wasm-hash` provenance is supplied. `source` is optional for byte callers
/// that need their facts to retain a file-origin label; browser callers can omit
/// it and receive `wasm:memory`.
#[cfg(feature = "wasm")]
#[wasm_bindgen::prelude::wasm_bindgen]
pub fn verify_cvdr(
    receipt_bytes: &[u8],
    source: Option<String>,
) -> Result<String, wasm_bindgen::JsValue> {
    let receipt = intake::decode_receipt_bytes(receipt_bytes)
        .map_err(|e| wasm_bindgen::JsValue::from_str(&e.to_string()))?;
    let trust_root = trust_root::TrustRoot::built_in("mainnet")
        .map_err(|e| wasm_bindgen::JsValue::from_str(&e.to_string()))?;
    let facts = verify::verify_receipt(
        &receipt,
        source.unwrap_or_else(|| "wasm:memory".to_string()),
        &verify::VerifyOptions {
            trust_root,
            published_module_hash: None,
        },
    );
    Ok(render::render_json(&facts))
}
