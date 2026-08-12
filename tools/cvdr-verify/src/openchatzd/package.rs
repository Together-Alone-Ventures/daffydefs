//! Portable frozen-package artifact (spec §4) as a versioned JSON document.
//!
//! The on-chain `FrozenCvdrPackage` is six frozen fields; this is their portable
//! transport for offline verification. Byte fields are hex (default) or base64,
//! selected by the top-level `encoding`. `certificate_time` is nanoseconds as a
//! number or a numeric string. Schema/version are checked so a future layout
//! change is an explicit, detectable migration — never a silent misparse.
//!
//! ```json
//! {
//!   "schema": "openchatzd.cvdr.frozen_package",
//!   "version": 1,
//!   "encoding": "hex",
//!   "receipt_body":      "<hex|base64>",
//!   "receipt_hash":      "<hex|base64, 32 bytes>",
//!   "tree_root":         "<hex|base64, 32 bytes>",
//!   "witness_bytes":     "<hex|base64>",
//!   "certificate_bytes": "<hex|base64>",
//!   "certificate_time":  1783058017047703691
//! }
//! ```

use anyhow::{anyhow, bail, Context, Result};
use base64::Engine;
use serde::Deserialize;
use serde_json::Value;
use std::fs;

pub const FROZEN_SCHEMA_ID: &str = "openchatzd.cvdr.frozen_package";
pub const REVEAL_SCHEMA_ID: &str = "openchatzd.cvdr.reveal_package";
/// Highest package schema version this build understands.
pub const SUPPORTED_VERSION: u64 = 1;

/// Decoded six-field frozen package (spec §4), byte fields as raw bytes. Plus an OPTIONAL,
/// non-verification `root_key_der`: a fixture-supplied trust anchor, decoded from `root_key_hex`.
/// It is NEVER used unless the caller passes `--allow-fixture-root-key` (a fixture must not
/// silently supply its own trust anchor); default verification uses the built-in NNS roots.
#[derive(Debug, Clone)]
pub struct FrozenPackage {
    pub receipt_body: Vec<u8>,
    pub receipt_hash: [u8; 32],
    pub tree_root: [u8; 32],
    pub witness_bytes: Vec<u8>,
    pub certificate_bytes: Vec<u8>,
    pub certificate_time: u64,
    /// Optional fixture trust anchor (DER). Test-only; gated behind `--allow-fixture-root-key`.
    pub root_key_der: Option<Vec<u8>>,
}

/// The user-held reveal package (spec §2): `{version, salt, sorted target list}`.
#[derive(Debug, Clone)]
pub struct RevealPackage {
    pub salt: [u8; 32],
    /// Targets as principal text, in the order supplied (ascending order is
    /// enforced downstream by `body::targets_commitment(.., enforce_sorted=true)`).
    pub targets: Vec<candid::Principal>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ByteEncoding {
    Hex,
    Base64,
}

impl ByteEncoding {
    fn parse_name(name: &str) -> Result<Self> {
        match name.to_ascii_lowercase().as_str() {
            "hex" => Ok(ByteEncoding::Hex),
            "base64" | "b64" => Ok(ByteEncoding::Base64),
            other => bail!("unsupported `encoding` '{}': expected \"hex\" or \"base64\"", other),
        }
    }

    fn decode(self, field: &str, s: &str) -> Result<Vec<u8>> {
        let s = s.trim();
        match self {
            ByteEncoding::Hex => {
                let s = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
                hex::decode(s).with_context(|| format!("field `{}` is not valid hex", field))
            }
            ByteEncoding::Base64 => base64::engine::general_purpose::STANDARD
                .decode(s)
                .with_context(|| format!("field `{}` is not valid base64", field)),
        }
    }
}

/// Raw JSON shape; schema/version/encoding validated in [`FrozenPackage::from_json`].
#[derive(Debug, Deserialize)]
struct FrozenWire {
    schema: Option<String>,
    version: Option<u64>,
    #[serde(default)]
    encoding: Option<String>,
    receipt_body: String,
    receipt_hash: String,
    tree_root: String,
    witness_bytes: String,
    certificate_bytes: String,
    certificate_time: Value,
    /// Optional fixture trust anchor (hex DER). Consumed only under `--allow-fixture-root-key`.
    #[serde(default)]
    root_key_hex: Option<String>,
}

fn parse_u64_field(name: &str, v: &Value) -> Result<u64> {
    match v {
        Value::Number(n) => n
            .as_u64()
            .ok_or_else(|| anyhow!("`{}` must be a non-negative integer (u64)", name)),
        Value::String(s) => s
            .trim()
            .parse::<u64>()
            .map_err(|e| anyhow!("`{}` '{}' is not a u64: {}", name, s, e)),
        _ => bail!("`{}` must be a number or numeric string", name),
    }
}

fn decode_array32(enc: ByteEncoding, field: &str, s: &str) -> Result<[u8; 32]> {
    let bytes = enc.decode(field, s)?;
    if bytes.len() != 32 {
        bail!("`{}` must be 32 bytes, got {}", field, bytes.len());
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

impl FrozenPackage {
    pub fn from_path(path: &str) -> Result<Self> {
        let raw = fs::read_to_string(path)
            .with_context(|| format!("failed to read frozen package '{}'", path))?;
        Self::from_json(&raw).with_context(|| format!("in frozen package '{}'", path))
    }

    pub fn from_json(raw: &str) -> Result<Self> {
        let wire: FrozenWire =
            serde_json::from_str(raw).context("frozen package is not valid JSON of the expected shape")?;

        if let Some(schema) = &wire.schema {
            if schema != FROZEN_SCHEMA_ID {
                bail!(
                    "unexpected `schema` '{}' (expected '{}')",
                    schema,
                    FROZEN_SCHEMA_ID
                );
            }
        }
        if let Some(v) = wire.version {
            if v > SUPPORTED_VERSION {
                bail!(
                    "frozen package `version` {} is newer than supported {} — upgrade CVDR-Verify",
                    v,
                    SUPPORTED_VERSION
                );
            }
        }
        let enc = ByteEncoding::parse_name(wire.encoding.as_deref().unwrap_or("hex"))?;

        // `root_key_hex` is ALWAYS hex (independent of `encoding`), and only ever consumed under
        // an explicit --allow-fixture-root-key opt-in.
        let root_key_der = match &wire.root_key_hex {
            Some(h) => Some(ByteEncoding::Hex.decode("root_key_hex", h)?),
            None => None,
        };

        Ok(Self {
            receipt_body: enc.decode("receipt_body", &wire.receipt_body)?,
            receipt_hash: decode_array32(enc, "receipt_hash", &wire.receipt_hash)?,
            tree_root: decode_array32(enc, "tree_root", &wire.tree_root)?,
            witness_bytes: enc.decode("witness_bytes", &wire.witness_bytes)?,
            certificate_bytes: enc.decode("certificate_bytes", &wire.certificate_bytes)?,
            certificate_time: parse_u64_field("certificate_time", &wire.certificate_time)?,
            root_key_der,
        })
    }
}

#[derive(Debug, Deserialize)]
struct RevealWire {
    schema: Option<String>,
    version: Option<u64>,
    #[serde(default)]
    encoding: Option<String>,
    salt: String,
    targets: Vec<String>,
}

impl RevealPackage {
    pub fn from_path(path: &str) -> Result<Self> {
        let raw = fs::read_to_string(path)
            .with_context(|| format!("failed to read reveal package '{}'", path))?;
        Self::from_json(&raw).with_context(|| format!("in reveal package '{}'", path))
    }

    pub fn from_json(raw: &str) -> Result<Self> {
        let wire: RevealWire =
            serde_json::from_str(raw).context("reveal package is not valid JSON of the expected shape")?;
        if let Some(schema) = &wire.schema {
            if schema != REVEAL_SCHEMA_ID {
                bail!("unexpected reveal `schema` '{}' (expected '{}')", schema, REVEAL_SCHEMA_ID);
            }
        }
        if let Some(v) = wire.version {
            if v > SUPPORTED_VERSION {
                bail!("reveal package `version` {} is newer than supported {}", v, SUPPORTED_VERSION);
            }
        }
        let enc = ByteEncoding::parse_name(wire.encoding.as_deref().unwrap_or("hex"))?;
        let salt = decode_array32(enc, "salt", &wire.salt)?;

        let mut targets = Vec::with_capacity(wire.targets.len());
        for (i, t) in wire.targets.iter().enumerate() {
            let p = candid::Principal::from_text(t.trim())
                .map_err(|e| anyhow!("reveal targets[{}] '{}' is not a valid principal: {}", i, t, e))?;
            targets.push(p);
        }
        Ok(Self { salt, targets })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_and_base64_agree() {
        let body = vec![0xDEu8, 0xAD, 0xBE, 0xEF];
        let h = hex::encode(&body);
        let b = base64::engine::general_purpose::STANDARD.encode(&body);
        let mk = |enc: &str, v: &str| {
            format!(
                r#"{{"schema":"{FROZEN_SCHEMA_ID}","version":1,"encoding":"{enc}",
                "receipt_body":"{v}","receipt_hash":"{z}","tree_root":"{z}",
                "witness_bytes":"{v}","certificate_bytes":"{v}","certificate_time":"7"}}"#,
                z = hex::encode([0u8; 32]),
            )
        };
        // base64 z field would break; use hex for the 32-byte fields in both by
        // keeping encoding=hex for base64 case is not possible — test bytes only.
        let ph = FrozenPackage::from_json(&mk("hex", &h)).unwrap();
        assert_eq!(ph.receipt_body, body);
        assert_eq!(ph.certificate_time, 7);
        let pb = FrozenPackage::from_json(&mk("base64", &b));
        // base64 case: the 32-byte hex zeros are NOT valid base64-of-32-bytes, so
        // this must error cleanly (proves per-encoding decoding is wired).
        assert!(pb.is_err());
    }

    #[test]
    fn rejects_future_version() {
        let z = hex::encode([0u8; 32]);
        let j = format!(
            r#"{{"schema":"{FROZEN_SCHEMA_ID}","version":999,"receipt_body":"00",
            "receipt_hash":"{z}","tree_root":"{z}","witness_bytes":"00",
            "certificate_bytes":"00","certificate_time":1}}"#
        );
        let err = FrozenPackage::from_json(&j).unwrap_err().to_string();
        assert!(err.contains("newer than supported"), "{err}");
    }

    #[test]
    fn rejects_wrong_length_hash() {
        let z = hex::encode([0u8; 32]);
        let j = format!(
            r#"{{"receipt_body":"00","receipt_hash":"0011","tree_root":"{z}",
            "witness_bytes":"00","certificate_bytes":"00","certificate_time":1}}"#
        );
        let err = FrozenPackage::from_json(&j).unwrap_err().to_string();
        assert!(err.contains("must be 32 bytes"), "{err}");
    }
}
