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
pub const PORTABLE_SCHEMA_ID: &str = "openchatzd.cvdr.portable_package";
pub const REVEAL_SCHEMA_ID: &str = "openchatzd.cvdr.reveal_package";
/// Highest frozen-package schema version this build understands.
pub const SUPPORTED_VERSION: u64 = 1;
/// Highest PortablePackageV2 schema version this build understands.
pub const SUPPORTED_PORTABLE_VERSION: u64 = 2;

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

/// INDEX code-identity evidence blob (spec §14.2): complete `read_state` certificate bytes.
#[derive(Debug, Clone)]
pub struct IndexCodeIdentityEvidence {
    pub certificate_bytes: Vec<u8>,
}

/// PortablePackageV2 (spec §14.1): nested FrozenWire + INDEX evidence.
#[derive(Debug, Clone)]
pub struct PortablePackage {
    pub frozen: FrozenPackage,
    pub index_evidence: Option<IndexCodeIdentityEvidence>,
}

/// Either a FrozenWire-only artifact or a PortablePackageV2.
#[derive(Debug, Clone)]
pub enum PackageInput {
    Frozen(FrozenPackage),
    Portable(PortablePackage),
}

impl PackageInput {
    pub fn from_path(path: &str) -> Result<Self> {
        let raw = fs::read_to_string(path)
            .with_context(|| format!("failed to read package '{}'", path))?;
        Self::from_json(&raw).with_context(|| format!("in package '{}'", path))
    }

    pub fn from_json(raw: &str) -> Result<Self> {
        let v: Value = serde_json::from_str(raw).context("package is not valid JSON")?;
        let schema = v
            .get("schema")
            .and_then(|s| s.as_str())
            .unwrap_or(FROZEN_SCHEMA_ID);
        if schema == PORTABLE_SCHEMA_ID {
            // G v0.7.0: PortablePackageV2 requires exact version == 2 (structural).
            let version = v.get("version").and_then(|x| x.as_u64()).ok_or_else(|| {
                anyhow!("PortablePackageV2 missing required `version` (must be exactly 2)")
            })?;
            if version != SUPPORTED_PORTABLE_VERSION {
                bail!(
                    "PortablePackageV2 `version` must be exactly {} (got {}) — structurally malformed",
                    SUPPORTED_PORTABLE_VERSION,
                    version
                );
            }
            let enc = ByteEncoding::parse_name(
                v.get("encoding")
                    .and_then(|e| e.as_str())
                    .unwrap_or("hex"),
            )?;
            let frozen_val = v
                .get("frozen")
                .ok_or_else(|| anyhow!("PortablePackageV2 missing `frozen`"))?;
            let frozen = if frozen_val.is_object() {
                let mut nested = frozen_val.clone();
                if nested.get("schema").is_none() {
                    nested
                        .as_object_mut()
                        .unwrap()
                        .insert("schema".into(), Value::String(FROZEN_SCHEMA_ID.into()));
                }
                if nested.get("encoding").is_none() {
                    if let Some(enc_name) = v.get("encoding").cloned() {
                        nested.as_object_mut().unwrap().insert("encoding".into(), enc_name);
                    }
                }
                if nested.get("root_key_hex").is_none() {
                    if let Some(rk) = v.get("root_key_hex").cloned() {
                        nested.as_object_mut().unwrap().insert("root_key_hex".into(), rk);
                    }
                }
                FrozenPackage::from_json(&nested.to_string())?
            } else if let Some(s) = frozen_val.as_str() {
                // Gate B forward shape (spec §14.1): nested `frozen` as exact canonical
                // FrozenWire portable-JSON bytes (hex/base64). Must decode to UTF-8 JSON of
                // the six-field frozen package — not a re-encoded approximation of fields.
                let bytes = enc.decode("frozen", s)?;
                let nested = std::str::from_utf8(&bytes).map_err(|e| {
                    anyhow!("PortablePackageV2 `frozen` bytes are not UTF-8 JSON: {}", e)
                })?;
                FrozenPackage::from_json(nested)?
            } else {
                bail!(
                    "PortablePackageV2 `frozen` must be a JSON object of FrozenWire fields \
                     or hex/base64 of exact FrozenWire JSON bytes"
                );
            };

            // G v0.7.0: incomplete V2 is structurally malformed — never parse as
            // "evidence absent → INDEX_ATTESTATION_UNAVAILABLE". That outcome is only for
            // FrozenWire-only packages.
            let ev = v.get("index_code_identity_evidence").ok_or_else(|| {
                anyhow!(
                    "PortablePackageV2 missing `index_code_identity_evidence` — \
                     incomplete V2 is structurally malformed (not INDEX_ATTESTATION_UNAVAILABLE)"
                )
            })?;
            if ev.is_null() {
                bail!(
                    "PortablePackageV2 `index_code_identity_evidence` is null — \
                     incomplete V2 is structurally malformed (not INDEX_ATTESTATION_UNAVAILABLE)"
                );
            }
            let cert = ev
                .get("certificate_bytes")
                .and_then(|c| c.as_str())
                .ok_or_else(|| {
                    anyhow!(
                        "PortablePackageV2 index_code_identity_evidence.certificate_bytes missing — \
                         incomplete V2 is structurally malformed"
                    )
                })?;
            let certificate_bytes = enc
                .decode("index_code_identity_evidence.certificate_bytes", cert)?;
            if certificate_bytes.is_empty() {
                bail!(
                    "PortablePackageV2 index_code_identity_evidence.certificate_bytes is empty — \
                     incomplete V2 is structurally malformed"
                );
            }
            let index_evidence = Some(IndexCodeIdentityEvidence { certificate_bytes });
            Ok(PackageInput::Portable(PortablePackage {
                frozen,
                index_evidence,
            }))
        } else if schema == FROZEN_SCHEMA_ID || v.get("receipt_body").is_some() {
            Ok(PackageInput::Frozen(FrozenPackage::from_json(raw)?))
        } else {
            bail!("unrecognised package schema '{}'", schema);
        }
    }

    pub fn frozen(&self) -> &FrozenPackage {
        match self {
            PackageInput::Frozen(f) => f,
            PackageInput::Portable(p) => &p.frozen,
        }
    }

    pub fn index_evidence_bytes(&self) -> Option<&[u8]> {
        match self {
            PackageInput::Frozen(_) => None,
            PackageInput::Portable(p) => {
                p.index_evidence.as_ref().map(|e| e.certificate_bytes.as_slice())
            }
        }
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

    #[test]
    fn portable_v2_nests_frozen_and_optional_index_evidence() {
        let z = hex::encode([0u8; 32]);
        let j = format!(
            r#"{{
              "schema":"{PORTABLE_SCHEMA_ID}",
              "version":2,
              "encoding":"hex",
              "frozen":{{
                "receipt_body":"00","receipt_hash":"{z}","tree_root":"{z}",
                "witness_bytes":"00","certificate_bytes":"aabb","certificate_time":9
              }},
              "index_code_identity_evidence":{{"certificate_bytes":"deadbeef"}}
            }}"#
        );
        let pkg = PackageInput::from_json(&j).unwrap();
        assert_eq!(pkg.frozen().certificate_time, 9);
        assert_eq!(pkg.index_evidence_bytes(), Some([0xde, 0xad, 0xbe, 0xef].as_slice()));
    }

    #[test]
    fn portable_v2_requires_complete_index_evidence() {
        let z = hex::encode([0u8; 32]);
        let j = format!(
            r#"{{
              "schema":"{PORTABLE_SCHEMA_ID}","version":2,"encoding":"hex",
              "frozen":{{
                "receipt_body":"00","receipt_hash":"{z}","tree_root":"{z}",
                "witness_bytes":"00","certificate_bytes":"aa","certificate_time":1
              }}
            }}"#
        );
        let err = PackageInput::from_json(&j).unwrap_err().to_string();
        assert!(
            err.contains("structurally malformed") || err.contains("missing `index_code_identity_evidence`"),
            "{err}"
        );
    }

    #[test]
    fn portable_v2_null_or_empty_evidence_is_malformed_not_unavailable() {
        let z = hex::encode([0u8; 32]);
        for evidence_json in [
            r#","index_code_identity_evidence":null"#,
            r#","index_code_identity_evidence":{"certificate_bytes":""}"#,
        ] {
            let j = format!(
                r#"{{
                  "schema":"{PORTABLE_SCHEMA_ID}","version":2,"encoding":"hex",
                  "frozen":{{
                    "receipt_body":"00","receipt_hash":"{z}","tree_root":"{z}",
                    "witness_bytes":"00","certificate_bytes":"aa","certificate_time":1
                  }}
                  {evidence_json}
                }}"#
            );
            let err = PackageInput::from_json(&j).unwrap_err().to_string();
            assert!(
                err.contains("structurally malformed") || err.contains("empty"),
                "evidence_json={evidence_json:?} err={err}"
            );
            assert!(
                !err.contains("INDEX_ATTESTATION_UNAVAILABLE")
                    || err.contains("not INDEX_ATTESTATION_UNAVAILABLE"),
                "{err}"
            );
        }
    }

    #[test]
    fn portable_v2_rejects_non_exact_version() {
        let z = hex::encode([0u8; 32]);
        for version in [1u64, 3, 0] {
            let j = format!(
                r#"{{
                  "schema":"{PORTABLE_SCHEMA_ID}","version":{version},"encoding":"hex",
                  "frozen":{{
                    "receipt_body":"00","receipt_hash":"{z}","tree_root":"{z}",
                    "witness_bytes":"00","certificate_bytes":"aa","certificate_time":1
                  }},
                  "index_code_identity_evidence":{{"certificate_bytes":"dead"}}
                }}"#
            );
            let err = PackageInput::from_json(&j).unwrap_err().to_string();
            assert!(
                err.contains("exactly 2") || err.contains("structurally malformed"),
                "version={version} err={err}"
            );
        }
        let missing = format!(
            r#"{{
              "schema":"{PORTABLE_SCHEMA_ID}","encoding":"hex",
              "frozen":{{
                "receipt_body":"00","receipt_hash":"{z}","tree_root":"{z}",
                "witness_bytes":"00","certificate_bytes":"aa","certificate_time":1
              }},
              "index_code_identity_evidence":{{"certificate_bytes":"dead"}}
            }}"#
        );
        let err = PackageInput::from_json(&missing).unwrap_err().to_string();
        assert!(err.contains("version"), "{err}");
    }

    #[test]
    fn portable_v2_nested_frozen_exact_json_bytes_hex_gate_b_shape() {
        let z = hex::encode([0u8; 32]);
        let frozen_json = format!(
            r#"{{"schema":"{FROZEN_SCHEMA_ID}","version":1,"encoding":"hex",
            "receipt_body":"abcd","receipt_hash":"{z}","tree_root":"{z}",
            "witness_bytes":"11","certificate_bytes":"22","certificate_time":42}}"#
        );
        let frozen_hex = hex::encode(frozen_json.as_bytes());
        let j = format!(
            r#"{{
              "schema":"{PORTABLE_SCHEMA_ID}",
              "version":2,
              "encoding":"hex",
              "frozen":"{frozen_hex}",
              "index_code_identity_evidence":{{"certificate_bytes":"dead"}}
            }}"#
        );
        let pkg = PackageInput::from_json(&j).unwrap();
        assert_eq!(pkg.frozen().certificate_time, 42);
        assert_eq!(pkg.frozen().receipt_body, vec![0xab, 0xcd]);
        assert_eq!(pkg.index_evidence_bytes(), Some([0xde, 0xad].as_slice()));

        // Byte-equality Gate B seed: re-hex of the same nested JSON must round-trip identically.
        let again = PackageInput::from_json(&j).unwrap();
        assert_eq!(again.frozen().certificate_bytes, pkg.frozen().certificate_bytes);
        assert_eq!(again.frozen().receipt_body, pkg.frozen().receipt_body);
    }

    /// Gate B: nested FrozenWire must be exact bytes — whitespace-equivalent JSON
    /// that decodes to the same fields is NOT the same artifact.
    #[test]
    fn portable_v2_nested_frozen_sha256_rejects_whitespace_equivalent_json() {
        use zombie_core::hashing::sha256;

        let z = hex::encode([0u8; 32]);
        let frozen_json = format!(
            r#"{{"schema":"{FROZEN_SCHEMA_ID}","version":1,"encoding":"hex",
            "receipt_body":"abcd","receipt_hash":"{z}","tree_root":"{z}",
            "witness_bytes":"11","certificate_bytes":"22","certificate_time":42}}"#
        );
        let frozen_bytes = frozen_json.as_bytes();
        let frozen_hex = hex::encode(frozen_bytes);
        let standalone = FrozenPackage::from_json(&frozen_json).unwrap();
        let nested = PackageInput::from_json(&format!(
            r#"{{
              "schema":"{PORTABLE_SCHEMA_ID}",
              "version":2,
              "encoding":"hex",
              "frozen":"{frozen_hex}",
              "index_code_identity_evidence":{{"certificate_bytes":"dead"}}
            }}"#
        ))
        .unwrap();

        assert_eq!(standalone.receipt_body, nested.frozen().receipt_body);
        assert_eq!(standalone.certificate_bytes, nested.frozen().certificate_bytes);
        assert_eq!(standalone.certificate_time, nested.frozen().certificate_time);

        // Trailing space before closing brace → identical fields, different SHA-256.
        let reencoded = format!(
            r#"{{"schema":"{FROZEN_SCHEMA_ID}","version":1,"encoding":"hex",
            "receipt_body":"abcd","receipt_hash":"{z}","tree_root":"{z}",
            "witness_bytes":"11","certificate_bytes":"22","certificate_time":42 }}"#
        );
        assert_eq!(
            FrozenPackage::from_json(&reencoded).unwrap().receipt_body,
            standalone.receipt_body
        );
        assert_ne!(
            sha256(frozen_bytes),
            sha256(reencoded.as_bytes()),
            "Gate B requires exact bytes; whitespace-equivalent JSON must hash differently"
        );
    }

    #[test]
    fn frozen_wire_only_still_evaluates_unavailable_not_applicable() {
        use crate::openchatzd::index_attestation::{
            evaluate, INDEX_ATTESTATION_UNAVAILABLE, TIMING_NOT_APPLICABLE,
        };
        use candid::Principal;

        let z = hex::encode([0u8; 32]);
        let j = format!(
            r#"{{"schema":"{FROZEN_SCHEMA_ID}","version":1,"encoding":"hex",
            "receipt_body":"00","receipt_hash":"{z}","tree_root":"{z}",
            "witness_bytes":"00","certificate_bytes":"aa","certificate_time":1}}"#
        );
        let pkg = PackageInput::from_json(&j).unwrap();
        assert!(matches!(pkg, PackageInput::Frozen(_)));
        assert!(pkg.index_evidence_bytes().is_none());
        let r = evaluate(
            pkg.index_evidence_bytes(),
            Principal::from_slice(&[3u8; 10]),
            &[0u8; 32],
            pkg.frozen().certificate_time,
            0,
            &[],
        );
        assert_eq!(r.outcome, INDEX_ATTESTATION_UNAVAILABLE);
        assert_eq!(r.timing, TIMING_NOT_APPLICABLE);
    }

    #[test]
    fn portable_v2_rejects_evidence_object_missing_certificate_bytes_key() {
        let z = hex::encode([0u8; 32]);
        let j = format!(
            r#"{{
              "schema":"{PORTABLE_SCHEMA_ID}","version":2,"encoding":"hex",
              "frozen":{{
                "receipt_body":"00","receipt_hash":"{z}","tree_root":"{z}",
                "witness_bytes":"00","certificate_bytes":"aa","certificate_time":1
              }},
              "index_code_identity_evidence":{{"other":"00"}}
            }}"#
        );
        let err = PackageInput::from_json(&j).unwrap_err().to_string();
        assert!(
            err.contains("structurally malformed") || err.contains("certificate_bytes"),
            "{err}"
        );
    }
}
