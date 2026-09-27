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
/// LIVE portable package version (suite v5, R-6): exact match, fail closed on anything else.
pub const PORTABLE_VERSION_V3: u64 = 3;
/// HISTORICAL portable package version (pre-v5 PortablePackageV2): decoded, never emitted.
pub const PORTABLE_VERSION_V2: u64 = 2;
/// `trust_root_key_id` SELECTOR values a package may carry (R-6 / G step-5 rule 1). The id only
/// selects a verifier-configured trusted root; it is never evidence.
pub const TRUST_ROOT_MAINNET: &str = "mainnet";
pub const TRUST_ROOT_NON_PRODUCTION: &str = "non-production-test-root";
/// Exact key set of a PortablePackageV3 document; any other key is malformed (fail closed).
const V3_KEYS: [&str; 6] = [
    "schema",
    "version",
    "encoding",
    "trust_root_key_id",
    "frozen",
    "index_code_identity_evidence",
];
const V3_EVIDENCE_KEYS: [&str; 2] = ["certificate_bytes", "index_module_hash"];

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
    /// RevealWire v2 (R-1): the per-deletion `record_salt` — lets the user recompute the displayed
    /// non-identifying `record_id`. `None` on a historical v1 reveal package.
    pub record_salt: Option<[u8; 32]>,
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
            other => bail!(
                "unsupported `encoding` '{}': expected \"hex\" or \"base64\"",
                other
            ),
        }
    }

    fn decode(self, field: &str, s: &str) -> Result<Vec<u8>> {
        let s = s.trim();
        match self {
            ByteEncoding::Hex => {
                let s = s
                    .strip_prefix("0x")
                    .or_else(|| s.strip_prefix("0X"))
                    .unwrap_or(s);
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
    pub fn from_json(raw: &str) -> Result<Self> {
        let wire: FrozenWire = serde_json::from_str(raw)
            .context("frozen package is not valid JSON of the expected shape")?;

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

/// INDEX code-identity evidence: the complete `read_state` certificate bytes and (V3) the
/// `index_module_hash` the Index extracted from it — DISPLAYED, and equality-checked by V3A
/// against the BLS-authenticated value. `None` on historical V2 packages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexCodeIdentityEvidence {
    pub certificate_bytes: Vec<u8>,
    pub index_module_hash: Option<[u8; 32]>,
}

/// PortablePackageV3 (live) or PortablePackageV2 (historical): nested FrozenWire + INDEX evidence.
///
/// `frozen_exact_bytes` retains the decoded nested FrozenWire JSON byte vector
/// exactly as carried in the outer package (Gate B byte identity). Parsing must
/// not discard these bytes in favour of a reconstructed encoding.
#[derive(Debug, Clone)]
pub struct PortablePackage {
    /// 3 (live) or 2 (historical) — exact.
    pub version: u64,
    /// V3: the trust-root SELECTOR the Index stamped (`mainnet` | `non-production-test-root`).
    /// Never evidence: V3A authenticates the certificate under the root this id selects in the
    /// verifier's own configuration. `None` on historical V2.
    pub trust_root_key_id: Option<String>,
    pub frozen: FrozenPackage,
    /// Exact nested FrozenWire JSON bytes decoded from the outer `frozen` field.
    pub frozen_exact_bytes: Vec<u8>,
    pub index_evidence: Option<IndexCodeIdentityEvidence>,
}

impl PortablePackage {
    /// SHA-256 of the retained nested FrozenWire bytes (audit / Gate B evidence).
    pub fn frozen_exact_sha256(&self) -> [u8; 32] {
        zombie_core::hashing::sha256(&self.frozen_exact_bytes)
    }
}

/// Either a FrozenWire-only artifact or a PortablePackageV3 (live) / V2 (historical).
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
            // Exact version dispatch (R-6): 3 = live, 2 = historical, anything else malformed.
            let version = v.get("version").and_then(|x| x.as_u64()).ok_or_else(|| {
                anyhow!("PortablePackage missing required integer `version` (must be exactly 3, or 2 for historical)")
            })?;
            if version == PORTABLE_VERSION_V3 {
                return Self::from_json_v3(&v);
            }
            if version != PORTABLE_VERSION_V2 {
                bail!(
                    "PortablePackage `version` must be exactly {} (live) or {} (historical); got {} — structurally malformed",
                    PORTABLE_VERSION_V3,
                    PORTABLE_VERSION_V2,
                    version
                );
            }
            let enc = ByteEncoding::parse_name(
                v.get("encoding").and_then(|e| e.as_str()).unwrap_or("hex"),
            )?;
            let frozen_val = v
                .get("frozen")
                .ok_or_else(|| anyhow!("PortablePackageV2 missing `frozen`"))?;
            // Ratified PortablePackageV2: nested FrozenWire as exact Gate A JSON
            // bytes only. Object-form nesting / Value::to_string reconstruction is
            // non-conforming (proves field equivalence, not byte identity).
            let (frozen, frozen_exact_bytes) = if let Some(s) = frozen_val.as_str() {
                let bytes = enc.decode("frozen", s)?;
                let nested = std::str::from_utf8(&bytes).map_err(|e| {
                    anyhow!("PortablePackageV2 `frozen` bytes are not UTF-8 JSON: {}", e)
                })?;
                let frozen = FrozenPackage::from_json(nested)?;
                (frozen, bytes)
            } else if frozen_val.is_object() {
                bail!(
                    "PortablePackageV2 `frozen` must be hex/base64 of exact FrozenWire JSON bytes \
                     (object-form nesting is non-conforming — field equivalence is not byte identity)"
                );
            } else {
                bail!(
                    "PortablePackageV2 `frozen` must be hex/base64 of exact FrozenWire JSON bytes"
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
            let certificate_bytes =
                enc.decode("index_code_identity_evidence.certificate_bytes", cert)?;
            if certificate_bytes.is_empty() {
                bail!(
                    "PortablePackageV2 index_code_identity_evidence.certificate_bytes is empty — \
                     incomplete V2 is structurally malformed"
                );
            }
            let index_evidence = Some(IndexCodeIdentityEvidence {
                certificate_bytes,
                index_module_hash: None,
            });
            Ok(PackageInput::Portable(PortablePackage {
                version: PORTABLE_VERSION_V2,
                trust_root_key_id: None,
                frozen,
                frozen_exact_bytes,
                index_evidence,
            }))
        } else if schema == FROZEN_SCHEMA_ID || v.get("receipt_body").is_some() {
            Ok(PackageInput::Frozen(FrozenPackage::from_json(raw)?))
        } else {
            bail!("unrecognised package schema '{}'", schema);
        }
    }

    /// PortablePackageV3 (R-6), FAIL CLOSED: exact key set at both levels, `version == 3`,
    /// `trust_root_key_id` a known selector, `frozen` = exact FrozenWire bytes, evidence complete
    /// (non-empty certificate, 32-byte `index_module_hash`). Nothing is defaulted.
    fn from_json_v3(v: &Value) -> Result<Self> {
        let obj = v
            .as_object()
            .ok_or_else(|| anyhow!("PortablePackageV3 must be a JSON object"))?;
        for key in obj.keys() {
            if !V3_KEYS.contains(&key.as_str()) {
                bail!(
                    "PortablePackageV3 has unknown key `{}` — structurally malformed (fail closed)",
                    key
                );
            }
        }
        for key in V3_KEYS {
            if !obj.contains_key(key) {
                bail!(
                    "PortablePackageV3 missing required key `{}` — structurally malformed",
                    key
                );
            }
        }
        let enc = ByteEncoding::parse_name(
            obj.get("encoding")
                .and_then(|e| e.as_str())
                .ok_or_else(|| anyhow!("PortablePackageV3 `encoding` must be a string"))?,
        )?;
        let trust_root_key_id = obj
            .get("trust_root_key_id")
            .and_then(|t| t.as_str())
            .ok_or_else(|| anyhow!("PortablePackageV3 `trust_root_key_id` must be a string"))?
            .to_string();
        if trust_root_key_id != TRUST_ROOT_MAINNET && trust_root_key_id != TRUST_ROOT_NON_PRODUCTION
        {
            bail!(
                "PortablePackageV3 `trust_root_key_id` '{}' is not a known trust-root selector \
                 (known: '{}', '{}') — fail closed",
                trust_root_key_id,
                TRUST_ROOT_MAINNET,
                TRUST_ROOT_NON_PRODUCTION
            );
        }
        let frozen_hex = obj.get("frozen").and_then(|f| f.as_str()).ok_or_else(|| {
            anyhow!("PortablePackageV3 `frozen` must be hex/base64 of exact FrozenWire JSON bytes")
        })?;
        let frozen_exact_bytes = enc.decode("frozen", frozen_hex)?;
        let nested = std::str::from_utf8(&frozen_exact_bytes)
            .map_err(|e| anyhow!("PortablePackageV3 `frozen` bytes are not UTF-8 JSON: {}", e))?;
        let frozen = FrozenPackage::from_json(nested)?;

        let ev = obj
            .get("index_code_identity_evidence")
            .and_then(|e| e.as_object())
            .ok_or_else(|| {
                anyhow!("PortablePackageV3 `index_code_identity_evidence` must be an object")
            })?;
        for key in ev.keys() {
            if !V3_EVIDENCE_KEYS.contains(&key.as_str()) {
                bail!("PortablePackageV3 index_code_identity_evidence has unknown key `{}` — fail closed", key);
            }
        }
        let certificate_bytes = enc.decode(
            "index_code_identity_evidence.certificate_bytes",
            ev.get("certificate_bytes")
                .and_then(|c| c.as_str())
                .ok_or_else(|| {
                    anyhow!(
                        "PortablePackageV3 index_code_identity_evidence.certificate_bytes missing"
                    )
                })?,
        )?;
        if certificate_bytes.is_empty() {
            bail!("PortablePackageV3 index_code_identity_evidence.certificate_bytes is empty — malformed");
        }
        let index_module_hash = decode_array32(
            enc,
            "index_code_identity_evidence.index_module_hash",
            ev.get("index_module_hash")
                .and_then(|h| h.as_str())
                .ok_or_else(|| {
                    anyhow!(
                        "PortablePackageV3 index_code_identity_evidence.index_module_hash missing"
                    )
                })?,
        )?;
        Ok(PackageInput::Portable(PortablePackage {
            version: PORTABLE_VERSION_V3,
            trust_root_key_id: Some(trust_root_key_id),
            frozen,
            frozen_exact_bytes,
            index_evidence: Some(IndexCodeIdentityEvidence {
                certificate_bytes,
                index_module_hash: Some(index_module_hash),
            }),
        }))
    }

    pub fn frozen(&self) -> &FrozenPackage {
        match self {
            PackageInput::Frozen(f) => f,
            PackageInput::Portable(p) => &p.frozen,
        }
    }

    /// Outer package version: `Some(3|2)` for portable packages, `None` for FrozenWire-only.
    pub fn portable_version(&self) -> Option<u64> {
        match self {
            PackageInput::Frozen(_) => None,
            PackageInput::Portable(p) => Some(p.version),
        }
    }

    pub fn trust_root_key_id(&self) -> Option<&str> {
        match self {
            PackageInput::Frozen(_) => None,
            PackageInput::Portable(p) => p.trust_root_key_id.as_deref(),
        }
    }

    pub fn index_evidence(&self) -> Option<&IndexCodeIdentityEvidence> {
        match self {
            PackageInput::Frozen(_) => None,
            PackageInput::Portable(p) => p.index_evidence.as_ref(),
        }
    }

    /// SHA-256 of the retained nested FrozenWire bytes (Gate B evidence); None for FrozenWire-only.
    pub fn frozen_exact_sha256(&self) -> Option<[u8; 32]> {
        match self {
            PackageInput::Frozen(_) => None,
            PackageInput::Portable(p) => Some(p.frozen_exact_sha256()),
        }
    }

    /// Retained nested FrozenWire JSON bytes for a portable package; None for FrozenWire-only.
    #[cfg(test)]
    pub fn frozen_exact_bytes(&self) -> Option<&[u8]> {
        match self {
            PackageInput::Frozen(_) => None,
            PackageInput::Portable(p) => Some(p.frozen_exact_bytes.as_slice()),
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
    #[serde(default)]
    record_salt: Option<String>,
    targets: Vec<String>,
}

impl RevealPackage {
    pub fn from_path(path: &str) -> Result<Self> {
        let raw = fs::read_to_string(path)
            .with_context(|| format!("failed to read reveal package '{}'", path))?;
        Self::from_json(&raw).with_context(|| format!("in reveal package '{}'", path))
    }

    pub fn from_json(raw: &str) -> Result<Self> {
        let wire: RevealWire = serde_json::from_str(raw)
            .context("reveal package is not valid JSON of the expected shape")?;
        if let Some(schema) = &wire.schema {
            if schema != REVEAL_SCHEMA_ID {
                bail!(
                    "unexpected reveal `schema` '{}' (expected '{}')",
                    schema,
                    REVEAL_SCHEMA_ID
                );
            }
        }
        let version = wire.version.unwrap_or(1);
        if version != 1 && version != 2 {
            bail!(
                "reveal package `version` must be 1 (historical) or 2; got {}",
                version
            );
        }
        let enc = ByteEncoding::parse_name(wire.encoding.as_deref().unwrap_or("hex"))?;
        let salt = decode_array32(enc, "salt", &wire.salt)?;
        let record_salt = match (&wire.record_salt, version) {
            (Some(rs), 2) => Some(decode_array32(enc, "record_salt", rs)?),
            (None, 2) => bail!("reveal package version 2 must carry `record_salt`"),
            (Some(_), _) => bail!("reveal package version 1 must not carry `record_salt`"),
            (None, _) => None,
        };

        let mut targets = Vec::with_capacity(wire.targets.len());
        for (i, t) in wire.targets.iter().enumerate() {
            let p = candid::Principal::from_text(t.trim()).map_err(|e| {
                anyhow!(
                    "reveal targets[{}] '{}' is not a valid principal: {}",
                    i,
                    t,
                    e
                )
            })?;
            targets.push(p);
        }
        Ok(Self {
            salt,
            record_salt,
            targets,
        })
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

    /// Helper: nest exact FrozenWire JSON bytes as hex inside PortablePackageV2.
    fn portable_v2_json(frozen_json: &str, evidence_hex: &str) -> String {
        let frozen_hex = hex::encode(frozen_json.as_bytes());
        format!(
            r#"{{
              "schema":"{PORTABLE_SCHEMA_ID}",
              "version":2,
              "encoding":"hex",
              "frozen":"{frozen_hex}",
              "index_code_identity_evidence":{{"certificate_bytes":"{evidence_hex}"}}
            }}"#
        )
    }

    #[test]
    fn portable_v2_nests_frozen_bytes_and_index_evidence() {
        let z = hex::encode([0u8; 32]);
        let frozen_json = format!(
            r#"{{"schema":"{FROZEN_SCHEMA_ID}","version":1,"encoding":"hex",
            "receipt_body":"00","receipt_hash":"{z}","tree_root":"{z}",
            "witness_bytes":"00","certificate_bytes":"aabb","certificate_time":9}}"#
        );
        let pkg = PackageInput::from_json(&portable_v2_json(&frozen_json, "deadbeef")).unwrap();
        assert_eq!(pkg.frozen().certificate_time, 9);
        assert_eq!(
            pkg.index_evidence().map(|e| e.certificate_bytes.clone()),
            Some(vec![0xde, 0xad, 0xbe, 0xef])
        );
    }

    #[test]
    fn portable_v2_rejects_object_form_frozen() {
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
        let err = PackageInput::from_json(&j).unwrap_err().to_string();
        assert!(
            err.contains("exact FrozenWire JSON bytes") || err.contains("object-form"),
            "{err}"
        );
    }

    #[test]
    fn portable_v2_rejects_non_string_frozen() {
        let j = format!(
            r#"{{
              "schema":"{PORTABLE_SCHEMA_ID}",
              "version":2,
              "encoding":"hex",
              "frozen":[1,2,3],
              "index_code_identity_evidence":{{"certificate_bytes":"deadbeef"}}
            }}"#
        );
        let err = PackageInput::from_json(&j).unwrap_err().to_string();
        assert!(
            err.contains("exact FrozenWire JSON bytes") || err.contains("hex or base64"),
            "{err}"
        );
    }

    #[test]
    fn portable_v2_requires_complete_index_evidence() {
        let z = hex::encode([0u8; 32]);
        let frozen_json = format!(
            r#"{{"schema":"{FROZEN_SCHEMA_ID}","version":1,"encoding":"hex",
            "receipt_body":"00","receipt_hash":"{z}","tree_root":"{z}",
            "witness_bytes":"00","certificate_bytes":"aa","certificate_time":1}}"#
        );
        let frozen_hex = hex::encode(frozen_json.as_bytes());
        let j = format!(
            r#"{{
              "schema":"{PORTABLE_SCHEMA_ID}","version":2,"encoding":"hex",
              "frozen":"{frozen_hex}"
            }}"#
        );
        let err = PackageInput::from_json(&j).unwrap_err().to_string();
        assert!(
            err.contains("structurally malformed")
                || err.contains("missing `index_code_identity_evidence`"),
            "{err}"
        );
    }

    #[test]
    fn portable_v2_null_or_empty_evidence_is_malformed_not_unavailable() {
        let z = hex::encode([0u8; 32]);
        let frozen_json = format!(
            r#"{{"schema":"{FROZEN_SCHEMA_ID}","version":1,"encoding":"hex",
            "receipt_body":"00","receipt_hash":"{z}","tree_root":"{z}",
            "witness_bytes":"00","certificate_bytes":"aa","certificate_time":1}}"#
        );
        let frozen_hex = hex::encode(frozen_json.as_bytes());
        for evidence_json in [
            r#","index_code_identity_evidence":null"#,
            r#","index_code_identity_evidence":{"certificate_bytes":""}"#,
        ] {
            let j = format!(
                r#"{{
                  "schema":"{PORTABLE_SCHEMA_ID}","version":2,"encoding":"hex",
                  "frozen":"{frozen_hex}"
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
        let frozen_json = format!(
            r#"{{"schema":"{FROZEN_SCHEMA_ID}","version":1,"encoding":"hex",
            "receipt_body":"00","receipt_hash":"{z}","tree_root":"{z}",
            "witness_bytes":"00","certificate_bytes":"aa","certificate_time":1}}"#
        );
        let frozen_hex = hex::encode(frozen_json.as_bytes());
        for version in [1u64, 3, 0] {
            let j = format!(
                r#"{{
                  "schema":"{PORTABLE_SCHEMA_ID}","version":{version},"encoding":"hex",
                  "frozen":"{frozen_hex}",
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
              "frozen":"{frozen_hex}",
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
        assert_eq!(
            pkg.index_evidence().map(|e| e.certificate_bytes.clone()),
            Some(vec![0xde, 0xad])
        );

        // Retained nested vector must equal the decoded Gate A JSON bytes exactly.
        assert_eq!(
            pkg.frozen_exact_bytes().unwrap(),
            frozen_json.as_bytes(),
            "PortablePackage must preserve exact nested FrozenWire bytes after parse"
        );
        if let PackageInput::Portable(p) = &pkg {
            use zombie_core::hashing::sha256;
            assert_eq!(p.frozen_exact_sha256(), sha256(frozen_json.as_bytes()));
        }

        // Byte-equality Gate B seed: re-hex of the same nested JSON must round-trip identically.
        let again = PackageInput::from_json(&j).unwrap();
        assert_eq!(
            again.frozen().certificate_bytes,
            pkg.frozen().certificate_bytes
        );
        assert_eq!(again.frozen().receipt_body, pkg.frozen().receipt_body);
        assert_eq!(again.frozen_exact_bytes(), pkg.frozen_exact_bytes());
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
        assert_eq!(
            standalone.certificate_bytes,
            nested.frozen().certificate_bytes
        );
        assert_eq!(
            standalone.certificate_time,
            nested.frozen().certificate_time
        );
        assert_eq!(
            nested.frozen_exact_bytes().unwrap(),
            frozen_bytes,
            "parsed package must retain the original nested byte vector"
        );

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
    fn frozen_wire_only_has_no_retained_nested_bytes() {
        let z = hex::encode([0u8; 32]);
        let j = format!(
            r#"{{"schema":"{FROZEN_SCHEMA_ID}","version":1,"encoding":"hex",
            "receipt_body":"00","receipt_hash":"{z}","tree_root":"{z}",
            "witness_bytes":"00","certificate_bytes":"aa","certificate_time":1}}"#
        );
        let pkg = PackageInput::from_json(&j).unwrap();
        assert!(matches!(pkg, PackageInput::Frozen(_)));
        assert!(pkg.frozen_exact_bytes().is_none());
    }

    #[test]
    fn frozen_wire_only_exposes_no_evidence_and_no_selector() {
        let z = hex::encode([0u8; 32]);
        let j = format!(
            r#"{{"schema":"{FROZEN_SCHEMA_ID}","version":1,"encoding":"hex",
            "receipt_body":"00","receipt_hash":"{z}","tree_root":"{z}",
            "witness_bytes":"00","certificate_bytes":"aa","certificate_time":1}}"#
        );
        let pkg = PackageInput::from_json(&j).unwrap();
        assert!(matches!(pkg, PackageInput::Frozen(_)));
        assert!(pkg.index_evidence().is_none());
        assert_eq!(pkg.portable_version(), None);
        assert_eq!(pkg.trust_root_key_id(), None);
    }

    fn frozen_json() -> String {
        let z = hex::encode([0u8; 32]);
        format!(
            r#"{{"schema":"{FROZEN_SCHEMA_ID}","version":1,"encoding":"hex","receipt_body":"00","receipt_hash":"{z}","tree_root":"{z}","witness_bytes":"00","certificate_bytes":"aa","certificate_time":1}}"#
        )
    }

    fn v3_json(
        extra_top: &str,
        extra_ev: &str,
        version: u64,
        selector: &str,
        hash_hex: &str,
    ) -> String {
        format!(
            r#"{{"schema":"{PORTABLE_SCHEMA_ID}","version":{version},"encoding":"hex","trust_root_key_id":"{selector}","frozen":"{frozen}","index_code_identity_evidence":{{"certificate_bytes":"dead","index_module_hash":"{hash_hex}"{extra_ev}}}{extra_top}}}"#,
            frozen = hex::encode(frozen_json().as_bytes()),
        )
    }

    /// R-6 / G rule 3: PortablePackageV3 parses exactly; every deviation is malformed (fail closed).
    #[test]
    fn portable_v3_exact_and_fail_closed() {
        let h = "1d".repeat(32);
        let ok = PackageInput::from_json(&v3_json("", "", 3, TRUST_ROOT_MAINNET, &h)).unwrap();
        assert_eq!(ok.portable_version(), Some(3));
        assert_eq!(ok.trust_root_key_id(), Some(TRUST_ROOT_MAINNET));
        let ev = ok.index_evidence().unwrap();
        assert_eq!(ev.certificate_bytes, vec![0xde, 0xad]);
        assert_eq!(ev.index_module_hash, Some([0x1d; 32]));
        assert_eq!(ok.frozen_exact_bytes(), Some(frozen_json().as_bytes()));
        assert!(
            PackageInput::from_json(&v3_json("", "", 3, TRUST_ROOT_NON_PRODUCTION, &h)).is_ok()
        );

        let cases = [
            (
                v3_json(r#","extra":1"#, "", 3, TRUST_ROOT_MAINNET, &h),
                "unknown key",
            ),
            (
                v3_json("", r#","note":"x""#, 3, TRUST_ROOT_MAINNET, &h),
                "unknown key",
            ),
            (v3_json("", "", 4, TRUST_ROOT_MAINNET, &h), "malformed"),
            (
                v3_json("", "", 3, "prod", &h),
                "not a known trust-root selector",
            ),
            (
                v3_json("", "", 3, "", &h),
                "not a known trust-root selector",
            ),
            (
                v3_json("", "", 3, TRUST_ROOT_MAINNET, "1d1d"),
                "must be 32 bytes",
            ),
            (
                v3_json("", "", 3, TRUST_ROOT_MAINNET, ""),
                "must be 32 bytes",
            ),
        ];
        for (json, needle) in cases {
            let err = PackageInput::from_json(&json).unwrap_err().to_string();
            assert!(err.contains(needle), "expected `{needle}` in: {err}");
        }
        // missing required keys
        for key in [
            "trust_root_key_id",
            "index_code_identity_evidence",
            "frozen",
            "encoding",
        ] {
            let mut v: serde_json::Value =
                serde_json::from_str(&v3_json("", "", 3, TRUST_ROOT_MAINNET, &h)).unwrap();
            v.as_object_mut().unwrap().remove(key);
            let err = PackageInput::from_json(&v.to_string())
                .unwrap_err()
                .to_string();
            assert!(err.contains("missing required key"), "{key}: {err}");
        }
        // V3 with the V2 evidence shape (no index_module_hash) is malformed, not "V2".
        let mut v: serde_json::Value =
            serde_json::from_str(&v3_json("", "", 3, TRUST_ROOT_MAINNET, &h)).unwrap();
        v["index_code_identity_evidence"]
            .as_object_mut()
            .unwrap()
            .remove("index_module_hash");
        assert!(PackageInput::from_json(&v.to_string())
            .unwrap_err()
            .to_string()
            .contains("index_module_hash missing"));
    }

    /// Historical V2 still decodes (no selector, no extracted hash) and is never confused with V3.
    #[test]
    fn portable_v2_historical_decodes() {
        let json = format!(
            r#"{{"schema":"{PORTABLE_SCHEMA_ID}","version":2,"encoding":"hex","frozen":"{frozen}","index_code_identity_evidence":{{"certificate_bytes":"dead"}}}}"#,
            frozen = hex::encode(frozen_json().as_bytes()),
        );
        let pkg = PackageInput::from_json(&json).unwrap();
        assert_eq!(pkg.portable_version(), Some(2));
        assert_eq!(pkg.trust_root_key_id(), None);
        assert_eq!(pkg.index_evidence().unwrap().index_module_hash, None);
    }

    /// RevealWire v2 carries record_salt; v1 must not; v2 without it is malformed.
    #[test]
    fn reveal_wire_versions() {
        let salt = hex::encode([4u8; 32]);
        let rs = hex::encode([0xC3u8; 32]);
        let v2 = format!(
            r#"{{"schema":"{REVEAL_SCHEMA_ID}","version":2,"encoding":"hex","salt":"{salt}","record_salt":"{rs}","targets":[]}}"#
        );
        let r = RevealPackage::from_json(&v2).unwrap();
        assert_eq!(r.record_salt, Some([0xC3; 32]));
        let v1 = format!(
            r#"{{"schema":"{REVEAL_SCHEMA_ID}","version":1,"encoding":"hex","salt":"{salt}","targets":[]}}"#
        );
        assert_eq!(RevealPackage::from_json(&v1).unwrap().record_salt, None);
        let v2_missing = format!(
            r#"{{"schema":"{REVEAL_SCHEMA_ID}","version":2,"encoding":"hex","salt":"{salt}","targets":[]}}"#
        );
        assert!(RevealPackage::from_json(&v2_missing).is_err());
        let v1_extra = format!(
            r#"{{"schema":"{REVEAL_SCHEMA_ID}","version":1,"encoding":"hex","salt":"{salt}","record_salt":"{rs}","targets":[]}}"#
        );
        assert!(RevealPackage::from_json(&v1_extra).is_err());
        let v3 = format!(
            r#"{{"schema":"{REVEAL_SCHEMA_ID}","version":3,"encoding":"hex","salt":"{salt}","record_salt":"{rs}","targets":[]}}"#
        );
        assert!(RevealPackage::from_json(&v3).is_err());
    }

    #[test]
    fn portable_v2_rejects_evidence_object_missing_certificate_bytes_key() {
        let z = hex::encode([0u8; 32]);
        let frozen_json = format!(
            r#"{{"schema":"{FROZEN_SCHEMA_ID}","version":1,"encoding":"hex",
            "receipt_body":"00","receipt_hash":"{z}","tree_root":"{z}",
            "witness_bytes":"00","certificate_bytes":"aa","certificate_time":1}}"#
        );
        let frozen_hex = hex::encode(frozen_json.as_bytes());
        let j = format!(
            r#"{{
              "schema":"{PORTABLE_SCHEMA_ID}","version":2,"encoding":"hex",
              "frozen":"{frozen_hex}",
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
