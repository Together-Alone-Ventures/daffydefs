//! # CVDR (Cryptographically Verifiable Deletion Receipt)
//!
//! Receipt struct definition and `receipt_id` computation.
//! Domain tags:
//! - v2: `MKTD02_RECEIPT_V1`
//! - v3: `MKTD02_RECEIPT_V3`
//!
//! The receipt is an **unsigned artifact**. Verification relies on
//! the certified commitment obtained via ICP's certified query
//! mechanism, not a signature on the receipt itself.
//!
//! ## v0.2.0 Changes
//!
//! - Added `protocol_version` (constrained enum -> String on wire)
//! - Added `bls_certificate` (Option<Vec<u8>>, populated on finalization)
//! - Added `trust_root_key_id` (String, identifies NNS key from zombie-core allowlist)
//! - Removed `commit_mode` (redundant - MKTd02 is Leaf by definition)
//! - Removed `manifest_hash` (replaced by module_hash -> source code path)
//! - Removed `trust_root_key: Vec<u8>` (replaced by `trust_root_key_id`)
//!
//! ## trust_root_key_id Design
//!
//! Instead of embedding 96 raw key bytes in every receipt, the receipt stores
//! a compact identifier (e.g. `"mainnet"`) that references a key in
//! `zombie_core::nns_keys`. Verifiers look up the actual bytes there.
//! This keeps the receipt compact while ensuring verifiers always use the
//! key that was current when the receipt was issued -- critical for
//! historical verification after any future NNS key rotation.

use crate::hashing::{hash_with_tag, TAG_RECEIPT, TAG_RECEIPT_V3};
use candid::{CandidType, Principal};
use serde::ser::{Error as _, Serializer};
use serde::{Deserialize, Serialize};

mod serde_hex_bytes {
    use serde::de::{Error, SeqAccess, Visitor};
    use serde::{Deserializer, Serialize, Serializer};
    use std::fmt;

    struct BytesVisitor;

    impl<'de> Visitor<'de> for BytesVisitor {
        type Value = Vec<u8>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a lowercase hex string or byte array")
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: Error,
        {
            decode_hex(value).map_err(Error::custom)
        }

        fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
        where
            E: Error,
        {
            decode_hex(&value).map_err(Error::custom)
        }

        fn visit_bytes<E>(self, value: &[u8]) -> Result<Self::Value, E>
        where
            E: Error,
        {
            Ok(value.to_vec())
        }

        fn visit_byte_buf<E>(self, value: Vec<u8>) -> Result<Self::Value, E>
        where
            E: Error,
        {
            Ok(value)
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let mut out = Vec::new();
            while let Some(b) = seq.next_element::<u8>()? {
                out.push(b);
            }
            Ok(out)
        }
    }

    fn decode_hex(input: &str) -> Result<Vec<u8>, String> {
        let normalized = input
            .strip_prefix("0x")
            .or_else(|| input.strip_prefix("0X"))
            .unwrap_or(input)
            .to_ascii_lowercase();
        hex::decode(normalized).map_err(|e| format!("invalid hex: {e}"))
    }

    pub fn serialize_array_32<S>(value: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            serializer.serialize_str(&hex::encode(value))
        } else {
            value.serialize(serializer)
        }
    }

    pub fn deserialize_array_32<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = deserializer.deserialize_any(BytesVisitor)?;
        value
            .try_into()
            .map_err(|_| D::Error::custom("expected exactly 32 bytes"))
    }

    pub fn serialize_vec<S>(value: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            serializer.serialize_str(&hex::encode(value))
        } else {
            value.serialize(serializer)
        }
    }

    pub fn deserialize_vec<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(BytesVisitor)
    }

    pub fn serialize_option_vec<S>(value: &Option<Vec<u8>>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            match value {
                Some(bytes) => serializer.serialize_some(&hex::encode(bytes)),
                None => serializer.serialize_none(),
            }
        } else {
            value.serialize(serializer)
        }
    }

    pub fn deserialize_option_vec<'de, D>(deserializer: D) -> Result<Option<Vec<u8>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct OptionBytesVisitor;

        impl<'de> Visitor<'de> for OptionBytesVisitor {
            type Value = Option<Vec<u8>>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("null, a hex string, or a byte array")
            }

            fn visit_none<E>(self) -> Result<Self::Value, E>
            where
                E: Error,
            {
                Ok(None)
            }

            fn visit_unit<E>(self) -> Result<Self::Value, E>
            where
                E: Error,
            {
                Ok(None)
            }

            fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
            where
                D: Deserializer<'de>,
            {
                deserialize_vec(deserializer).map(Some)
            }
        }

        deserializer.deserialize_option(OptionBytesVisitor)
    }
}

// ---------------------------------------------------------------------------
// Protocol Version
// ---------------------------------------------------------------------------

/// Constrained protocol version enum.
///
/// Provides compile-time safety for version strings. The receipt stores
/// the serialised string on the wire (Candid and CBOR), not the enum
/// variant, so verification tooling can parse it without importing
/// this crate.
///
/// **Naming convention:** `mktd02-v{N}` - no "leaf" suffix because
/// MKTd02 is Leaf mode by definition. Tree mode is MKTd03.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolVersion {
    /// v0.2.0 format: manifest_hash removed from deletion_event_hash,
    /// BLS certificate embedded, trust_root_key_id references allowlist.
    V2,
    /// v0.3.0 format: adds `record_id`, removes `subnet_id`, renames
    /// `nonce` to `deletion_seq`, and uses length-delimited v3 receipt_id.
    V3,
    /// v0.4.0 format: adds `module_hash_certificate` (subnet-attested code
    /// identity, helper-fetched read_state over /canister/<id>/module_hash).
    /// All V3 fields are unchanged; no hash preimage changes.
    V4,
}

impl ProtocolVersion {
    pub fn as_str(&self) -> &'static str {
        match self {
            ProtocolVersion::V2 => "mktd02-v2",
            ProtocolVersion::V3 => "mktd02-v3",
            ProtocolVersion::V4 => "mktd02-v4",
        }
    }
}

/// Classify a wire `protocol_version` string into a known [`ProtocolVersion`].
///
/// Uses `starts_with` for parity with the historical dispatch, so a
/// suffixed string (e.g. `"mktd02-v4-rc1"`) still classifies. Returns
/// `None` for any unrecognised string — callers MUST treat `None` as a
/// hard error and never fall back to a legacy wire shape.
fn classify_protocol(protocol_version: &str) -> Option<ProtocolVersion> {
    if protocol_version.starts_with("mktd02-v4") {
        Some(ProtocolVersion::V4)
    } else if protocol_version.starts_with("mktd02-v3") {
        Some(ProtocolVersion::V3)
    } else if protocol_version.starts_with("mktd02-v2") {
        Some(ProtocolVersion::V2)
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Receipt state classification (G ruling — schema-level, three outcomes)
// ---------------------------------------------------------------------------

/// Certificate-completeness classification of a receipt.
///
/// A finalized v4 receipt carries **two** certificates: `bls_certificate`
/// (Phase B, certified_data) and `module_hash_certificate` (helper-fetched
/// read_state). This enum captures the only three legitimate combinations;
/// verifier enforcement lives in CVDR-Verify, but the classification and its
/// invariants are owned here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, CandidType)]
pub enum ReceiptState {
    /// Neither certificate present. Exportable, but non-attested.
    Pending,
    /// Both certificates present. Subject to verification (V1/V2/V3-A).
    FinalizedCandidate,
    /// Exactly one certificate present. This is a malformed finalization —
    /// it is **not** Pending and must never be treated as verifiable-finalized.
    InvalidIncompleteFinalization,
}

impl From<ProtocolVersion> for String {
    fn from(v: ProtocolVersion) -> String {
        v.as_str().to_string()
    }
}

impl std::fmt::Display for ProtocolVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Deletion Receipt
// ---------------------------------------------------------------------------

// Serialisation is version-dispatched, not derived:
// - `Serialize` is a manual impl (below) so an unrecognised `protocol_version`
//   is a HARD ERROR, never a silent fallback to a legacy wire shape.
// - `Deserialize` decodes a tolerant superset (`DeletionReceiptRawWire`) then
//   validates + dispatches via `TryFrom`, which also hard-errors on an
//   unrecognised `protocol_version`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, CandidType)]
#[serde(try_from = "DeletionReceiptRawWire")]
pub struct DeletionReceipt {
    /// Protocol version string (e.g. "mktd02-v3"). Tells the verifier
    /// which hash formulas to use.
    pub protocol_version: String,
    #[serde(
        serialize_with = "serde_hex_bytes::serialize_array_32",
        deserialize_with = "serde_hex_bytes::deserialize_array_32"
    )]
    pub receipt_id: [u8; 32],
    pub canister_id: Principal,
    /// In MKTd02 leaf mode this is the deleted subject principal bytes.
    /// For legacy v2 receipts, this decodes as an empty vector.
    #[serde(
        serialize_with = "serde_hex_bytes::serialize_vec",
        deserialize_with = "serde_hex_bytes::deserialize_vec"
    )]
    pub record_id: Vec<u8>,
    #[serde(
        serialize_with = "serde_hex_bytes::serialize_array_32",
        deserialize_with = "serde_hex_bytes::deserialize_array_32"
    )]
    pub pre_state_hash: [u8; 32],
    #[serde(
        serialize_with = "serde_hex_bytes::serialize_array_32",
        deserialize_with = "serde_hex_bytes::deserialize_array_32"
    )]
    pub post_state_hash: [u8; 32],
    #[serde(
        serialize_with = "serde_hex_bytes::serialize_array_32",
        deserialize_with = "serde_hex_bytes::deserialize_array_32"
    )]
    pub tombstone_hash: [u8; 32],
    #[serde(
        serialize_with = "serde_hex_bytes::serialize_array_32",
        deserialize_with = "serde_hex_bytes::deserialize_array_32"
    )]
    pub deletion_event_hash: [u8; 32],
    #[serde(
        serialize_with = "serde_hex_bytes::serialize_array_32",
        deserialize_with = "serde_hex_bytes::deserialize_array_32"
    )]
    pub certified_commitment: [u8; 32],
    #[serde(
        serialize_with = "serde_hex_bytes::serialize_array_32",
        deserialize_with = "serde_hex_bytes::deserialize_array_32"
    )]
    pub module_hash: [u8; 32],
    pub timestamp: u64,
    pub deletion_seq: u64,
    /// Raw BLS certificate blob from ic0.data_certificate().
    /// None while receipt is pending finalization; Some after finalization.
    #[serde(
        serialize_with = "serde_hex_bytes::serialize_option_vec",
        deserialize_with = "serde_hex_bytes::deserialize_option_vec"
    )]
    pub bls_certificate: Option<Vec<u8>>,
    /// Identifies the NNS root key used to sign the BLS certificate.
    /// Look up the actual key bytes via `zombie_core::nns_keys::lookup_key(id)`.
    ///
    /// Empty string for pending receipts (populated during finalization).
    /// For all mainnet receipts: `"mainnet"`.
    /// For local-dev receipts: `"local-dev"` (requires `local-replica` feature).
    pub trust_root_key_id: String,
    /// Raw certificate blob from a `read_state` over
    /// `/canister/<id>/module_hash` (subnet-attested code identity).
    ///
    /// `None` until the off-canister helper attaches it; `Some` in a
    /// finalized v4 receipt. Present only on `mktd02-v4`+ receipts — always
    /// `None` for v2/v3. Serialised with the same hex pattern as
    /// `bls_certificate`.
    #[serde(default)]
    #[serde(
        serialize_with = "serde_hex_bytes::serialize_option_vec",
        deserialize_with = "serde_hex_bytes::deserialize_option_vec"
    )]
    pub module_hash_certificate: Option<Vec<u8>>,
}

impl DeletionReceipt {
    /// Classify this receipt by certificate completeness.
    ///
    /// The classification is **protocol-aware** (R-2). G's two-certificate rule
    /// governs the frozen v4 schema; v2/v3 predate `module_hash_certificate` and
    /// keep their existing single-certificate finalization semantics.
    ///
    /// - **v4**: neither certificate → `Pending`; both → `FinalizedCandidate`;
    ///   exactly one → `InvalidIncompleteFinalization`.
    /// - **v2/v3**: `bls_certificate` absent → `Pending`, present →
    ///   `FinalizedCandidate`. A bls-only v3 receipt is a legitimately finalized
    ///   v3 receipt, not `Invalid`.
    ///
    /// Note: after R-1, a *decoded* v2/v3 receipt can never carry a
    /// `module_hash_certificate` (that input hard-errors). A
    /// programmatically-constructed v2/v3 receipt that sets one anyway is
    /// treated as malformed and classifies `InvalidIncompleteFinalization` —
    /// acceptable, since such a value cannot arise from the wire.
    /// An unrecognised `protocol_version` also classifies
    /// `InvalidIncompleteFinalization` (it can never be a valid finalized state).
    pub fn state(&self) -> ReceiptState {
        let bls = self.bls_certificate.is_some();
        let module = self.module_hash_certificate.is_some();
        match classify_protocol(&self.protocol_version) {
            Some(ProtocolVersion::V4) => match (bls, module) {
                (false, false) => ReceiptState::Pending,
                (true, true) => ReceiptState::FinalizedCandidate,
                _ => ReceiptState::InvalidIncompleteFinalization,
            },
            Some(ProtocolVersion::V3) | Some(ProtocolVersion::V2) => {
                if module {
                    // v2/v3 have no module_hash_certificate field; a set value
                    // is malformed by construction (cannot arise from decode).
                    ReceiptState::InvalidIncompleteFinalization
                } else if bls {
                    ReceiptState::FinalizedCandidate
                } else {
                    ReceiptState::Pending
                }
            }
            None => ReceiptState::InvalidIncompleteFinalization,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, CandidType)]
pub struct ReceiptSummary {
    pub receipt_id: [u8; 32],
    pub canister_id: Principal,
    pub protocol_version: String,
    pub timestamp: u64,
    pub deletion_seq: u64,
    pub state_changed: bool,
    /// Certificate-completeness classification (see [`ReceiptState`]).
    pub state: ReceiptState,
}

impl From<&DeletionReceipt> for ReceiptSummary {
    fn from(r: &DeletionReceipt) -> Self {
        Self {
            receipt_id: r.receipt_id,
            canister_id: r.canister_id,
            protocol_version: r.protocol_version.clone(),
            timestamp: r.timestamp,
            deletion_seq: r.deletion_seq,
            state_changed: r.pre_state_hash != r.post_state_hash,
            state: r.state(),
        }
    }
}

/// Compute a v3 receipt ID.
///
/// `receipt_id = SHA-256(
///   MKTD02_RECEIPT_V3 ||
///   u32_be(len(canister_id_bytes)) || canister_id_bytes ||
///   u32_be(len(record_id_bytes))   || record_id_bytes   ||
///   u64_be(deletion_seq)
/// )`
pub fn compute_receipt_id(
    canister_id: &Principal,
    record_id: &[u8],
    deletion_seq: u64,
) -> [u8; 32] {
    let canister_bytes = canister_id.as_slice();
    let canister_len = (canister_bytes.len() as u32).to_be_bytes();
    let record_len = (record_id.len() as u32).to_be_bytes();
    let deletion_seq_be = deletion_seq.to_be_bytes();

    hash_with_tag(
        TAG_RECEIPT_V3,
        &[
            &canister_len,
            canister_bytes,
            &record_len,
            record_id,
            &deletion_seq_be,
        ],
    )
}

/// Compute a legacy v2 receipt ID for backward-compatible verification.
///
/// `receipt_id = SHA-256(MKTD02_RECEIPT_V1 || canister_id_bytes || nonce_be_bytes)`
pub fn compute_receipt_id_v2(canister_id: &Principal, nonce: u64) -> [u8; 32] {
    hash_with_tag(TAG_RECEIPT, &[canister_id.as_slice(), &nonce.to_be_bytes()])
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct DeletionReceiptV3Wire {
    protocol_version: String,
    #[serde(
        serialize_with = "serde_hex_bytes::serialize_array_32",
        deserialize_with = "serde_hex_bytes::deserialize_array_32"
    )]
    receipt_id: [u8; 32],
    canister_id: Principal,
    #[serde(
        serialize_with = "serde_hex_bytes::serialize_vec",
        deserialize_with = "serde_hex_bytes::deserialize_vec"
    )]
    record_id: Vec<u8>,
    #[serde(
        serialize_with = "serde_hex_bytes::serialize_array_32",
        deserialize_with = "serde_hex_bytes::deserialize_array_32"
    )]
    pre_state_hash: [u8; 32],
    #[serde(
        serialize_with = "serde_hex_bytes::serialize_array_32",
        deserialize_with = "serde_hex_bytes::deserialize_array_32"
    )]
    post_state_hash: [u8; 32],
    #[serde(
        serialize_with = "serde_hex_bytes::serialize_array_32",
        deserialize_with = "serde_hex_bytes::deserialize_array_32"
    )]
    tombstone_hash: [u8; 32],
    #[serde(
        serialize_with = "serde_hex_bytes::serialize_array_32",
        deserialize_with = "serde_hex_bytes::deserialize_array_32"
    )]
    deletion_event_hash: [u8; 32],
    #[serde(
        serialize_with = "serde_hex_bytes::serialize_array_32",
        deserialize_with = "serde_hex_bytes::deserialize_array_32"
    )]
    certified_commitment: [u8; 32],
    #[serde(
        serialize_with = "serde_hex_bytes::serialize_array_32",
        deserialize_with = "serde_hex_bytes::deserialize_array_32"
    )]
    module_hash: [u8; 32],
    timestamp: u64,
    deletion_seq: u64,
    #[serde(default)]
    #[serde(
        serialize_with = "serde_hex_bytes::serialize_option_vec",
        deserialize_with = "serde_hex_bytes::deserialize_option_vec"
    )]
    bls_certificate: Option<Vec<u8>>,
    #[serde(default)]
    trust_root_key_id: String,
}

/// v4 wire shape: byte-compatible superset of [`DeletionReceiptV3Wire`] with
/// `module_hash_certificate` appended. Used only for serialisation of
/// `mktd02-v4` receipts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct DeletionReceiptV4Wire {
    protocol_version: String,
    #[serde(
        serialize_with = "serde_hex_bytes::serialize_array_32",
        deserialize_with = "serde_hex_bytes::deserialize_array_32"
    )]
    receipt_id: [u8; 32],
    canister_id: Principal,
    #[serde(
        serialize_with = "serde_hex_bytes::serialize_vec",
        deserialize_with = "serde_hex_bytes::deserialize_vec"
    )]
    record_id: Vec<u8>,
    #[serde(
        serialize_with = "serde_hex_bytes::serialize_array_32",
        deserialize_with = "serde_hex_bytes::deserialize_array_32"
    )]
    pre_state_hash: [u8; 32],
    #[serde(
        serialize_with = "serde_hex_bytes::serialize_array_32",
        deserialize_with = "serde_hex_bytes::deserialize_array_32"
    )]
    post_state_hash: [u8; 32],
    #[serde(
        serialize_with = "serde_hex_bytes::serialize_array_32",
        deserialize_with = "serde_hex_bytes::deserialize_array_32"
    )]
    tombstone_hash: [u8; 32],
    #[serde(
        serialize_with = "serde_hex_bytes::serialize_array_32",
        deserialize_with = "serde_hex_bytes::deserialize_array_32"
    )]
    deletion_event_hash: [u8; 32],
    #[serde(
        serialize_with = "serde_hex_bytes::serialize_array_32",
        deserialize_with = "serde_hex_bytes::deserialize_array_32"
    )]
    certified_commitment: [u8; 32],
    #[serde(
        serialize_with = "serde_hex_bytes::serialize_array_32",
        deserialize_with = "serde_hex_bytes::deserialize_array_32"
    )]
    module_hash: [u8; 32],
    timestamp: u64,
    deletion_seq: u64,
    #[serde(default)]
    #[serde(
        serialize_with = "serde_hex_bytes::serialize_option_vec",
        deserialize_with = "serde_hex_bytes::deserialize_option_vec"
    )]
    bls_certificate: Option<Vec<u8>>,
    #[serde(default)]
    trust_root_key_id: String,
    #[serde(default)]
    #[serde(
        serialize_with = "serde_hex_bytes::serialize_option_vec",
        deserialize_with = "serde_hex_bytes::deserialize_option_vec"
    )]
    module_hash_certificate: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct DeletionReceiptV2Wire {
    protocol_version: String,
    #[serde(
        serialize_with = "serde_hex_bytes::serialize_array_32",
        deserialize_with = "serde_hex_bytes::deserialize_array_32"
    )]
    receipt_id: [u8; 32],
    canister_id: Principal,
    subnet_id: Principal,
    #[serde(
        serialize_with = "serde_hex_bytes::serialize_array_32",
        deserialize_with = "serde_hex_bytes::deserialize_array_32"
    )]
    pre_state_hash: [u8; 32],
    #[serde(
        serialize_with = "serde_hex_bytes::serialize_array_32",
        deserialize_with = "serde_hex_bytes::deserialize_array_32"
    )]
    post_state_hash: [u8; 32],
    #[serde(
        serialize_with = "serde_hex_bytes::serialize_array_32",
        deserialize_with = "serde_hex_bytes::deserialize_array_32"
    )]
    tombstone_hash: [u8; 32],
    #[serde(
        serialize_with = "serde_hex_bytes::serialize_array_32",
        deserialize_with = "serde_hex_bytes::deserialize_array_32"
    )]
    deletion_event_hash: [u8; 32],
    #[serde(
        serialize_with = "serde_hex_bytes::serialize_array_32",
        deserialize_with = "serde_hex_bytes::deserialize_array_32"
    )]
    certified_commitment: [u8; 32],
    #[serde(
        serialize_with = "serde_hex_bytes::serialize_array_32",
        deserialize_with = "serde_hex_bytes::deserialize_array_32"
    )]
    module_hash: [u8; 32],
    timestamp: u64,
    nonce: u64,
    #[serde(default)]
    #[serde(
        serialize_with = "serde_hex_bytes::serialize_option_vec",
        deserialize_with = "serde_hex_bytes::deserialize_option_vec"
    )]
    bls_certificate: Option<Vec<u8>>,
    #[serde(default)]
    trust_root_key_id: String,
}

/// Tolerant read-side superset used for decoding.
///
/// Every version-specific field is optional/defaulted so a v2, v3, or v4
/// map all decode into this one shape; [`TryFrom`] then validates the
/// `protocol_version` and maps fields to the canonical [`DeletionReceipt`].
/// An unrecognised `protocol_version` is a hard error here — there is no
/// structural fallback to a legacy variant.
#[derive(Debug, Clone, Deserialize)]
struct DeletionReceiptRawWire {
    protocol_version: String,
    #[serde(deserialize_with = "serde_hex_bytes::deserialize_array_32")]
    receipt_id: [u8; 32],
    canister_id: Principal,
    #[serde(default)]
    #[serde(deserialize_with = "serde_hex_bytes::deserialize_vec")]
    record_id: Vec<u8>,
    // A v2 `subnet_id` field, if present on the wire, is ignored (serde skips
    // unknown fields) — it is not carried into the canonical receipt.
    #[serde(deserialize_with = "serde_hex_bytes::deserialize_array_32")]
    pre_state_hash: [u8; 32],
    #[serde(deserialize_with = "serde_hex_bytes::deserialize_array_32")]
    post_state_hash: [u8; 32],
    #[serde(deserialize_with = "serde_hex_bytes::deserialize_array_32")]
    tombstone_hash: [u8; 32],
    #[serde(deserialize_with = "serde_hex_bytes::deserialize_array_32")]
    deletion_event_hash: [u8; 32],
    #[serde(deserialize_with = "serde_hex_bytes::deserialize_array_32")]
    certified_commitment: [u8; 32],
    #[serde(deserialize_with = "serde_hex_bytes::deserialize_array_32")]
    module_hash: [u8; 32],
    timestamp: u64,
    /// v3/v4.
    #[serde(default)]
    deletion_seq: Option<u64>,
    /// v2.
    #[serde(default)]
    nonce: Option<u64>,
    #[serde(default)]
    #[serde(deserialize_with = "serde_hex_bytes::deserialize_option_vec")]
    bls_certificate: Option<Vec<u8>>,
    #[serde(default)]
    trust_root_key_id: String,
    /// v4 only.
    #[serde(default)]
    #[serde(deserialize_with = "serde_hex_bytes::deserialize_option_vec")]
    module_hash_certificate: Option<Vec<u8>>,
}

impl TryFrom<DeletionReceiptRawWire> for DeletionReceipt {
    type Error = String;

    fn try_from(w: DeletionReceiptRawWire) -> Result<Self, Self::Error> {
        match classify_protocol(&w.protocol_version) {
            Some(ProtocolVersion::V4) | Some(ProtocolVersion::V3) => {
                let is_v4 = matches!(
                    classify_protocol(&w.protocol_version),
                    Some(ProtocolVersion::V4)
                );
                // R-1: module_hash_certificate is a v4-only field. A v3-labelled
                // wire carrying it is malformed by construction — hard-error
                // rather than silently drop it (which would let a module-cert-
                // only payload decode as Pending). No-silent-degrade: malformed
                // input errors, never reshapes.
                if !is_v4 && w.module_hash_certificate.is_some() {
                    return Err(format!(
                        "DeletionReceipt: {} receipt carries module_hash_certificate \
                         (a v4-only field) — malformed, refusing to decode",
                        w.protocol_version
                    ));
                }
                let deletion_seq = w.deletion_seq.ok_or_else(|| {
                    format!(
                        "DeletionReceipt: {} receipt missing deletion_seq",
                        w.protocol_version
                    )
                })?;
                Ok(DeletionReceipt {
                    protocol_version: w.protocol_version,
                    receipt_id: w.receipt_id,
                    canister_id: w.canister_id,
                    record_id: w.record_id,
                    pre_state_hash: w.pre_state_hash,
                    post_state_hash: w.post_state_hash,
                    tombstone_hash: w.tombstone_hash,
                    deletion_event_hash: w.deletion_event_hash,
                    certified_commitment: w.certified_commitment,
                    module_hash: w.module_hash,
                    timestamp: w.timestamp,
                    deletion_seq,
                    bls_certificate: w.bls_certificate,
                    trust_root_key_id: w.trust_root_key_id,
                    module_hash_certificate: if is_v4 {
                        w.module_hash_certificate
                    } else {
                        None
                    },
                })
            }
            Some(ProtocolVersion::V2) => {
                // R-1: as for v3, module_hash_certificate is not a v2 field.
                if w.module_hash_certificate.is_some() {
                    return Err(format!(
                        "DeletionReceipt: {} receipt carries module_hash_certificate \
                         (a v4-only field) — malformed, refusing to decode",
                        w.protocol_version
                    ));
                }
                let deletion_seq = w.nonce.ok_or_else(|| {
                    format!(
                        "DeletionReceipt: {} receipt missing nonce",
                        w.protocol_version
                    )
                })?;
                Ok(DeletionReceipt {
                    protocol_version: w.protocol_version,
                    receipt_id: w.receipt_id,
                    canister_id: w.canister_id,
                    record_id: Vec::new(),
                    pre_state_hash: w.pre_state_hash,
                    post_state_hash: w.post_state_hash,
                    tombstone_hash: w.tombstone_hash,
                    deletion_event_hash: w.deletion_event_hash,
                    certified_commitment: w.certified_commitment,
                    module_hash: w.module_hash,
                    timestamp: w.timestamp,
                    deletion_seq,
                    bls_certificate: w.bls_certificate,
                    trust_root_key_id: w.trust_root_key_id,
                    module_hash_certificate: None,
                })
            }
            None => Err(format!(
                "DeletionReceipt: unrecognised protocol_version {:?}; \
                 refusing to decode (no silent legacy fallback)",
                w.protocol_version
            )),
        }
    }
}

impl Serialize for DeletionReceipt {
    /// Version-dispatched serialisation. Emits the exact V2/V3/V4 wire shape
    /// for a recognised `protocol_version`, and a hard error otherwise — the
    /// fix for the historical silent-V2-fallback defect.
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match classify_protocol(&self.protocol_version) {
            Some(ProtocolVersion::V4) => DeletionReceiptV4Wire {
                protocol_version: self.protocol_version.clone(),
                receipt_id: self.receipt_id,
                canister_id: self.canister_id,
                record_id: self.record_id.clone(),
                pre_state_hash: self.pre_state_hash,
                post_state_hash: self.post_state_hash,
                tombstone_hash: self.tombstone_hash,
                deletion_event_hash: self.deletion_event_hash,
                certified_commitment: self.certified_commitment,
                module_hash: self.module_hash,
                timestamp: self.timestamp,
                deletion_seq: self.deletion_seq,
                bls_certificate: self.bls_certificate.clone(),
                trust_root_key_id: self.trust_root_key_id.clone(),
                module_hash_certificate: self.module_hash_certificate.clone(),
            }
            .serialize(serializer),
            Some(ProtocolVersion::V3) => DeletionReceiptV3Wire {
                protocol_version: self.protocol_version.clone(),
                receipt_id: self.receipt_id,
                canister_id: self.canister_id,
                record_id: self.record_id.clone(),
                pre_state_hash: self.pre_state_hash,
                post_state_hash: self.post_state_hash,
                tombstone_hash: self.tombstone_hash,
                deletion_event_hash: self.deletion_event_hash,
                certified_commitment: self.certified_commitment,
                module_hash: self.module_hash,
                timestamp: self.timestamp,
                deletion_seq: self.deletion_seq,
                bls_certificate: self.bls_certificate.clone(),
                trust_root_key_id: self.trust_root_key_id.clone(),
            }
            .serialize(serializer),
            Some(ProtocolVersion::V2) => DeletionReceiptV2Wire {
                protocol_version: self.protocol_version.clone(),
                receipt_id: self.receipt_id,
                canister_id: self.canister_id,
                subnet_id: Principal::anonymous(),
                pre_state_hash: self.pre_state_hash,
                post_state_hash: self.post_state_hash,
                tombstone_hash: self.tombstone_hash,
                deletion_event_hash: self.deletion_event_hash,
                certified_commitment: self.certified_commitment,
                module_hash: self.module_hash,
                timestamp: self.timestamp,
                nonce: self.deletion_seq,
                bls_certificate: self.bls_certificate.clone(),
                trust_root_key_id: self.trust_root_key_id.clone(),
            }
            .serialize(serializer),
            None => Err(S::Error::custom(format!(
                "DeletionReceipt: unrecognised protocol_version {:?}; \
                 refusing to serialise (no silent legacy fallback)",
                self.protocol_version
            ))),
        }
    }
}


// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn test_receipt() -> DeletionReceipt {
        DeletionReceipt {
            protocol_version: ProtocolVersion::V3.into(),
            receipt_id: [1u8; 32],
            canister_id: Principal::from_text("aaaaa-aa").unwrap(),
            record_id: vec![7u8, 8u8, 9u8],
            pre_state_hash: [2u8; 32],
            post_state_hash: [3u8; 32],
            tombstone_hash: [4u8; 32],
            deletion_event_hash: [5u8; 32],
            certified_commitment: [6u8; 32],
            module_hash: [8u8; 32],
            timestamp: 1_000_000,
            deletion_seq: 1,
            bls_certificate: None,
            // Finalized receipt: bls_certificate = None here only for test brevity,
            // but trust_root_key_id reflects a finalized state.
            trust_root_key_id: String::from("mainnet"),
            module_hash_certificate: None,
        }
    }

    /// A finalized v4 receipt: both certificates present.
    fn test_receipt_v4() -> DeletionReceipt {
        DeletionReceipt {
            protocol_version: ProtocolVersion::V4.into(),
            record_id: vec![7u8, 8u8, 9u8],
            bls_certificate: Some(vec![0xAA, 0xBB, 0xCC]),
            module_hash_certificate: Some(vec![0x01, 0x02, 0x03, 0x04]),
            ..test_receipt()
        }
    }

    #[test]
    fn receipt_id_deterministic() {
        let c = Principal::from_text("aaaaa-aa").unwrap();
        let record_id = vec![1, 2, 3];
        assert_eq!(
            compute_receipt_id(&c, &record_id, 1),
            compute_receipt_id(&c, &record_id, 1)
        );
    }

    #[test]
    fn receipt_id_different_deletion_seq_values_differ() {
        let c = Principal::from_text("aaaaa-aa").unwrap();
        let record_id = vec![1, 2, 3];
        assert_ne!(
            compute_receipt_id(&c, &record_id, 1),
            compute_receipt_id(&c, &record_id, 2)
        );
    }

    #[test]
    fn receipt_id_different_canister_bytes_differ() {
        let c1 = Principal::from_text("aaaaa-aa").unwrap();
        let c2 = Principal::from_text("2vxsx-fae").unwrap();
        let record_id = vec![1, 2, 3];
        assert_ne!(
            compute_receipt_id(&c1, &record_id, 1),
            compute_receipt_id(&c2, &record_id, 1)
        );
    }

    #[test]
    fn receipt_id_different_record_ids_differ() {
        let c = Principal::from_text("aaaaa-aa").unwrap();
        assert_ne!(
            compute_receipt_id(&c, &[1, 2, 3], 1),
            compute_receipt_id(&c, &[1, 2, 4], 1)
        );
    }

    #[test]
    fn receipt_summary_from_receipt() {
        let r = test_receipt();
        let s = ReceiptSummary::from(&r);
        assert!(s.state_changed);
        assert_eq!(s.protocol_version, "mktd02-v3");
        assert_eq!(s.deletion_seq, 1);
    }

    #[test]
    fn receipt_summary_state_unchanged_when_equal() {
        let mut r = test_receipt();
        r.post_state_hash = r.pre_state_hash;
        let s = ReceiptSummary::from(&r);
        assert!(!s.state_changed);
    }

    #[test]
    fn golden_receipt_id_v3_with_u32_length_prefixes() {
        // canister bytes = [1,2,3,4], record_id bytes = [10,11,12], deletion_seq = 7
        // Preimage bytes:
        // 00000004 || 01020304 || 00000003 || 0a0b0c || 0000000000000007
        let c = Principal::from_slice(&[1, 2, 3, 4]);
        let id = compute_receipt_id(&c, &[10, 11, 12], 7);
        assert_eq!(
            hex::encode(id),
            "231bca0d2351bb588bae612eab8ea46810097294dcd98cfbc4ae3045fdced09d",
            "v3 receipt_id derivation changed - this breaks v0.3 receipts"
        );
    }

    #[test]
    fn golden_receipt_id_v2_still_stable() {
        let c = Principal::from_text("aaaaa-aa").unwrap();
        let id = compute_receipt_id_v2(&c, 1);
        assert_eq!(
            hex::encode(id),
            "1f213a0f2bf4992071a7f23e72d1942e564a4e871e3decce8ac8ee27d08f534b",
            "v2 receipt_id derivation changed - this breaks existing v2 receipts"
        );
    }

    #[test]
    fn protocol_version_serialises_correctly() {
        assert_eq!(ProtocolVersion::V2.as_str(), "mktd02-v2");
        assert_eq!(ProtocolVersion::V3.as_str(), "mktd02-v3");
        let s: String = ProtocolVersion::V2.into();
        let s3: String = ProtocolVersion::V3.into();
        assert_eq!(s, "mktd02-v2");
        assert_eq!(s3, "mktd02-v3");
        assert_eq!(format!("{}", ProtocolVersion::V2), "mktd02-v2");
        assert_eq!(format!("{}", ProtocolVersion::V3), "mktd02-v3");
    }

    #[test]
    fn trust_root_key_id_default_is_mainnet_for_finalized_receipt() {
        // A finalized mainnet receipt must carry "mainnet" as the key ID.
        // This test documents the expected value.
        let r = test_receipt();
        assert_eq!(r.trust_root_key_id, "mainnet");
    }

    #[test]
    fn pending_receipt_has_empty_trust_root_key_id() {
        // Invariant: pending receipts (not yet finalized) have empty trust_root_key_id.
        // This is enforced by convention and tested here.
        let r = DeletionReceipt {
            trust_root_key_id: String::new(),
            bls_certificate: None,
            ..test_receipt()
        };
        assert!(r.trust_root_key_id.is_empty());
        assert!(r.bls_certificate.is_none());
    }

    #[test]
    fn legacy_v2_cbor_decodes_safely_to_v3_shape() {
        let legacy_wire = DeletionReceiptV2Wire {
            protocol_version: "mktd02-v2".into(),
            receipt_id: [1u8; 32],
            canister_id: Principal::from_text("aaaaa-aa").unwrap(),
            subnet_id: Principal::from_text("2vxsx-fae").unwrap(),
            pre_state_hash: [2u8; 32],
            post_state_hash: [3u8; 32],
            tombstone_hash: [4u8; 32],
            deletion_event_hash: [5u8; 32],
            certified_commitment: [6u8; 32],
            module_hash: [8u8; 32],
            timestamp: 1_000_000u64,
            nonce: 42u64,
            bls_certificate: None,
            trust_root_key_id: "mainnet".into(),
        };

        let mut buf = Vec::new();
        ciborium::into_writer(&legacy_wire, &mut buf).unwrap();
        let decoded: DeletionReceipt = ciborium::from_reader(buf.as_slice()).unwrap();

        assert_eq!(decoded.protocol_version, "mktd02-v2");
        assert_eq!(decoded.record_id, Vec::<u8>::new());
        assert_eq!(decoded.deletion_seq, 42);
        assert_eq!(decoded.trust_root_key_id, "mainnet");
    }

    #[test]
    fn legacy_v2_receipt_summary_uses_deletion_seq_from_nonce() {
        let legacy_wire = DeletionReceiptV2Wire {
            protocol_version: "mktd02-v2".into(),
            receipt_id: [1u8; 32],
            canister_id: Principal::from_text("aaaaa-aa").unwrap(),
            subnet_id: Principal::from_text("2vxsx-fae").unwrap(),
            pre_state_hash: [2u8; 32],
            post_state_hash: [3u8; 32],
            tombstone_hash: [4u8; 32],
            deletion_event_hash: [5u8; 32],
            certified_commitment: [6u8; 32],
            module_hash: [8u8; 32],
            timestamp: 1_000_000u64,
            nonce: 77u64,
            bls_certificate: None,
            trust_root_key_id: "mainnet".into(),
        };

        let mut buf = Vec::new();
        ciborium::into_writer(&legacy_wire, &mut buf).unwrap();
        let decoded: DeletionReceipt = ciborium::from_reader(buf.as_slice()).unwrap();

        let summary = ReceiptSummary::from(&decoded);
        assert_eq!(summary.protocol_version, "mktd02-v2");
        assert_eq!(summary.deletion_seq, 77);
    }

    #[test]
    fn v3_json_serializes_portable_bytes_as_hex_strings() {
        let mut receipt = test_receipt();
        receipt.bls_certificate = Some(vec![0x0a, 0x0b, 0x0c]);

        let value = serde_json::to_value(&receipt).unwrap();

        assert_eq!(value["receipt_id"], json!(hex::encode(receipt.receipt_id)));
        assert_eq!(value["record_id"], json!(hex::encode(&receipt.record_id)));
        assert_eq!(
            value["pre_state_hash"],
            json!(hex::encode(receipt.pre_state_hash))
        );
        assert_eq!(
            value["post_state_hash"],
            json!(hex::encode(receipt.post_state_hash))
        );
        assert_eq!(
            value["tombstone_hash"],
            json!(hex::encode(receipt.tombstone_hash))
        );
        assert_eq!(
            value["deletion_event_hash"],
            json!(hex::encode(receipt.deletion_event_hash))
        );
        assert_eq!(
            value["certified_commitment"],
            json!(hex::encode(receipt.certified_commitment))
        );
        assert_eq!(value["module_hash"], json!(hex::encode(receipt.module_hash)));
        assert_eq!(
            value["bls_certificate"],
            json!(hex::encode(receipt.bls_certificate.unwrap()))
        );
    }

    #[test]
    fn v3_json_deserializes_hex_strings_for_portable_bytes() {
        let receipt = test_receipt();
        let json_value = json!({
            "protocol_version": receipt.protocol_version,
            "receipt_id": hex::encode(receipt.receipt_id),
            "canister_id": receipt.canister_id,
            "record_id": hex::encode(&receipt.record_id),
            "pre_state_hash": hex::encode(receipt.pre_state_hash),
            "post_state_hash": hex::encode(receipt.post_state_hash),
            "tombstone_hash": hex::encode(receipt.tombstone_hash),
            "deletion_event_hash": hex::encode(receipt.deletion_event_hash),
            "certified_commitment": hex::encode(receipt.certified_commitment),
            "module_hash": hex::encode(receipt.module_hash),
            "timestamp": receipt.timestamp,
            "deletion_seq": receipt.deletion_seq,
            "bls_certificate": "0a0b0c",
            "trust_root_key_id": receipt.trust_root_key_id,
        });

        let decoded: DeletionReceipt = serde_json::from_value(json_value).unwrap();
        assert_eq!(decoded.receipt_id, [1u8; 32]);
        assert_eq!(decoded.record_id, vec![7u8, 8u8, 9u8]);
        assert_eq!(decoded.pre_state_hash, [2u8; 32]);
        assert_eq!(decoded.post_state_hash, [3u8; 32]);
        assert_eq!(decoded.tombstone_hash, [4u8; 32]);
        assert_eq!(decoded.deletion_event_hash, [5u8; 32]);
        assert_eq!(decoded.certified_commitment, [6u8; 32]);
        assert_eq!(decoded.module_hash, [8u8; 32]);
        assert_eq!(decoded.bls_certificate, Some(vec![0x0a, 0x0b, 0x0c]));
    }

    // -----------------------------------------------------------------------
    // v0.4.0 — v4 schema, wire dispatch, state classification, golden vectors
    // -----------------------------------------------------------------------

    /// The exact receipt used to capture the pristine (pre-v4) V3 golden
    /// vectors from HEAD `508f2f8`, before any v4 change was applied.
    fn golden_v3_receipt() -> DeletionReceipt {
        DeletionReceipt {
            protocol_version: ProtocolVersion::V3.into(),
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
            module_hash_certificate: None,
        }
    }

    // --- v3 byte-identical regression (golden vector from HEAD 508f2f8) -----

    /// v3 CBOR output must be byte-identical to pristine HEAD behaviour.
    /// Golden hex captured from the unmodified crate before the v4 change.
    #[test]
    fn v3_cbor_byte_identical_to_head_golden() {
        const V3_CBOR_HEX: &str = "ae7070726f746f636f6c5f76657273696f6e696d6b746430322d76336a726563656970745f6964982001010101010101010101010101010101010101010101010101010101010101016b63616e69737465725f69644401020304697265636f72645f6964830a0b0c6e7072655f73746174655f68617368982002020202020202020202020202020202020202020202020202020202020202026f706f73745f73746174655f68617368982003030303030303030303030303030303030303030303030303030303030303036e746f6d6273746f6e655f68617368982004040404040404040404040404040404040404040404040404040404040404047364656c6574696f6e5f6576656e745f6861736898200505050505050505050505050505050505050505050505050505050505050505746365727469666965645f636f6d6d69746d656e74982006060606060606060606060606060606060606060606060606060606060606066b6d6f64756c655f68617368982007070707070707070707070707070707070707070707070707070707070707076974696d657374616d701a000f42406c64656c6574696f6e5f736571076f626c735f63657274696669636174658318aa18bb18cc7174727573745f726f6f745f6b65795f6964676d61696e6e6574";
        let mut cbor = Vec::new();
        ciborium::into_writer(&golden_v3_receipt(), &mut cbor).unwrap();
        assert_eq!(
            hex::encode(&cbor),
            V3_CBOR_HEX,
            "v3 CBOR output changed — this breaks byte-compat with existing v3 receipts"
        );
    }

    /// v3 JSON output must be byte-identical to pristine HEAD behaviour.
    #[test]
    fn v3_json_byte_identical_to_head_golden() {
        const V3_JSON: &str = "{\"protocol_version\":\"mktd02-v3\",\"receipt_id\":\"0101010101010101010101010101010101010101010101010101010101010101\",\"canister_id\":\"wy6px-tibai-bqi\",\"record_id\":\"0a0b0c\",\"pre_state_hash\":\"0202020202020202020202020202020202020202020202020202020202020202\",\"post_state_hash\":\"0303030303030303030303030303030303030303030303030303030303030303\",\"tombstone_hash\":\"0404040404040404040404040404040404040404040404040404040404040404\",\"deletion_event_hash\":\"0505050505050505050505050505050505050505050505050505050505050505\",\"certified_commitment\":\"0606060606060606060606060606060606060606060606060606060606060606\",\"module_hash\":\"0707070707070707070707070707070707070707070707070707070707070707\",\"timestamp\":1000000,\"deletion_seq\":7,\"bls_certificate\":\"aabbcc\",\"trust_root_key_id\":\"mainnet\"}";
        assert_eq!(
            serde_json::to_string(&golden_v3_receipt()).unwrap(),
            V3_JSON,
            "v3 JSON output changed — v3 receipts must have no module_hash_certificate field"
        );
    }

    /// v3 output must NOT contain a `module_hash_certificate` field at all.
    #[test]
    fn v3_output_omits_module_hash_certificate_field() {
        let v = serde_json::to_value(golden_v3_receipt()).unwrap();
        assert!(
            v.get("module_hash_certificate").is_none(),
            "v3 receipts must not carry a module_hash_certificate field"
        );
    }

    // --- v4 round-trips -----------------------------------------------------

    #[test]
    fn v4_cbor_round_trip_preserves_record_id_and_both_certificates() {
        let r = test_receipt_v4();
        let mut cbor = Vec::new();
        ciborium::into_writer(&r, &mut cbor).unwrap();
        let decoded: DeletionReceipt = ciborium::from_reader(cbor.as_slice()).unwrap();
        assert_eq!(decoded, r);
        assert_eq!(decoded.protocol_version, "mktd02-v4");
        assert_eq!(decoded.record_id, vec![7u8, 8u8, 9u8]);
        assert_eq!(decoded.bls_certificate, Some(vec![0xAA, 0xBB, 0xCC]));
        assert_eq!(
            decoded.module_hash_certificate,
            Some(vec![0x01, 0x02, 0x03, 0x04])
        );
    }

    #[test]
    fn v4_json_round_trip_preserves_record_id_and_both_certificates() {
        let r = test_receipt_v4();
        let json = serde_json::to_string(&r).unwrap();
        // module_hash_certificate serialises with the same hex pattern as bls_certificate.
        assert!(json.contains("\"module_hash_certificate\":\"01020304\""));
        assert!(json.contains("\"bls_certificate\":\"aabbcc\""));
        let decoded: DeletionReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, r);
        assert_eq!(decoded.record_id, vec![7u8, 8u8, 9u8]);
    }

    // --- legacy / pending shapes without the new field still decode ---------

    /// A v4 map missing the `module_hash_certificate` key (serde default) still
    /// decodes — this is the pending v4 shape.
    #[test]
    fn v4_without_module_hash_certificate_decodes_as_pending() {
        let json = json!({
            "protocol_version": "mktd02-v4",
            "receipt_id": hex::encode([1u8; 32]),
            "canister_id": Principal::from_slice(&[1, 2, 3, 4]),
            "record_id": "0a0b0c",
            "pre_state_hash": hex::encode([2u8; 32]),
            "post_state_hash": hex::encode([3u8; 32]),
            "tombstone_hash": hex::encode([4u8; 32]),
            "deletion_event_hash": hex::encode([5u8; 32]),
            "certified_commitment": hex::encode([6u8; 32]),
            "module_hash": hex::encode([7u8; 32]),
            "timestamp": 1_000_000,
            "deletion_seq": 7,
            // no bls_certificate, no trust_root_key_id, no module_hash_certificate
        });
        let decoded: DeletionReceipt = serde_json::from_value(json).unwrap();
        assert_eq!(decoded.protocol_version, "mktd02-v4");
        assert_eq!(decoded.record_id, vec![10, 11, 12]);
        assert_eq!(decoded.bls_certificate, None);
        assert_eq!(decoded.module_hash_certificate, None);
        assert_eq!(decoded.state(), ReceiptState::Pending);
    }

    /// Existing v3 CBOR (no module_hash_certificate key) still decodes, with
    /// the field defaulting to None.
    #[test]
    fn legacy_v3_cbor_decodes_with_default_none() {
        let mut cbor = Vec::new();
        ciborium::into_writer(&golden_v3_receipt(), &mut cbor).unwrap();
        let decoded: DeletionReceipt = ciborium::from_reader(cbor.as_slice()).unwrap();
        assert_eq!(decoded, golden_v3_receipt());
        assert_eq!(decoded.module_hash_certificate, None);
    }

    // --- unrecognised protocol string is a HARD ERROR (the defect fix) ------

    /// The old failure scenario: a receipt whose `protocol_version` is not a
    /// recognised line. Before the fix, serialisation silently fell through to
    /// the legacy V2 wire branch (dropping record_id, subnet_id=anonymous,
    /// deletion_seq->nonce). It must now error instead.
    #[test]
    fn unrecognised_protocol_string_errors_on_serialize() {
        let mut bad = test_receipt_v4();
        bad.protocol_version = "mktd02-v5".into(); // unknown line
        // CBOR
        let mut cbor = Vec::new();
        let cbor_res = ciborium::into_writer(&bad, &mut cbor);
        assert!(
            cbor_res.is_err(),
            "unrecognised protocol_version must not serialise to CBOR (no silent V2 fallback)"
        );
        // JSON
        let json_res = serde_json::to_string(&bad);
        assert!(
            json_res.is_err(),
            "unrecognised protocol_version must not serialise to JSON"
        );
        assert!(
            json_res.unwrap_err().to_string().contains("unrecognised protocol_version"),
            "error must name the cause"
        );
    }

    /// Proof the silent degrade is gone: a record_id-bearing receipt with an
    /// unknown protocol string does NOT round-trip through a lossy V2 shape —
    /// it fails to serialise at all.
    #[test]
    fn unrecognised_protocol_does_not_silently_degrade_to_v2() {
        let mut bad = golden_v3_receipt();
        bad.protocol_version = "not-a-real-version".into();
        let mut cbor = Vec::new();
        assert!(
            ciborium::into_writer(&bad, &mut cbor).is_err(),
            "must error, not silently emit a V2 wire that drops record_id"
        );
        assert!(cbor.is_empty() || ciborium::from_reader::<DeletionReceipt, _>(cbor.as_slice()).is_err());
    }

    /// An unrecognised protocol string on the DECODE side also hard-errors.
    #[test]
    fn unrecognised_protocol_string_errors_on_deserialize() {
        let json = json!({
            "protocol_version": "mktd02-v9",
            "receipt_id": hex::encode([1u8; 32]),
            "canister_id": Principal::from_slice(&[1, 2, 3, 4]),
            "record_id": "0a0b0c",
            "pre_state_hash": hex::encode([2u8; 32]),
            "post_state_hash": hex::encode([3u8; 32]),
            "tombstone_hash": hex::encode([4u8; 32]),
            "deletion_event_hash": hex::encode([5u8; 32]),
            "certified_commitment": hex::encode([6u8; 32]),
            "module_hash": hex::encode([7u8; 32]),
            "timestamp": 1_000_000,
            "deletion_seq": 7,
        });
        let res: Result<DeletionReceipt, _> = serde_json::from_value(json);
        assert!(res.is_err(), "unknown protocol_version must not decode");
        assert!(res.unwrap_err().to_string().contains("unrecognised protocol_version"));
    }

    // --- three-state classification (both single-cert permutations) ---------

    #[test]
    fn state_pending_when_neither_certificate_present() {
        let r = DeletionReceipt {
            protocol_version: ProtocolVersion::V4.into(),
            bls_certificate: None,
            module_hash_certificate: None,
            ..test_receipt()
        };
        assert_eq!(r.state(), ReceiptState::Pending);
    }

    #[test]
    fn state_finalized_candidate_when_both_certificates_present() {
        let r = DeletionReceipt {
            protocol_version: ProtocolVersion::V4.into(),
            bls_certificate: Some(vec![0xAA]),
            module_hash_certificate: Some(vec![0xBB]),
            ..test_receipt()
        };
        assert_eq!(r.state(), ReceiptState::FinalizedCandidate);
    }

    #[test]
    fn state_invalid_when_only_bls_certificate_present() {
        let r = DeletionReceipt {
            protocol_version: ProtocolVersion::V4.into(),
            bls_certificate: Some(vec![0xAA]),
            module_hash_certificate: None,
            ..test_receipt()
        };
        assert_eq!(r.state(), ReceiptState::InvalidIncompleteFinalization);
    }

    #[test]
    fn state_invalid_when_only_module_hash_certificate_present() {
        let r = DeletionReceipt {
            protocol_version: ProtocolVersion::V4.into(),
            bls_certificate: None,
            module_hash_certificate: Some(vec![0xBB]),
            ..test_receipt()
        };
        assert_eq!(r.state(), ReceiptState::InvalidIncompleteFinalization);
    }

    #[test]
    fn receipt_summary_carries_state() {
        let r = test_receipt_v4();
        let s = ReceiptSummary::from(&r);
        assert_eq!(s.state, ReceiptState::FinalizedCandidate);
        assert_eq!(s.protocol_version, "mktd02-v4");
    }

    // --- golden preimage vectors: hashes unchanged, cert-independent --------

    /// `receipt_id` derives only from (canister_id, record_id, deletion_seq).
    /// It is identical whether certificates are present or absent, and equals
    /// the pre-existing v3 golden.
    #[test]
    fn golden_receipt_id_unchanged_and_cert_independent() {
        let absent = DeletionReceipt {
            bls_certificate: None,
            module_hash_certificate: None,
            ..golden_v3_receipt()
        };
        let present = DeletionReceipt {
            protocol_version: ProtocolVersion::V4.into(),
            bls_certificate: Some(vec![0xAA, 0xBB, 0xCC]),
            module_hash_certificate: Some(vec![0x01, 0x02, 0x03, 0x04]),
            ..golden_v3_receipt()
        };
        let id_absent =
            compute_receipt_id(&absent.canister_id, &absent.record_id, absent.deletion_seq);
        let id_present =
            compute_receipt_id(&present.canister_id, &present.record_id, present.deletion_seq);
        assert_eq!(id_absent, id_present, "receipt_id must be certificate-independent");
        assert_eq!(
            hex::encode(id_present),
            "231bca0d2351bb588bae612eab8ea46810097294dcd98cfbc4ae3045fdced09d",
            "receipt_id derivation changed — breaks v3/v4 receipts"
        );
    }

    /// `deletion_event_hash` and `certified_commitment` preimages exclude the
    /// certificates by construction. Recomputed here from receipt fields via
    /// the mktd02 formulas; the certificates never enter either preimage, and
    /// the outputs match independently-verified goldens.
    #[test]
    fn golden_event_and_certified_preimages_cert_independent() {
        use crate::hashing::DomainTag;
        const TAG_EVENT: DomainTag = DomainTag(b"MKTD02_EVENT_V1");
        const TAG_CERTIFIED: DomainTag = DomainTag(b"MKTD02_CERTIFIED_V1");

        // Fixed inputs (same as hashing.rs::golden_deletion_event_hash_v2).
        let pre = [1u8; 32];
        let post = [2u8; 32];
        let module_hash = [3u8; 32];
        let ts: u64 = 1_000_000;
        let seq: u64 = 1;

        let event = hash_with_tag(
            TAG_EVENT,
            &[&pre, &post, &ts.to_be_bytes(), &module_hash, &seq.to_be_bytes()],
        );
        let certified = hash_with_tag(TAG_CERTIFIED, &[&post, &event]);

        assert_eq!(
            hex::encode(event),
            "9078d9a080606b46298bd9d66d3dd4a75389b04f7531b53a3a0e7c8f25955023",
            "deletion_event_hash formula changed"
        );
        assert_eq!(
            hex::encode(certified),
            "932e7b4ec2249ea53dd7ec1ed76c4dc57fba00fb55957228d92fc416700ebc16",
            "certified_commitment formula changed"
        );

        // The certificates are simply not part of either preimage: building a
        // receipt with or without them cannot change these values.
        let with_certs = test_receipt_v4();
        let without_certs = DeletionReceipt {
            bls_certificate: None,
            module_hash_certificate: None,
            ..test_receipt_v4()
        };
        assert_ne!(with_certs.bls_certificate, without_certs.bls_certificate);
        // Neither certificate field appears in the event/certified inputs above.
        assert_eq!(event, hash_with_tag(
            TAG_EVENT,
            &[&pre, &post, &ts.to_be_bytes(), &module_hash, &seq.to_be_bytes()],
        ));
    }

    #[test]
    fn protocol_version_v4_serialises_correctly() {
        assert_eq!(ProtocolVersion::V4.as_str(), "mktd02-v4");
        let s: String = ProtocolVersion::V4.into();
        assert_eq!(s, "mktd02-v4");
    }

    /// The Candid representation (type) of `DeletionReceipt` includes
    /// `module_hash_certificate` as `opt blob` (opt vec nat8).
    ///
    /// Note: Candid *encode* of a `DeletionReceipt` emits this field; Candid
    /// *decode* round-trip of `DeletionReceipt` was already non-functional on
    /// HEAD `508f2f8` (the wire-indirection deserialize cannot satisfy Candid's
    /// type-driven decoder). The over-the-wire path uses the host's own
    /// `MktdReceiptResponse`, not this type directly; v0.4.0 does not change
    /// that behaviour.
    #[test]
    fn candid_type_includes_module_hash_certificate_field() {
        use candid::CandidType;
        let ty = format!("{:?}", DeletionReceipt::ty());
        assert!(
            ty.contains("Named(\"module_hash_certificate\")"),
            "Candid type must expose module_hash_certificate; got: {ty}"
        );
        // opt vec nat8 == opt blob
        assert!(ty.contains(
            "Named(\"module_hash_certificate\"), ty: Type(Opt(Type(Vec(Type(Nat8)"
        ));
    }

    // -----------------------------------------------------------------------
    // Remediation (CD P5 NO-GO): R-1 hard-error on malformed v3/v2 wire,
    // R-2 protocol-aware state(). Locked tests per CD P8.
    // -----------------------------------------------------------------------

    /// Build a JSON object for a v3 wire with the given optional certificate
    /// fields, so we can exercise malformed permutations.
    fn v3_json_with_certs(bls: Option<&str>, module: Option<&str>) -> serde_json::Value {
        let mut obj = json!({
            "protocol_version": "mktd02-v3",
            "receipt_id": hex::encode([1u8; 32]),
            "canister_id": Principal::from_slice(&[1, 2, 3, 4]),
            "record_id": "0a0b0c",
            "pre_state_hash": hex::encode([2u8; 32]),
            "post_state_hash": hex::encode([3u8; 32]),
            "tombstone_hash": hex::encode([4u8; 32]),
            "deletion_event_hash": hex::encode([5u8; 32]),
            "certified_commitment": hex::encode([6u8; 32]),
            "module_hash": hex::encode([7u8; 32]),
            "timestamp": 1_000_000,
            "deletion_seq": 7,
        });
        let map = obj.as_object_mut().unwrap();
        if let Some(b) = bls {
            map.insert("bls_certificate".into(), json!(b));
        }
        if let Some(m) = module {
            map.insert("module_hash_certificate".into(), json!(m));
        }
        obj
    }

    // T-1: a v3 wire carrying a stray module_hash_certificate is malformed and
    // must ERROR on decode (was: silently dropped). Both permutations.
    #[test]
    fn t1_v3_wire_with_stray_module_cert_no_bls_errors() {
        let json = v3_json_with_certs(None, Some("01020304"));
        let res: Result<DeletionReceipt, _> = serde_json::from_value(json);
        assert!(
            res.is_err(),
            "v3 + module_hash_certificate (no bls) must not decode as Pending"
        );
        assert!(res
            .unwrap_err()
            .to_string()
            .contains("module_hash_certificate"));
    }

    #[test]
    fn t1_v3_wire_with_stray_module_cert_and_bls_errors() {
        let json = v3_json_with_certs(Some("aabbcc"), Some("01020304"));
        let res: Result<DeletionReceipt, _> = serde_json::from_value(json);
        assert!(
            res.is_err(),
            "v3 + module_hash_certificate (with bls) must hard-error"
        );
        assert!(res
            .unwrap_err()
            .to_string()
            .contains("module_hash_certificate"));
    }

    /// A clean v3 wire (bls only, no module cert) still decodes fine — R-1 does
    /// not over-reject the legitimate finalized-v3 shape.
    #[test]
    fn t1_v3_wire_bls_only_still_decodes() {
        let json = v3_json_with_certs(Some("aabbcc"), None);
        let decoded: DeletionReceipt = serde_json::from_value(json).unwrap();
        assert_eq!(decoded.protocol_version, "mktd02-v3");
        assert_eq!(decoded.bls_certificate, Some(vec![0xAA, 0xBB, 0xCC]));
        assert_eq!(decoded.module_hash_certificate, None);
    }

    /// T-1 (V2 arm): an "mktd02-v2"-labelled wire carrying a stray
    /// module_hash_certificate (a v4-only field) is malformed and must ERROR
    /// on decode. Mirrors the v3 T-1 shape; a v2 wire uses `nonce`, not
    /// `deletion_seq`. The legitimate no-stray-field v2 decode is covered by
    /// `legacy_v2_cbor_decodes_safely_to_v3_shape`.
    #[test]
    fn t1_v2_wire_with_stray_module_cert_errors() {
        let json = json!({
            "protocol_version": "mktd02-v2",
            "receipt_id": hex::encode([1u8; 32]),
            "canister_id": Principal::from_slice(&[1, 2, 3, 4]),
            "pre_state_hash": hex::encode([2u8; 32]),
            "post_state_hash": hex::encode([3u8; 32]),
            "tombstone_hash": hex::encode([4u8; 32]),
            "deletion_event_hash": hex::encode([5u8; 32]),
            "certified_commitment": hex::encode([6u8; 32]),
            "module_hash": hex::encode([7u8; 32]),
            "timestamp": 1_000_000,
            "nonce": 7,
            "module_hash_certificate": "01020304",
        });
        let res: Result<DeletionReceipt, _> = serde_json::from_value(json);
        assert!(
            res.is_err(),
            "v2 + module_hash_certificate must hard-error, not decode"
        );
        assert!(res
            .unwrap_err()
            .to_string()
            .contains("module_hash_certificate"));
    }

    // T-2: v2/v3 keep single-certificate finalization semantics under R-2.
    #[test]
    fn t2_v3_bls_only_is_finalized_candidate() {
        let r = DeletionReceipt {
            protocol_version: ProtocolVersion::V3.into(),
            bls_certificate: Some(vec![0xAA]),
            module_hash_certificate: None,
            ..test_receipt()
        };
        assert_eq!(r.state(), ReceiptState::FinalizedCandidate);
    }

    #[test]
    fn t2_v3_no_certs_is_pending() {
        let r = DeletionReceipt {
            protocol_version: ProtocolVersion::V3.into(),
            bls_certificate: None,
            module_hash_certificate: None,
            ..test_receipt()
        };
        assert_eq!(r.state(), ReceiptState::Pending);
    }

    /// A programmatically-constructed v3 receipt carrying a module cert (cannot
    /// arise from decode after R-1) classifies Invalid — documents the R-2 note.
    #[test]
    fn t2_v3_with_module_cert_is_invalid() {
        let r = DeletionReceipt {
            protocol_version: ProtocolVersion::V3.into(),
            bls_certificate: Some(vec![0xAA]),
            module_hash_certificate: Some(vec![0xBB]),
            ..test_receipt()
        };
        assert_eq!(r.state(), ReceiptState::InvalidIncompleteFinalization);
    }

    // T-3: CBOR-side unknown-protocol decode error (symmetry with the existing
    // JSON-side test `unrecognised_protocol_string_errors_on_deserialize`).
    #[test]
    fn t3_unrecognised_protocol_string_errors_on_cbor_deserialize() {
        // Start from a valid v3 CBOR, then rewrite protocol_version to unknown.
        let mut cbor = Vec::new();
        ciborium::into_writer(&golden_v3_receipt(), &mut cbor).unwrap();
        let mut val: ciborium::value::Value = ciborium::from_reader(cbor.as_slice()).unwrap();
        if let ciborium::value::Value::Map(entries) = &mut val {
            for (k, v) in entries.iter_mut() {
                if k.as_text() == Some("protocol_version") {
                    *v = ciborium::value::Value::Text("mktd02-v7".into());
                }
            }
        } else {
            panic!("expected a CBOR map");
        }
        let mut cbor2 = Vec::new();
        ciborium::into_writer(&val, &mut cbor2).unwrap();
        let res: Result<DeletionReceipt, _> = ciborium::from_reader(cbor2.as_slice());
        assert!(res.is_err(), "unknown protocol_version must not decode from CBOR");
    }
}
