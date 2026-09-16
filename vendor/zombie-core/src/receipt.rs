//! # CVDR (Cryptographically Verifiable Deletion Receipt)
//!
//! Receipt struct definition and `receipt_id` computation.
//! Domain tags:
//! - v2: `MKTD02_RECEIPT_V1`
//! - v3: `MKTD02_RECEIPT_V3`
//!
//! The receipt is an **unsigned artifact**. Verification relies on
//! the certified commitment obtained via ICP's certified query
//! mechanism, not a signature on the receipt itself. (v2–v4 only: mktd02-v5
//! retires the certified commitment — see v0.5.0 below.)
//!
//! ## v0.5.0 Changes (mktd02-v5, Direct Certification, SR-06)
//!
//! - [`DeletionReceiptV5`] is v5-only and has no `certified_commitment`
//!   (retired, no replacement field). A `mktd02-v5` receipt carrying that key
//!   fails to decode with `retired-field:certified_commitment`.
//! - The v2/v3/v4 receipt is frozen verbatim as [`DeletionReceiptV4`].
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

use crate::hashing::{
    hash_with_tag, TAG_EVENT, TAG_EVENT_V2, TAG_GENESIS, TAG_RECEIPT, TAG_RECEIPT_V3, ZERO_HASH,
};
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

    pub fn serialize_option_vec<S>(
        value: &Option<Vec<u8>>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
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

/// Serialisation helpers for the `mktd02-v5` wire types **only**
/// (ruling A-2(b), 12 Sep 2026).
///
/// Human-readable (JSON) output is identical to [`serde_hex_bytes`]:
/// lowercase hex, `null` for an absent optional. The non-human-readable
/// (CBOR) path differs — every byte-valued field is emitted as a CBOR
/// **byte string** (major type 2) instead of an array of integers.
///
/// Decode delegates to the shared visitors, so the tolerated input forms are
/// unchanged (byte string, hex text with optional `0x`, or a sequence of
/// integers); only the **emitted** form is narrowed.
///
/// [`DeletionReceiptV4`] and its wire/raw types keep using
/// [`serde_hex_bytes`], which this module does not modify: the v2–v4 wire is
/// frozen and must stay byte-identical.
mod serde_bytes_v5 {
    use super::serde_hex_bytes;
    use serde::{Deserializer, Serialize, Serializer};

    /// Emits a CBOR byte string for a borrowed slice.
    struct ByteStr<'a>(&'a [u8]);

    impl Serialize for ByteStr<'_> {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            serializer.serialize_bytes(self.0)
        }
    }

    pub fn serialize_array_32<S>(value: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            serializer.serialize_str(&hex::encode(value))
        } else {
            serializer.serialize_bytes(value)
        }
    }

    pub fn deserialize_array_32<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        serde_hex_bytes::deserialize_array_32(deserializer)
    }

    pub fn serialize_vec<S>(value: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            serializer.serialize_str(&hex::encode(value))
        } else {
            serializer.serialize_bytes(value)
        }
    }

    pub fn deserialize_vec<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        serde_hex_bytes::deserialize_vec(deserializer)
    }

    pub fn serialize_option_vec<S>(
        value: &Option<Vec<u8>>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match value {
            Some(bytes) if serializer.is_human_readable() => {
                serializer.serialize_some(&hex::encode(bytes))
            }
            Some(bytes) => serializer.serialize_some(&ByteStr(bytes)),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize_option_vec<'de, D>(deserializer: D) -> Result<Option<Vec<u8>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        serde_hex_bytes::deserialize_option_vec(deserializer)
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
    /// v0.5.0 format, Direct Certification (ruling SR-06): retires
    /// `certified_commitment` and its tag `MKTD02_CERTIFIED_V1`. The
    /// deletion-event hash binds `receipt_id`; the receipt-id preimage is
    /// unchanged.
    V5,
}

impl ProtocolVersion {
    pub fn as_str(&self) -> &'static str {
        match self {
            ProtocolVersion::V2 => "mktd02-v2",
            ProtocolVersion::V3 => "mktd02-v3",
            ProtocolVersion::V4 => "mktd02-v4",
            ProtocolVersion::V5 => "mktd02-v5",
        }
    }
}

/// Classify a wire `protocol_version` string into a known [`ProtocolVersion`].
///
/// `mktd02-v5` matches **exactly** (ruling 1b.7): `"mktd02-v5-x"`,
/// `"mktd02-v50"` and `"mktd02-v5 "` are unrecognised.
///
/// The frozen v2/v3/v4 arms use `starts_with` for parity with the historical
/// dispatch, so a suffixed string (e.g. `"mktd02-v4-rc1"`) still classifies.
/// Returns `None` for any unrecognised string — callers MUST treat `None` as a
/// hard error and never fall back to a legacy wire shape.
fn classify_protocol(protocol_version: &str) -> Option<ProtocolVersion> {
    if protocol_version == ProtocolVersion::V5.as_str() {
        Some(ProtocolVersion::V5)
    } else if protocol_version.starts_with("mktd02-v4") {
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
///
/// Scope: the three-state rule applies to **v4** ([`DeletionReceiptV4::state`],
/// unchanged) and, explicitly, to **v5** ([`DeletionReceiptV5::state`], SR-06
/// slice 1). v2/v3 keep single-certificate semantics.
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
// Deletion Receipt — v2/v3/v4 (frozen)
// ---------------------------------------------------------------------------

// Serialisation is version-dispatched, not derived:
// - `Serialize` is a manual impl (below) so an unrecognised `protocol_version`
//   is a HARD ERROR, never a silent fallback to a legacy wire shape.
// - `Deserialize` decodes a tolerant superset (`DeletionReceiptRawWire`) then
//   validates + dispatches via `TryFrom`, which also hard-errors on an
//   unrecognised `protocol_version`.
/// Deletion receipt covering protocol_version v2, v3 and v4 (frozen by
/// ruling, 11 Sep 2026).
///
/// Carries `certified_commitment`, retired for mktd02-v5 by SR-06. Kept
/// verbatim so issued v2–v4 receipts stay permanently verifiable: decode,
/// serialise and `state()` are byte-identical to v0.4.1. A `mktd02-v5`
/// receipt is refused here; use [`DeletionReceiptV5`].
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, CandidType)]
#[serde(try_from = "DeletionReceiptRawWire")]
pub struct DeletionReceiptV4 {
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

impl DeletionReceiptV4 {
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
            // mktd02-v5 is not a protocol of this (certified_commitment-bearing)
            // type; classified exactly as an unrecognised string was pre-v5.
            Some(ProtocolVersion::V5) | None => ReceiptState::InvalidIncompleteFinalization,
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

impl From<&DeletionReceiptV4> for ReceiptSummary {
    fn from(r: &DeletionReceiptV4) -> Self {
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

impl From<&DeletionReceiptV5> for ReceiptSummary {
    fn from(r: &DeletionReceiptV5) -> Self {
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

/// Compute the `mktd02-v5` deletion-event hash (ruling A-1(a), 12 Sep 2026).
///
/// ```text
/// deletion_event_hash = SHA-256(
///   MKTD02_EVENT_V2 ||
///   pre_state_hash || post_state_hash || receipt_id ||
///   u64_be(timestamp) || module_hash || u64_be(deletion_seq)
/// )
/// ```
///
/// `receipt_id` is [`compute_receipt_id`]'s value and must be computed
/// **first**: a verifier recomputes it from `(canister_id, record_id,
/// deletion_seq)` and equality-checks it against the receipt's field before
/// recomputing this hash.
///
/// `deletion_seq` is an explicit operand as well as being bound inside
/// `receipt_id`. The redundancy is intentional.
///
/// `manifest_hash` is not in the preimage and must never be added to it.
///
/// This is the **single normative implementation** of the v5 construction:
/// consumers (including the engine) call it rather than rebuilding the
/// preimage. The v2–v4 construction is [`deletion_event_hash_v1`] and uses a
/// different tag, so the two can never collide over identical operands.
pub fn deletion_event_hash_v5(
    pre_state_hash: &[u8; 32],
    post_state_hash: &[u8; 32],
    receipt_id: &[u8; 32],
    timestamp: u64,
    module_hash: &[u8; 32],
    deletion_seq: u64,
) -> [u8; 32] {
    hash_with_tag(
        TAG_EVENT_V2,
        &[
            pre_state_hash,
            post_state_hash,
            receipt_id,
            &timestamp.to_be_bytes(),
            module_hash,
            &deletion_seq.to_be_bytes(),
        ],
    )
}

/// Compute the historical (`mktd02-v2`, `-v3`, `-v4`) deletion-event hash.
///
/// ```text
/// deletion_event_hash = SHA-256(
///   MKTD02_EVENT_V1 ||
///   pre_state_hash || post_state_hash ||
///   u64_be(timestamp) || module_hash || u64_be(deletion_seq)
/// )
/// ```
///
/// Five parts, no `receipt_id`. Exposed so that recomputing an
/// already-issued v2–v4 receipt never requires reimplementing the preimage
/// downstream. **Never** use it to produce a `mktd02-v5` value — v5 is
/// [`deletion_event_hash_v5`].
///
/// `manifest_hash` was removed from this preimage at v0.2.0 and must never
/// be added back.
pub fn deletion_event_hash_v1(
    pre_state_hash: &[u8; 32],
    post_state_hash: &[u8; 32],
    timestamp: u64,
    module_hash: &[u8; 32],
    deletion_seq: u64,
) -> [u8; 32] {
    hash_with_tag(
        TAG_EVENT,
        &[
            pre_state_hash,
            post_state_hash,
            &timestamp.to_be_bytes(),
            module_hash,
            &deletion_seq.to_be_bytes(),
        ],
    )
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
/// `protocol_version` and maps fields to the canonical [`DeletionReceiptV4`].
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

impl TryFrom<DeletionReceiptRawWire> for DeletionReceiptV4 {
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
                Ok(DeletionReceiptV4 {
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
                Ok(DeletionReceiptV4 {
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
            // mktd02-v5 is refused exactly as an unrecognised string was pre-v5.
            Some(ProtocolVersion::V5) | None => Err(format!(
                "DeletionReceipt: unrecognised protocol_version {:?}; \
                 refusing to decode (no silent legacy fallback)",
                w.protocol_version
            )),
        }
    }
}

impl Serialize for DeletionReceiptV4 {
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
            // mktd02-v5 is refused exactly as an unrecognised string was pre-v5.
            Some(ProtocolVersion::V5) | None => Err(S::Error::custom(format!(
                "DeletionReceipt: unrecognised protocol_version {:?}; \
                 refusing to serialise (no silent legacy fallback)",
                self.protocol_version
            ))),
        }
    }
}

// ---------------------------------------------------------------------------
// Deletion Receipt — mktd02-v5 (Direct Certification, SR-06)
// ---------------------------------------------------------------------------

/// Named decode rejection (SR-06): a `mktd02-v5` receipt carries the retired
/// `certified_commitment` key.
pub const ERR_RETIRED_FIELD_CERTIFIED_COMMITMENT: &str = "retired-field:certified_commitment";

/// Named decode rejection: a `mktd02-v5` receipt's `deletion_event_hash` is
/// all-zero.
pub const ERR_INVALID_EVENT_HASH_ZERO: &str = "invalid-event-hash:zero";

/// Named verifier rejection: a certificate's certified_data equals the
/// canister's genesis value, i.e. no deletion has been certified.
pub const ERR_NO_DELETION_CERTIFIED: &str = "no-deletion-certified";

/// mktd02-v5 genesis certified_data for `canister_id`:
/// `SHA-256(MKTD02_GENESIS_V1 || canister_id_bytes)`.
///
/// Preimage (ruled 11 Sep 2026): tag ‖ raw principal bytes
/// (`Principal::as_slice()`), with **no length prefix**.
///
/// **Verifier-side helper only** — not used in receipt construction.
pub fn genesis_certified_data(canister_id: &Principal) -> [u8; 32] {
    hash_with_tag(TAG_GENESIS, &[canister_id.as_slice()])
}

/// Verifier-side check: reject `certified_data` (as extracted from a
/// certificate by the caller) that equals the canister's genesis value.
pub fn check_certified_data_not_genesis(
    canister_id: &Principal,
    certified_data: &[u8],
) -> Result<(), &'static str> {
    if certified_data == genesis_certified_data(canister_id) {
        Err(ERR_NO_DELETION_CERTIFIED)
    } else {
        Ok(())
    }
}

/// Named verifier rejection (spec §7): the recomputed `receipt_id` differs
/// from the receipt's. First V1 step.
pub const ERR_V1_RECEIPT_ID_MISMATCH: &str = "v1:receipt-id-mismatch";

/// Named verifier rejection (spec §7): the recomputed `deletion_event_hash`
/// differs from the receipt's. Evaluated only after `receipt_id` passes.
pub const ERR_V1_EVENT_HASH_MISMATCH: &str = "v1:event-hash-mismatch";

/// The v5 V1 consistency check (spec §3.4, §7), in the ratified order:
/// [`verify_v1_receipt_id`], then — only if it passes —
/// [`verify_v1_event_hash`] over the checked `receipt_id`.
///
/// This is the **single normative implementation** of V1; verifiers call it
/// rather than composing the steps themselves.
pub fn verify_v1(receipt: &DeletionReceiptV5) -> Result<(), &'static str> {
    verify_v1_receipt_id(receipt)?;
    verify_v1_event_hash(receipt)
}

/// V1 step 1 (spec §3.5, §7): recompute `receipt_id` from
/// `(canister_id, record_id, deletion_seq)` and equality-check it against
/// the receipt, else [`ERR_V1_RECEIPT_ID_MISMATCH`].
pub fn verify_v1_receipt_id(receipt: &DeletionReceiptV5) -> Result<(), &'static str> {
    let recomputed = compute_receipt_id(
        &receipt.canister_id,
        &receipt.record_id,
        receipt.deletion_seq,
    );
    if recomputed == receipt.receipt_id {
        Ok(())
    } else {
        Err(ERR_V1_RECEIPT_ID_MISMATCH)
    }
}

/// V1 step 2 (spec §3.4, §7): recompute `deletion_event_hash` from the
/// receipt's fields, including its `receipt_id`, and equality-check it, else
/// [`ERR_V1_EVENT_HASH_MISMATCH`].
///
/// Assumes `receipt_id` has already been checked; verifiers call
/// [`verify_v1`].
pub fn verify_v1_event_hash(receipt: &DeletionReceiptV5) -> Result<(), &'static str> {
    let recomputed = deletion_event_hash_v5(
        &receipt.pre_state_hash,
        &receipt.post_state_hash,
        &receipt.receipt_id,
        receipt.timestamp,
        &receipt.module_hash,
        receipt.deletion_seq,
    );
    if recomputed == receipt.deletion_event_hash {
        Ok(())
    } else {
        Err(ERR_V1_EVENT_HASH_MISMATCH)
    }
}

// Same version-dispatched pattern as `DeletionReceiptV4`:
// - `Serialize` is manual and hard-errors on any non-v5 `protocol_version`.
// - `Deserialize` decodes `DeletionReceiptV5RawWire`, then validates via
//   `TryFrom` (non-v5 label, retired key, and missing fields all hard-error).
/// mktd02-v5 deletion receipt (Direct Certification, ruling SR-06).
///
/// v5 only. The fields of [`DeletionReceiptV4`] minus `certified_commitment`,
/// which is retired with no replacement field. Decode v2/v3/v4 receipts as
/// [`DeletionReceiptV4`]; they are refused here.
///
/// Decode is fail-closed (ruling 1d). A key outside the v5 schema (e.g.
/// `nonce`, `subnet_id`) is a hard error, so no unauthenticated data rides
/// alongside a v5 receipt. The retired `certified_commitment` key is still
/// rejected by name (`retired-field:certified_commitment`), never as a generic
/// unknown key. Structural serde errors (unknown key, bad hex, missing required
/// field) are reported before the named checks (protocol, retired-field,
/// zero-hash). That order is expected behaviour.
///
/// There is deliberately no unversioned `DeletionReceipt` (no alias, no shim):
///
/// ```compile_fail,E0432
/// use zombie_core::DeletionReceipt;
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, CandidType)]
#[serde(try_from = "DeletionReceiptV5RawWire")]
pub struct DeletionReceiptV5 {
    /// Protocol version string: `"mktd02-v5"`.
    pub protocol_version: String,
    pub receipt_id: [u8; 32],
    pub canister_id: Principal,
    /// The deleted subject principal bytes (MKTd02 leaf mode).
    pub record_id: Vec<u8>,
    pub pre_state_hash: [u8; 32],
    pub post_state_hash: [u8; 32],
    pub tombstone_hash: [u8; 32],
    pub deletion_event_hash: [u8; 32],
    pub module_hash: [u8; 32],
    pub timestamp: u64,
    pub deletion_seq: u64,
    /// Raw BLS certificate blob from ic0.data_certificate().
    /// None while receipt is pending finalization; Some after finalization.
    pub bls_certificate: Option<Vec<u8>>,
    /// Identifies the NNS root key used to sign the BLS certificate; see
    /// `zombie_core::nns_keys::lookup_key(id)`. Empty for pending receipts.
    pub trust_root_key_id: String,
    /// Raw certificate blob from a `read_state` over
    /// `/canister/<id>/module_hash`. `None` until the helper attaches it.
    pub module_hash_certificate: Option<Vec<u8>>,
}

impl DeletionReceiptV5 {
    /// Classify this receipt by certificate completeness: the v4 three-state
    /// rule, extended explicitly to v5 (SR-06 slice 1).
    ///
    /// - **v5**: neither certificate → `Pending`; both → `FinalizedCandidate`;
    ///   exactly one → `InvalidIncompleteFinalization`.
    /// - Any other `protocol_version` (cannot arise from decode; only from
    ///   programmatic construction) → `InvalidIncompleteFinalization`.
    pub fn state(&self) -> ReceiptState {
        let bls = self.bls_certificate.is_some();
        let module = self.module_hash_certificate.is_some();
        match classify_protocol(&self.protocol_version) {
            Some(ProtocolVersion::V5) => match (bls, module) {
                (false, false) => ReceiptState::Pending,
                (true, true) => ReceiptState::FinalizedCandidate,
                _ => ReceiptState::InvalidIncompleteFinalization,
            },
            _ => ReceiptState::InvalidIncompleteFinalization,
        }
    }
}

/// v5 wire shape: [`DeletionReceiptV4Wire`] without `certified_commitment`.
///
/// Byte-valued fields serialise through [`serde_bytes_v5`], so CBOR carries
/// them as byte strings (ruling A-2(b)); JSON is unchanged.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct DeletionReceiptV5Wire {
    protocol_version: String,
    #[serde(serialize_with = "serde_bytes_v5::serialize_array_32")]
    receipt_id: [u8; 32],
    canister_id: Principal,
    #[serde(serialize_with = "serde_bytes_v5::serialize_vec")]
    record_id: Vec<u8>,
    #[serde(serialize_with = "serde_bytes_v5::serialize_array_32")]
    pre_state_hash: [u8; 32],
    #[serde(serialize_with = "serde_bytes_v5::serialize_array_32")]
    post_state_hash: [u8; 32],
    #[serde(serialize_with = "serde_bytes_v5::serialize_array_32")]
    tombstone_hash: [u8; 32],
    #[serde(serialize_with = "serde_bytes_v5::serialize_array_32")]
    deletion_event_hash: [u8; 32],
    #[serde(serialize_with = "serde_bytes_v5::serialize_array_32")]
    module_hash: [u8; 32],
    timestamp: u64,
    deletion_seq: u64,
    #[serde(serialize_with = "serde_bytes_v5::serialize_option_vec")]
    bls_certificate: Option<Vec<u8>>,
    trust_root_key_id: String,
    #[serde(serialize_with = "serde_bytes_v5::serialize_option_vec")]
    module_hash_certificate: Option<Vec<u8>>,
}

/// Read-side shape for [`DeletionReceiptV5`].
///
/// `record_id` / `deletion_seq` are optional here only so a v2 label reaches
/// the protocol check (and its named error) before a missing-field error;
/// [`TryFrom`] requires both. `certified_commitment` is captured as key
/// presence only (any value, including null), so the retired key is rejected
/// by name, never silently dropped (R-1). It stays a declared field so that
/// `deny_unknown_fields` (ruling 1d) does not preempt its named error. Any
/// other undeclared key is a hard error.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeletionReceiptV5RawWire {
    protocol_version: String,
    #[serde(deserialize_with = "serde_bytes_v5::deserialize_array_32")]
    receipt_id: [u8; 32],
    canister_id: Principal,
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_some_vec")]
    record_id: Option<Vec<u8>>,
    #[serde(deserialize_with = "serde_bytes_v5::deserialize_array_32")]
    pre_state_hash: [u8; 32],
    #[serde(deserialize_with = "serde_bytes_v5::deserialize_array_32")]
    post_state_hash: [u8; 32],
    #[serde(deserialize_with = "serde_bytes_v5::deserialize_array_32")]
    tombstone_hash: [u8; 32],
    #[serde(deserialize_with = "serde_bytes_v5::deserialize_array_32")]
    deletion_event_hash: [u8; 32],
    #[serde(deserialize_with = "serde_bytes_v5::deserialize_array_32")]
    module_hash: [u8; 32],
    timestamp: u64,
    #[serde(default)]
    deletion_seq: Option<u64>,
    #[serde(default)]
    #[serde(deserialize_with = "serde_bytes_v5::deserialize_option_vec")]
    bls_certificate: Option<Vec<u8>>,
    #[serde(default)]
    trust_root_key_id: String,
    #[serde(default)]
    #[serde(deserialize_with = "serde_bytes_v5::deserialize_option_vec")]
    module_hash_certificate: Option<Vec<u8>>,
    /// Retired by SR-06: key presence only.
    #[serde(default, rename = "certified_commitment")]
    #[serde(deserialize_with = "deserialize_key_present")]
    certified_commitment_present: bool,
}

/// `deserialize_with` helper: a present key (byte string, hex text, or a
/// sequence of integers) becomes `Some`.
fn deserialize_some_vec<'de, D>(deserializer: D) -> Result<Option<Vec<u8>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    serde_bytes_v5::deserialize_vec(deserializer).map(Some)
}

/// `deserialize_with` helper: records that a key was present, whatever its
/// value (the value itself is discarded unparsed).
fn deserialize_key_present<'de, D>(deserializer: D) -> Result<bool, D::Error>
where
    D: serde::Deserializer<'de>,
{
    serde::de::IgnoredAny::deserialize(deserializer).map(|_| true)
}

impl TryFrom<DeletionReceiptV5RawWire> for DeletionReceiptV5 {
    type Error = String;

    fn try_from(w: DeletionReceiptV5RawWire) -> Result<Self, Self::Error> {
        match classify_protocol(&w.protocol_version) {
            Some(ProtocolVersion::V5) => {}
            Some(_) => {
                return Err(format!(
                    "DeletionReceiptV5: {:?} is not a mktd02-v5 receipt; \
                     decode v2/v3/v4 receipts as DeletionReceiptV4",
                    w.protocol_version
                ))
            }
            None => {
                return Err(format!(
                    "DeletionReceiptV5: unrecognised protocol_version {:?}; \
                     refusing to decode",
                    w.protocol_version
                ))
            }
        }
        if w.certified_commitment_present {
            return Err(ERR_RETIRED_FIELD_CERTIFIED_COMMITMENT.to_string());
        }
        if w.deletion_event_hash == ZERO_HASH {
            return Err(ERR_INVALID_EVENT_HASH_ZERO.to_string());
        }
        let record_id = w.record_id.ok_or_else(|| {
            format!(
                "DeletionReceiptV5: {} receipt missing record_id",
                w.protocol_version
            )
        })?;
        let deletion_seq = w.deletion_seq.ok_or_else(|| {
            format!(
                "DeletionReceiptV5: {} receipt missing deletion_seq",
                w.protocol_version
            )
        })?;
        Ok(DeletionReceiptV5 {
            protocol_version: w.protocol_version,
            receipt_id: w.receipt_id,
            canister_id: w.canister_id,
            record_id,
            pre_state_hash: w.pre_state_hash,
            post_state_hash: w.post_state_hash,
            tombstone_hash: w.tombstone_hash,
            deletion_event_hash: w.deletion_event_hash,
            module_hash: w.module_hash,
            timestamp: w.timestamp,
            deletion_seq,
            bls_certificate: w.bls_certificate,
            trust_root_key_id: w.trust_root_key_id,
            module_hash_certificate: w.module_hash_certificate,
        })
    }
}

impl Serialize for DeletionReceiptV5 {
    /// Emits the v5 wire shape for a `mktd02-v5` receipt and a hard error for
    /// any other `protocol_version` (no silent reshape into another line).
    /// An all-zero `deletion_event_hash` is refused with
    /// `invalid-event-hash:zero`, symmetric with decode.
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match classify_protocol(&self.protocol_version) {
            Some(ProtocolVersion::V5) if self.deletion_event_hash == ZERO_HASH => {
                Err(S::Error::custom(ERR_INVALID_EVENT_HASH_ZERO))
            }
            Some(ProtocolVersion::V5) => DeletionReceiptV5Wire {
                protocol_version: self.protocol_version.clone(),
                receipt_id: self.receipt_id,
                canister_id: self.canister_id,
                record_id: self.record_id.clone(),
                pre_state_hash: self.pre_state_hash,
                post_state_hash: self.post_state_hash,
                tombstone_hash: self.tombstone_hash,
                deletion_event_hash: self.deletion_event_hash,
                module_hash: self.module_hash,
                timestamp: self.timestamp,
                deletion_seq: self.deletion_seq,
                bls_certificate: self.bls_certificate.clone(),
                trust_root_key_id: self.trust_root_key_id.clone(),
                module_hash_certificate: self.module_hash_certificate.clone(),
            }
            .serialize(serializer),
            // Classified like decode: a near-miss carries the frozen §7
            // fragment; a wrong-line label keeps its own wording.
            Some(_) => Err(S::Error::custom(format!(
                "DeletionReceiptV5: protocol_version {:?} is not mktd02-v5; \
                 refusing to serialise",
                self.protocol_version
            ))),
            None => Err(S::Error::custom(format!(
                "DeletionReceiptV5: unrecognised protocol_version {:?}; \
                 refusing to serialise",
                self.protocol_version
            ))),
        }
    }
}

// ---------------------------------------------------------------------------
// Version-dispatching decode (ruling 1b.3)
// ---------------------------------------------------------------------------

/// A decoded receipt of any supported protocol line.
///
/// The constructors read `protocol_version` first, then decode with exactly one
/// versioned type's own decoder, so that type's named errors (e.g.
/// `retired-field:certified_commitment`) surface unchanged. An unrecognised
/// label hard-errors; there is no fallback.
///
/// A `mktd02-v5` receipt is decoded fail-closed (ruling 1d): an unknown key
/// is a hard error, so no unauthenticated data rides alongside a v5 receipt.
/// `certified_commitment` is still rejected by name. Structural serde errors
/// (unknown key, bad hex, missing required field) are reported before the
/// named checks (protocol, retired-field, zero-hash), which is expected
/// behaviour. v2–v4 decode is unchanged and still tolerates unknown keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnyDeletionReceipt {
    /// `mktd02-v2`, `mktd02-v3`, `mktd02-v4`.
    V4(DeletionReceiptV4),
    /// `mktd02-v5`.
    V5(DeletionReceiptV5),
}

/// Reads only `protocol_version`; every other key is ignored.
#[derive(Deserialize)]
struct ProtocolProbe {
    protocol_version: String,
}

/// Which versioned type decodes `protocol_version`, or the hard error.
fn dispatch_line(protocol_version: &str) -> Result<ProtocolVersion, String> {
    classify_protocol(protocol_version).ok_or_else(|| {
        format!(
            "AnyDeletionReceipt: unrecognised protocol_version {:?}; \
             refusing to decode (no silent legacy fallback)",
            protocol_version
        )
    })
}

impl AnyDeletionReceipt {
    /// Decode from a JSON value, e.g. a `serde_json::Value`.
    ///
    /// Generic over any owned self-describing value so that zombie-core takes
    /// no runtime `serde_json` dependency. Errors are the versioned type's own
    /// decode errors, stringified.
    pub fn from_json_value<V>(value: V) -> Result<Self, String>
    where
        V: Clone + for<'de> serde::Deserializer<'de>,
    {
        let probe = ProtocolProbe::deserialize(value.clone())
            .map_err(|e| format!("AnyDeletionReceipt: {e}"))?;
        match dispatch_line(&probe.protocol_version)? {
            ProtocolVersion::V5 => DeletionReceiptV5::deserialize(value)
                .map(AnyDeletionReceipt::V5)
                .map_err(|e| e.to_string()),
            ProtocolVersion::V2 | ProtocolVersion::V3 | ProtocolVersion::V4 => {
                DeletionReceiptV4::deserialize(value)
                    .map(AnyDeletionReceipt::V4)
                    .map_err(|e| e.to_string())
            }
        }
    }

    /// Decode from CBOR bytes. Errors are the versioned type's own decode
    /// errors (as from `ciborium::from_reader`), stringified.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, String> {
        let probe: ProtocolProbe =
            ciborium::from_reader(bytes).map_err(|e| format!("AnyDeletionReceipt: {e}"))?;
        match dispatch_line(&probe.protocol_version)? {
            ProtocolVersion::V5 => ciborium::from_reader::<DeletionReceiptV5, _>(bytes)
                .map(AnyDeletionReceipt::V5)
                .map_err(|e| e.to_string()),
            ProtocolVersion::V2 | ProtocolVersion::V3 | ProtocolVersion::V4 => {
                ciborium::from_reader::<DeletionReceiptV4, _>(bytes)
                    .map(AnyDeletionReceipt::V4)
                    .map_err(|e| e.to_string())
            }
        }
    }

    pub fn protocol_version(&self) -> &str {
        match self {
            AnyDeletionReceipt::V4(r) => &r.protocol_version,
            AnyDeletionReceipt::V5(r) => &r.protocol_version,
        }
    }

    pub fn receipt_id(&self) -> [u8; 32] {
        match self {
            AnyDeletionReceipt::V4(r) => r.receipt_id,
            AnyDeletionReceipt::V5(r) => r.receipt_id,
        }
    }

    /// The versioned type's own classification (v4 rule unchanged; v5 rule).
    pub fn state(&self) -> ReceiptState {
        match self {
            AnyDeletionReceipt::V4(r) => r.state(),
            AnyDeletionReceipt::V5(r) => r.state(),
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

    fn test_receipt() -> DeletionReceiptV4 {
        DeletionReceiptV4 {
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
    fn test_receipt_v4() -> DeletionReceiptV4 {
        DeletionReceiptV4 {
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
        let r = DeletionReceiptV4 {
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
        let decoded: DeletionReceiptV4 = ciborium::from_reader(buf.as_slice()).unwrap();

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
        let decoded: DeletionReceiptV4 = ciborium::from_reader(buf.as_slice()).unwrap();

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
        assert_eq!(
            value["module_hash"],
            json!(hex::encode(receipt.module_hash))
        );
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

        let decoded: DeletionReceiptV4 = serde_json::from_value(json_value).unwrap();
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
    fn golden_v3_receipt() -> DeletionReceiptV4 {
        DeletionReceiptV4 {
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
        let decoded: DeletionReceiptV4 = ciborium::from_reader(cbor.as_slice()).unwrap();
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
        let decoded: DeletionReceiptV4 = serde_json::from_str(&json).unwrap();
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
        let decoded: DeletionReceiptV4 = serde_json::from_value(json).unwrap();
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
        let decoded: DeletionReceiptV4 = ciborium::from_reader(cbor.as_slice()).unwrap();
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
        // Not a v2–v4 line: v5 belongs to DeletionReceiptV5, so the frozen
        // v4 type refuses it.
        bad.protocol_version = "mktd02-v5".into();
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
            json_res
                .unwrap_err()
                .to_string()
                .contains("unrecognised protocol_version"),
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
        assert!(
            cbor.is_empty()
                || ciborium::from_reader::<DeletionReceiptV4, _>(cbor.as_slice()).is_err()
        );
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
        let res: Result<DeletionReceiptV4, _> = serde_json::from_value(json);
        assert!(res.is_err(), "unknown protocol_version must not decode");
        assert!(res
            .unwrap_err()
            .to_string()
            .contains("unrecognised protocol_version"));
    }

    // --- three-state classification (both single-cert permutations) ---------

    #[test]
    fn state_pending_when_neither_certificate_present() {
        let r = DeletionReceiptV4 {
            protocol_version: ProtocolVersion::V4.into(),
            bls_certificate: None,
            module_hash_certificate: None,
            ..test_receipt()
        };
        assert_eq!(r.state(), ReceiptState::Pending);
    }

    #[test]
    fn state_finalized_candidate_when_both_certificates_present() {
        let r = DeletionReceiptV4 {
            protocol_version: ProtocolVersion::V4.into(),
            bls_certificate: Some(vec![0xAA]),
            module_hash_certificate: Some(vec![0xBB]),
            ..test_receipt()
        };
        assert_eq!(r.state(), ReceiptState::FinalizedCandidate);
    }

    #[test]
    fn state_invalid_when_only_bls_certificate_present() {
        let r = DeletionReceiptV4 {
            protocol_version: ProtocolVersion::V4.into(),
            bls_certificate: Some(vec![0xAA]),
            module_hash_certificate: None,
            ..test_receipt()
        };
        assert_eq!(r.state(), ReceiptState::InvalidIncompleteFinalization);
    }

    #[test]
    fn state_invalid_when_only_module_hash_certificate_present() {
        let r = DeletionReceiptV4 {
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
        let absent = DeletionReceiptV4 {
            bls_certificate: None,
            module_hash_certificate: None,
            ..golden_v3_receipt()
        };
        let present = DeletionReceiptV4 {
            protocol_version: ProtocolVersion::V4.into(),
            bls_certificate: Some(vec![0xAA, 0xBB, 0xCC]),
            module_hash_certificate: Some(vec![0x01, 0x02, 0x03, 0x04]),
            ..golden_v3_receipt()
        };
        let id_absent =
            compute_receipt_id(&absent.canister_id, &absent.record_id, absent.deletion_seq);
        let id_present = compute_receipt_id(
            &present.canister_id,
            &present.record_id,
            present.deletion_seq,
        );
        assert_eq!(
            id_absent, id_present,
            "receipt_id must be certificate-independent"
        );
        assert_eq!(
            hex::encode(id_present),
            "231bca0d2351bb588bae612eab8ea46810097294dcd98cfbc4ae3045fdced09d",
            "receipt_id derivation changed — breaks v3/v4 receipts"
        );
    }

    #[test]
    fn protocol_version_v4_serialises_correctly() {
        assert_eq!(ProtocolVersion::V4.as_str(), "mktd02-v4");
        let s: String = ProtocolVersion::V4.into();
        assert_eq!(s, "mktd02-v4");
    }

    /// The Candid representation (type) of `DeletionReceiptV4` includes
    /// `module_hash_certificate` as `opt blob` (opt vec nat8).
    ///
    /// Note: Candid *encode* of a `DeletionReceiptV4` emits this field; Candid
    /// *decode* round-trip of `DeletionReceiptV4` was already non-functional on
    /// HEAD `508f2f8` (the wire-indirection deserialize cannot satisfy Candid's
    /// type-driven decoder). The over-the-wire path uses the host's own
    /// `MktdReceiptResponse`, not this type directly; v0.4.0 does not change
    /// that behaviour.
    #[test]
    fn candid_type_includes_module_hash_certificate_field() {
        use candid::CandidType;
        let ty = format!("{:?}", DeletionReceiptV4::ty());
        assert!(
            ty.contains("Named(\"module_hash_certificate\")"),
            "Candid type must expose module_hash_certificate; got: {ty}"
        );
        // opt vec nat8 == opt blob
        assert!(ty.contains("Named(\"module_hash_certificate\"), ty: Type(Opt(Type(Vec(Type(Nat8)"));
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
        let res: Result<DeletionReceiptV4, _> = serde_json::from_value(json);
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
        let res: Result<DeletionReceiptV4, _> = serde_json::from_value(json);
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
        let decoded: DeletionReceiptV4 = serde_json::from_value(json).unwrap();
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
        let res: Result<DeletionReceiptV4, _> = serde_json::from_value(json);
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
        let r = DeletionReceiptV4 {
            protocol_version: ProtocolVersion::V3.into(),
            bls_certificate: Some(vec![0xAA]),
            module_hash_certificate: None,
            ..test_receipt()
        };
        assert_eq!(r.state(), ReceiptState::FinalizedCandidate);
    }

    #[test]
    fn t2_v3_no_certs_is_pending() {
        let r = DeletionReceiptV4 {
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
        let r = DeletionReceiptV4 {
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
        let res: Result<DeletionReceiptV4, _> = ciborium::from_reader(cbor2.as_slice());
        assert!(
            res.is_err(),
            "unknown protocol_version must not decode from CBOR"
        );
    }

    // -----------------------------------------------------------------------
    // v0.5.0 — mktd02-v5, Direct Certification (MKTd02 v5 Slice 1, SR-06).
    // Construction-level assertions only; no v5 golden digests (slice 3).
    // -----------------------------------------------------------------------

    // 3.3: protocol version.
    #[test]
    fn protocol_version_v5_serialises_correctly() {
        assert_eq!(ProtocolVersion::V5.as_str(), "mktd02-v5");
        let s: String = ProtocolVersion::V5.into();
        assert_eq!(s, "mktd02-v5");
        assert_eq!(format!("{}", ProtocolVersion::V5), "mktd02-v5");
        assert_eq!(classify_protocol("mktd02-v5"), Some(ProtocolVersion::V5));
    }

    // 1b.7: the v5 arm matches exactly.
    const NEAR_V5_LABELS: [&str; 3] = ["mktd02-v5-x", "mktd02-v50", "mktd02-v5 "];

    #[test]
    fn t1b7_classify_v5_is_exact() {
        assert_eq!(classify_protocol("mktd02-v5"), Some(ProtocolVersion::V5));
        for label in NEAR_V5_LABELS {
            assert_eq!(classify_protocol(label), None, "{label:?}");
        }
    }

    /// Near-v5 labels hard-error on every v5 path: decode, serialise, dispatch.
    #[test]
    fn t1b7_near_v5_labels_hard_error() {
        for label in NEAR_V5_LABELS {
            let r = DeletionReceiptV5 {
                protocol_version: label.into(),
                ..test_receipt_v5()
            };
            assert!(serde_json::to_string(&r).is_err(), "{label:?}");
            let mut json = serde_json::to_value(test_receipt_v5()).unwrap();
            json["protocol_version"] = json!(label);
            let err = serde_json::from_value::<DeletionReceiptV5>(json.clone())
                .unwrap_err()
                .to_string();
            assert!(err.contains("unrecognised protocol_version"), "{err}");
            let err = AnyDeletionReceipt::from_json_value(json).unwrap_err();
            assert!(err.contains("unrecognised protocol_version"), "{err}");
            let bytes = v5_cbor_with(
                "protocol_version",
                ciborium::value::Value::Text(label.into()),
            );
            let err = AnyDeletionReceipt::from_cbor(&bytes).unwrap_err();
            assert!(err.contains("unrecognised protocol_version"), "{err}");
        }
    }

    /// The frozen v2/v3/v4 prefix arms are unchanged by 1b.7 (see slice1_notes
    /// "Slice 6 candidates"): the documented suffixed example still classifies.
    #[test]
    fn t1b7_frozen_v4_prefix_arm_unchanged() {
        assert_eq!(
            classify_protocol("mktd02-v4-rc1"),
            Some(ProtocolVersion::V4)
        );
    }

    /// 3.3: the certified_commitment-bearing type treats a v5 label exactly as
    /// it treated that (then-unrecognised) string before v5 existed.
    #[test]
    fn v5_label_on_cc_bearing_type_behaves_as_before_v5() {
        let mut r = golden_v3_receipt();
        r.protocol_version = ProtocolVersion::V5.into();
        assert_eq!(r.state(), ReceiptState::InvalidIncompleteFinalization);
        let json_err = serde_json::to_string(&r).unwrap_err().to_string();
        assert!(json_err.contains("unrecognised protocol_version"));
        let mut v = serde_json::to_value(golden_v3_receipt()).unwrap();
        v["protocol_version"] = json!("mktd02-v5");
        let res: Result<DeletionReceiptV4, _> = serde_json::from_value(v);
        assert!(res
            .unwrap_err()
            .to_string()
            .contains("unrecognised protocol_version"));
    }

    // 3.2: receipt schema — v5-only DeletionReceiptV5, no certified_commitment.

    /// A finalized v5 receipt: both certificates present.
    fn test_receipt_v5() -> DeletionReceiptV5 {
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
            module_hash_certificate: Some(vec![0x01, 0x02, 0x03, 0x04]),
        }
    }

    const V5_WIRE_KEYS: [&str; 14] = [
        "protocol_version",
        "receipt_id",
        "canister_id",
        "record_id",
        "pre_state_hash",
        "post_state_hash",
        "tombstone_hash",
        "deletion_event_hash",
        "module_hash",
        "timestamp",
        "deletion_seq",
        "bls_certificate",
        "trust_root_key_id",
        "module_hash_certificate",
    ];

    #[test]
    fn v5_json_keys_exclude_certified_commitment() {
        let v = serde_json::to_value(test_receipt_v5()).unwrap();
        let mut keys: Vec<&str> = v.as_object().unwrap().keys().map(|k| k.as_str()).collect();
        keys.sort_unstable();
        let mut expected = V5_WIRE_KEYS.to_vec();
        expected.sort_unstable();
        assert_eq!(keys, expected);
    }

    #[test]
    fn v5_cbor_keys_exclude_certified_commitment() {
        let mut cbor = Vec::new();
        ciborium::into_writer(&test_receipt_v5(), &mut cbor).unwrap();
        let val: ciborium::value::Value = ciborium::from_reader(cbor.as_slice()).unwrap();
        let keys: Vec<&str> = val
            .as_map()
            .unwrap()
            .iter()
            .map(|(k, _)| k.as_text().unwrap())
            .collect();
        assert_eq!(keys, V5_WIRE_KEYS.to_vec());
    }

    #[test]
    fn v5_cbor_round_trip() {
        let r = test_receipt_v5();
        let mut cbor = Vec::new();
        ciborium::into_writer(&r, &mut cbor).unwrap();
        let decoded: DeletionReceiptV5 = ciborium::from_reader(cbor.as_slice()).unwrap();
        assert_eq!(decoded, r);
    }

    #[test]
    fn v5_json_round_trip_uses_hex_bytes() {
        let r = test_receipt_v5();
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains("\"bls_certificate\":\"aabbcc\""));
        assert!(json.contains("\"module_hash_certificate\":\"01020304\""));
        let decoded: DeletionReceiptV5 = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, r);
    }

    // -----------------------------------------------------------------------
    // Slice 3a — construction corrections (rulings A-1(a), A-2(b), 12 Sep 2026)
    // -----------------------------------------------------------------------

    /// T3a-1: the v5 event hash is tag-first over its six parts in order, and
    /// every part is load-bearing.
    #[test]
    fn t3a1_deletion_event_hash_v5_is_tag_first_over_six_parts_in_order() {
        use crate::hashing::sha256_concat;

        let pre = [1u8; 32];
        let post = [2u8; 32];
        let rid = [3u8; 32];
        let module = [4u8; 32];
        let ts = 1_000_000u64;
        let seq = 7u64;

        let base = deletion_event_hash_v5(&pre, &post, &rid, ts, &module, seq);
        assert_eq!(
            base,
            sha256_concat(&[
                b"MKTD02_EVENT_V2",
                &pre,
                &post,
                &rid,
                &ts.to_be_bytes(),
                &module,
                &seq.to_be_bytes(),
            ]),
            "v5 event hash is not tag-first over the six parts in order"
        );

        assert_ne!(
            base,
            deletion_event_hash_v5(&[9u8; 32], &post, &rid, ts, &module, seq)
        );
        assert_ne!(
            base,
            deletion_event_hash_v5(&pre, &[9u8; 32], &rid, ts, &module, seq)
        );
        assert_ne!(
            base,
            deletion_event_hash_v5(&pre, &post, &[9u8; 32], ts, &module, seq)
        );
        assert_ne!(
            base,
            deletion_event_hash_v5(&pre, &post, &rid, ts + 1, &module, seq)
        );
        assert_ne!(
            base,
            deletion_event_hash_v5(&pre, &post, &rid, ts, &[9u8; 32], seq)
        );
        assert_ne!(
            base,
            deletion_event_hash_v5(&pre, &post, &rid, ts, &module, seq + 1)
        );

        // Order matters: swapping pre/post is a different event.
        assert_ne!(
            base,
            deletion_event_hash_v5(&post, &pre, &rid, ts, &module, seq)
        );
    }

    /// T3a-2: the v5 construction is domain-separated from the historical one —
    /// the same operands under `MKTD02_EVENT_V1` never yield the v5 value.
    #[test]
    fn t3a2_v5_event_hash_differs_from_the_v1_construction() {
        use crate::hashing::TAG_EVENT;

        let pre = [1u8; 32];
        let post = [2u8; 32];
        let rid = [3u8; 32];
        let module = [4u8; 32];
        let ts = 1_000_000u64;
        let seq = 7u64;

        let v5 = deletion_event_hash_v5(&pre, &post, &rid, ts, &module, seq);
        let v1 = deletion_event_hash_v1(&pre, &post, ts, &module, seq);
        assert_ne!(v5, v1, "v5 and v2-v4 event hashes must never coincide");

        // The v1 helper is exactly the frozen five-part construction.
        assert_eq!(
            v1,
            hash_with_tag(
                TAG_EVENT,
                &[&pre, &post, &ts.to_be_bytes(), &module, &seq.to_be_bytes()]
            )
        );

        // Even over identical six operands, the tag separates the lines.
        assert_ne!(
            v5,
            hash_with_tag(
                TAG_EVENT,
                &[
                    &pre,
                    &post,
                    &rid,
                    &ts.to_be_bytes(),
                    &module,
                    &seq.to_be_bytes()
                ]
            )
        );
    }

    /// Walk a definite-length CBOR map of text keys, returning each key with
    /// the exact byte extent of its encoded value. Covers the value types the
    /// receipt wires use: unsigned ints, byte strings, text strings, arrays,
    /// and `null`.
    fn cbor_map_fields(bytes: &[u8]) -> Vec<(String, &[u8])> {
        fn header(b: &[u8]) -> (usize, usize) {
            let ai = b[0] & 0x1f;
            match ai {
                0..=23 => (1, ai as usize),
                24 => (2, b[1] as usize),
                25 => (3, u16::from_be_bytes([b[1], b[2]]) as usize),
                26 => (5, u32::from_be_bytes([b[1], b[2], b[3], b[4]]) as usize),
                _ => panic!("unsupported CBOR additional info {ai}"),
            }
        }

        fn value_len(b: &[u8]) -> usize {
            let (head, arg) = header(b);
            match b[0] >> 5 {
                0 | 1 | 7 => head,
                2 | 3 => head + arg,
                4 => (0..arg).fold(head, |off, _| off + value_len(&b[off..])),
                5 => (0..arg * 2).fold(head, |off, _| off + value_len(&b[off..])),
                m => panic!("unsupported CBOR major type {m}"),
            }
        }

        assert_eq!(bytes[0] >> 5, 5, "top level is not a CBOR map");
        let (mut off, pairs) = header(bytes);
        let mut fields = Vec::new();
        for _ in 0..pairs {
            let klen = value_len(&bytes[off..]);
            let key_bytes = &bytes[off..off + klen];
            assert_eq!(key_bytes[0] >> 5, 3, "map key is not a text string");
            let (khead, _) = header(key_bytes);
            fields.push((
                String::from_utf8(key_bytes[khead..].to_vec()).unwrap(),
                &bytes[off + klen..off + klen + value_len(&bytes[off + klen..])],
            ));
            off += klen + value_len(&bytes[off + klen..]);
        }
        assert_eq!(off, bytes.len(), "trailing bytes after the map");
        fields
    }

    /// The major-type-2 invariant, asserted semantically: the value is a CBOR
    /// byte string whose declared length equals its payload length — in
    /// whichever length form the encoder chose — and whose payload is the
    /// field's bytes.
    fn assert_cbor_byte_string(field: &str, value: &[u8], expected: &[u8]) {
        assert_eq!(value[0] >> 5, 2, "{field}: expected CBOR major type 2");
        let ai = value[0] & 0x1f;
        let (head, len) = match ai {
            0..=23 => (1usize, ai as usize),
            24 => (2, value[1] as usize),
            25 => (3, u16::from_be_bytes([value[1], value[2]]) as usize),
            26 => (
                5,
                u32::from_be_bytes([value[1], value[2], value[3], value[4]]) as usize,
            ),
            _ => panic!("{field}: unsupported byte-string length form {ai}"),
        };
        assert_eq!(
            len,
            expected.len(),
            "{field}: declared length != payload length"
        );
        assert_eq!(value.len(), head + len, "{field}: encoded extent mismatch");
        assert_eq!(&value[head..], expected, "{field}: payload != field value");
    }

    /// T3a-4: every byte-valued v5 field is a CBOR byte string, across all
    /// three length forms that arise (direct, one-byte, two-byte).
    #[test]
    fn t3a4_v5_byte_valued_fields_are_cbor_byte_strings() {
        let mut r = test_receipt_v5();
        r.record_id = vec![10, 11, 12]; // direct length form
        r.bls_certificate = Some(vec![0xAB; 300]); // two-byte length form
        r.module_hash_certificate = Some(vec![1, 2, 3, 4]); // direct length form

        let mut cbor = Vec::new();
        ciborium::into_writer(&r, &mut cbor).unwrap();
        let fields = cbor_map_fields(&cbor);
        let get = |name: &str| {
            fields
                .iter()
                .find(|(k, _)| k == name)
                .unwrap_or_else(|| panic!("missing field {name}"))
                .1
        };

        assert_cbor_byte_string("receipt_id", get("receipt_id"), &r.receipt_id);
        assert_cbor_byte_string("canister_id", get("canister_id"), r.canister_id.as_slice());
        assert_cbor_byte_string("record_id", get("record_id"), &r.record_id);
        assert_cbor_byte_string("pre_state_hash", get("pre_state_hash"), &r.pre_state_hash);
        assert_cbor_byte_string(
            "post_state_hash",
            get("post_state_hash"),
            &r.post_state_hash,
        );
        assert_cbor_byte_string("tombstone_hash", get("tombstone_hash"), &r.tombstone_hash);
        assert_cbor_byte_string(
            "deletion_event_hash",
            get("deletion_event_hash"),
            &r.deletion_event_hash,
        );
        assert_cbor_byte_string("module_hash", get("module_hash"), &r.module_hash);
        assert_cbor_byte_string(
            "bls_certificate",
            get("bls_certificate"),
            r.bls_certificate.as_deref().unwrap(),
        );
        assert_cbor_byte_string(
            "module_hash_certificate",
            get("module_hash_certificate"),
            r.module_hash_certificate.as_deref().unwrap(),
        );

        // All three length forms were exercised (a consequence, not the rule).
        assert_eq!(get("record_id")[0] & 0x1f, 3, "direct length form");
        assert_eq!(get("receipt_id")[0] & 0x1f, 24, "one-byte length form");
        assert_eq!(get("bls_certificate")[0] & 0x1f, 25, "two-byte length form");
    }

    /// T3a-4: an absent optional stays CBOR `null` with its key present.
    #[test]
    fn t3a4_pending_v5_keeps_certificate_keys_as_cbor_null() {
        let mut r = test_receipt_v5();
        r.bls_certificate = None;
        r.module_hash_certificate = None;

        let mut cbor = Vec::new();
        ciborium::into_writer(&r, &mut cbor).unwrap();
        let fields = cbor_map_fields(&cbor);

        assert_eq!(fields.len(), V5_WIRE_KEYS.len());
        let keys: Vec<&str> = fields.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(keys, V5_WIRE_KEYS.to_vec());

        for name in ["bls_certificate", "module_hash_certificate"] {
            let v = fields.iter().find(|(k, _)| k == name).unwrap().1;
            assert_eq!(v, [0xf6], "{name}: absent optional must be CBOR null");
        }
    }

    /// T3a-5: v5 CBOR round-trips across the byte-string length forms, and a
    /// pending receipt round-trips with its state intact.
    #[test]
    fn t3a5_v5_cbor_round_trip_across_byte_string_length_forms() {
        let mut r = test_receipt_v5();
        r.record_id = vec![10, 11, 12];
        r.bls_certificate = Some(vec![0xAB; 300]);
        let mut cbor = Vec::new();
        ciborium::into_writer(&r, &mut cbor).unwrap();
        let decoded: DeletionReceiptV5 = ciborium::from_reader(cbor.as_slice()).unwrap();
        assert_eq!(decoded, r);
        assert_eq!(decoded.state(), ReceiptState::FinalizedCandidate);

        let mut pending = test_receipt_v5();
        pending.bls_certificate = None;
        pending.module_hash_certificate = None;
        let mut cbor = Vec::new();
        ciborium::into_writer(&pending, &mut cbor).unwrap();
        let decoded: DeletionReceiptV5 = ciborium::from_reader(cbor.as_slice()).unwrap();
        assert_eq!(decoded, pending);
        assert_eq!(decoded.state(), ReceiptState::Pending);
    }

    /// T3a-6: the frozen v2–v4 wire is untouched — it still encodes byte-valued
    /// fields as CBOR arrays, so V5's change did not reach the shared helpers.
    ///
    /// Byte-identity of the v3 output is pinned by the unmodified
    /// `v3_cbor_byte_identical_to_head_golden` and
    /// `v3_json_byte_identical_to_head_golden`.
    #[test]
    fn t3a6_frozen_v4_wire_still_encodes_arrays_not_byte_strings() {
        let r = test_receipt_v4();
        let mut cbor = Vec::new();
        ciborium::into_writer(&r, &mut cbor).unwrap();
        let fields = cbor_map_fields(&cbor);
        let get = |name: &str| {
            fields
                .iter()
                .find(|(k, _)| k == name)
                .unwrap_or_else(|| panic!("missing field {name}"))
                .1
        };

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
            assert_eq!(
                get(name)[0] >> 5,
                4,
                "{name}: the frozen v4 wire must stay a CBOR array"
            );
        }

        // The principal was always a byte string, on every line.
        assert_eq!(get("canister_id")[0] >> 5, 2);
    }

    #[test]
    fn candid_type_v5_excludes_certified_commitment_v4_keeps_it() {
        use candid::CandidType;
        let v5 = format!("{:?}", DeletionReceiptV5::ty());
        assert!(!v5.contains("certified_commitment"), "got: {v5}");
        assert!(v5.contains("Named(\"module_hash_certificate\")"));
        let v4 = format!("{:?}", DeletionReceiptV4::ty());
        assert!(v4.contains("Named(\"certified_commitment\")"));
    }

    /// Parsing dispatches on protocol_version: v2/v3/v4 labels are refused by
    /// the v5 type (they belong to DeletionReceiptV4) ...
    #[test]
    fn v5_type_refuses_v2_v3_v4_labels() {
        let mut v3 = serde_json::to_value(golden_v3_receipt()).unwrap();
        let mut v4 = serde_json::to_value(test_receipt_v4()).unwrap();
        let mut v2 = serde_json::to_value(DeletionReceiptV4 {
            protocol_version: ProtocolVersion::V2.into(),
            ..golden_v3_receipt()
        })
        .unwrap();
        // 1d: the raw v2 wire's v2-only keys are unknown to the v5 schema, and
        // that structural error comes before the label check.
        let err = serde_json::from_value::<DeletionReceiptV5>(v2.clone())
            .unwrap_err()
            .to_string();
        assert!(err.starts_with("unknown field `"), "{err}");
        for key in ["nonce", "subnet_id"] {
            v2.as_object_mut().unwrap().remove(key);
        }
        for v in [&mut v3, &mut v4] {
            v.as_object_mut().unwrap().remove("certified_commitment");
        }
        for v in [v2, v3, v4] {
            let err = serde_json::from_value::<DeletionReceiptV5>(v)
                .unwrap_err()
                .to_string();
            assert!(err.contains("decode v2/v3/v4 receipts as DeletionReceiptV4"));
        }
        let mut r = test_receipt_v5();
        r.protocol_version = ProtocolVersion::V4.into();
        assert!(serde_json::to_string(&r).is_err());
    }

    /// ... and the v4 path is unchanged: a v5 wire does not decode as V4.
    #[test]
    fn v4_type_refuses_v5_wire() {
        let json = serde_json::to_value(test_receipt_v5()).unwrap();
        assert!(serde_json::from_value::<DeletionReceiptV4>(json).is_err());
    }

    // 3.4: three-state rule extended to v5 (all four permutations).

    #[test]
    fn v5_state_pending_when_neither_certificate_present() {
        let r = DeletionReceiptV5 {
            bls_certificate: None,
            module_hash_certificate: None,
            ..test_receipt_v5()
        };
        assert_eq!(r.state(), ReceiptState::Pending);
    }

    #[test]
    fn v5_state_finalized_candidate_when_both_certificates_present() {
        assert_eq!(test_receipt_v5().state(), ReceiptState::FinalizedCandidate);
    }

    #[test]
    fn v5_state_invalid_when_only_bls_certificate_present() {
        let r = DeletionReceiptV5 {
            module_hash_certificate: None,
            ..test_receipt_v5()
        };
        assert_eq!(r.state(), ReceiptState::InvalidIncompleteFinalization);
    }

    #[test]
    fn v5_state_invalid_when_only_module_hash_certificate_present() {
        let r = DeletionReceiptV5 {
            bls_certificate: None,
            ..test_receipt_v5()
        };
        assert_eq!(r.state(), ReceiptState::InvalidIncompleteFinalization);
    }

    /// Programmatic non-v5 label on the v5 type (cannot arise from decode).
    #[test]
    fn v5_type_with_non_v5_label_is_invalid() {
        let r = DeletionReceiptV5 {
            protocol_version: ProtocolVersion::V4.into(),
            ..test_receipt_v5()
        };
        assert_eq!(r.state(), ReceiptState::InvalidIncompleteFinalization);
    }

    #[test]
    fn v5_receipt_summary_carries_state() {
        let s = ReceiptSummary::from(&test_receipt_v5());
        assert_eq!(s.state, ReceiptState::FinalizedCandidate);
        assert_eq!(s.protocol_version, "mktd02-v5");
        assert!(s.state_changed);
    }

    // 3.6: negatives, each rejected by name.

    /// Real v5 CBOR with the map entry `key` set to `value` (added if absent).
    fn v5_cbor_with(key: &str, value: ciborium::value::Value) -> Vec<u8> {
        use ciborium::value::Value;
        let mut cbor = Vec::new();
        ciborium::into_writer(&test_receipt_v5(), &mut cbor).unwrap();
        let mut val: Value = ciborium::from_reader(cbor.as_slice()).unwrap();
        let map = val.as_map_mut().unwrap();
        match map.iter_mut().find(|(k, _)| k.as_text() == Some(key)) {
            Some((_, v)) => *v = value,
            None => map.push((Value::Text(key.into()), value)),
        }
        let mut out = Vec::new();
        ciborium::into_writer(&val, &mut out).unwrap();
        out
    }

    /// 3.6(a): v5 receipt with a certified_commitment key.
    #[test]
    fn t6a_v5_with_certified_commitment_key_is_retired_field() {
        for value in [json!(hex::encode([6u8; 32])), json!(null), json!("zz")] {
            let mut v = serde_json::to_value(test_receipt_v5()).unwrap();
            v["certified_commitment"] = value;
            let err = serde_json::from_value::<DeletionReceiptV5>(v).unwrap_err();
            assert_eq!(err.to_string(), "retired-field:certified_commitment");
        }
        use ciborium::value::Value;
        for value in [Value::Bytes(vec![6u8; 32]), Value::Null] {
            let cbor = v5_cbor_with("certified_commitment", value);
            let cbor_err = ciborium::from_reader::<DeletionReceiptV5, _>(cbor.as_slice())
                .unwrap_err()
                .to_string();
            assert!(
                cbor_err.contains("retired-field:certified_commitment"),
                "{cbor_err}"
            );
        }
    }

    /// 3.6(b): certified_data equal to the genesis value.
    #[test]
    fn t6b_genesis_certified_data_is_no_deletion_certified() {
        let c = Principal::from_slice(&[1, 2, 3, 4]);
        let genesis = genesis_certified_data(&c);
        assert_eq!(genesis, hash_with_tag(TAG_GENESIS, &[c.as_slice()]));
        assert_eq!(
            check_certified_data_not_genesis(&c, &genesis),
            Err("no-deletion-certified")
        );
        // Any other value, including another canister's genesis, passes.
        let other = genesis_certified_data(&Principal::from_slice(&[9]));
        assert_eq!(check_certified_data_not_genesis(&c, &other), Ok(()));
        let event = test_receipt_v5().deletion_event_hash;
        assert_eq!(check_certified_data_not_genesis(&c, &event), Ok(()));
    }

    /// 3.6(c): all-zero deletion_event_hash.
    #[test]
    fn t6c_v5_zero_event_hash_is_invalid_event_hash_zero() {
        let mut v = serde_json::to_value(test_receipt_v5()).unwrap();
        v["deletion_event_hash"] = json!(hex::encode(ZERO_HASH));
        let err = serde_json::from_value::<DeletionReceiptV5>(v.clone()).unwrap_err();
        assert_eq!(err.to_string(), "invalid-event-hash:zero");
        let cbor = v5_cbor_with(
            "deletion_event_hash",
            ciborium::value::Value::Bytes(ZERO_HASH.to_vec()),
        );
        let cbor_err = ciborium::from_reader::<DeletionReceiptV5, _>(cbor.as_slice())
            .unwrap_err()
            .to_string();
        assert!(cbor_err.contains("invalid-event-hash:zero"), "{cbor_err}");
        // Precedence: the retired key is reported first.
        v["certified_commitment"] = json!(hex::encode([6u8; 32]));
        let err = serde_json::from_value::<DeletionReceiptV5>(v).unwrap_err();
        assert_eq!(err.to_string(), "retired-field:certified_commitment");
        // Frozen v4 path is unchanged: no zero-hash rejection there.
        let v4 = DeletionReceiptV4 {
            deletion_event_hash: ZERO_HASH,
            ..test_receipt_v4()
        };
        let json = serde_json::to_value(&v4).unwrap();
        assert_eq!(
            serde_json::from_value::<DeletionReceiptV4>(json).unwrap(),
            v4
        );
    }

    /// 1b.4: serialise refuses an all-zero deletion_event_hash (symmetric
    /// with decode), for both JSON and CBOR.
    #[test]
    fn t1b4_v5_serialize_refuses_zero_event_hash() {
        let r = DeletionReceiptV5 {
            deletion_event_hash: ZERO_HASH,
            ..test_receipt_v5()
        };
        let json_err = serde_json::to_string(&r).unwrap_err().to_string();
        assert_eq!(json_err, "invalid-event-hash:zero");
        assert!(serde_json::to_value(&r).is_err());
        let mut buf = Vec::new();
        let cbor_err = ciborium::into_writer(&r, &mut buf).unwrap_err().to_string();
        assert!(cbor_err.contains("invalid-event-hash:zero"), "{cbor_err}");
        // A non-v5 label is still reported as such first.
        let r = DeletionReceiptV5 {
            protocol_version: ProtocolVersion::V4.into(),
            ..r
        };
        let err = serde_json::to_string(&r).unwrap_err().to_string();
        assert!(err.contains("is not mktd02-v5"), "{err}");
    }

    /// A V1-consistent v5 receipt: `receipt_id` and `deletion_event_hash`
    /// recomputed from the fixture's own fields.
    fn v1_consistent_receipt_v5() -> DeletionReceiptV5 {
        let mut r = test_receipt_v5();
        r.receipt_id = compute_receipt_id(&r.canister_id, &r.record_id, r.deletion_seq);
        r.deletion_event_hash = deletion_event_hash_v5(
            &r.pre_state_hash,
            &r.post_state_hash,
            &r.receipt_id,
            r.timestamp,
            &r.module_hash,
            r.deletion_seq,
        );
        r
    }

    #[test]
    fn gate_g_verify_v1_accepts_consistent_receipt() {
        let r = v1_consistent_receipt_v5();
        assert_eq!(verify_v1(&r), Ok(()));
        assert_eq!(verify_v1_receipt_id(&r), Ok(()));
        assert_eq!(verify_v1_event_hash(&r), Ok(()));
    }

    #[test]
    fn gate_g_verify_v1_receipt_id_step_runs_first() {
        let mut r = v1_consistent_receipt_v5();
        r.receipt_id[0] ^= 1;
        assert_eq!(verify_v1(&r), Err(ERR_V1_RECEIPT_ID_MISMATCH));
        // Both tampered: the event-hash step would also fail, so the
        // receipt_id error proves it was never reached.
        r.deletion_event_hash[0] ^= 1;
        assert_eq!(verify_v1_event_hash(&r), Err(ERR_V1_EVENT_HASH_MISMATCH));
        assert_eq!(verify_v1(&r), Err(ERR_V1_RECEIPT_ID_MISMATCH));
    }

    #[test]
    fn gate_g_verify_v1_event_hash_mismatch_after_receipt_id_passes() {
        let mut r = v1_consistent_receipt_v5();
        r.deletion_event_hash[0] ^= 1;
        assert_eq!(verify_v1_receipt_id(&r), Ok(()));
        assert_eq!(verify_v1(&r), Err(ERR_V1_EVENT_HASH_MISMATCH));
    }

    #[test]
    fn gate_g_v1_error_names_match_spec() {
        assert_eq!(ERR_V1_RECEIPT_ID_MISMATCH, "v1:receipt-id-mismatch");
        assert_eq!(ERR_V1_EVENT_HASH_MISMATCH, "v1:event-hash-mismatch");
    }

    /// Gate G / B1: serialise refusal is classified like decode. Near-miss
    /// labels carry the §7 fragment on both paths; a wrong-line label does not.
    #[test]
    fn gate_g_b1_v5_serialize_refusal_mirrors_decode_classification() {
        for label in ["mktd02-v5-x", "mktd02-v50", "mktd02-v5 "] {
            let r = DeletionReceiptV5 {
                protocol_version: label.into(),
                ..test_receipt_v5()
            };
            let json_err = serde_json::to_string(&r).unwrap_err().to_string();
            assert!(
                json_err.contains("unrecognised protocol_version"),
                "{json_err}"
            );
            let mut buf = Vec::new();
            let cbor_err = ciborium::into_writer(&r, &mut buf).unwrap_err().to_string();
            assert!(
                cbor_err.contains("unrecognised protocol_version"),
                "{cbor_err}"
            );
        }
        let r = DeletionReceiptV5 {
            protocol_version: ProtocolVersion::V4.into(),
            ..test_receipt_v5()
        };
        let json_err = serde_json::to_string(&r).unwrap_err().to_string();
        assert!(json_err.contains("is not mktd02-v5"), "{json_err}");
        assert!(
            !json_err.contains("unrecognised protocol_version"),
            "{json_err}"
        );
        let mut buf = Vec::new();
        let cbor_err = ciborium::into_writer(&r, &mut buf).unwrap_err().to_string();
        assert!(
            !cbor_err.contains("unrecognised protocol_version"),
            "{cbor_err}"
        );
    }

    /// 3.6: genesis and a deletion_event_hash derived from the same inputs
    /// differ (domain separation MKTD02_GENESIS_V1 vs MKTD02_EVENT_V1).
    #[test]
    fn t6_genesis_differs_from_event_hash_over_same_inputs() {
        use crate::hashing::TAG_EVENT;
        let c = Principal::from_slice(&[1, 2, 3, 4]);
        // Same preimage (the canister_id bytes) under each construction.
        assert_ne!(
            genesis_certified_data(&c),
            hash_with_tag(TAG_EVENT, &[c.as_slice()])
        );
        // Same full event preimage under each tag.
        let r = test_receipt_v5();
        let (ts, seq) = (r.timestamp.to_be_bytes(), r.deletion_seq.to_be_bytes());
        let parts: &[&[u8]] = &[
            &r.pre_state_hash,
            &r.post_state_hash,
            &ts,
            &r.module_hash,
            &seq,
        ];
        let event = hash_with_tag(TAG_EVENT, parts);
        assert_ne!(hash_with_tag(TAG_GENESIS, parts), event);
        assert_ne!(genesis_certified_data(&r.canister_id), event);
    }

    // 1b.3: AnyDeletionReceipt dispatches on protocol_version.

    fn cbor(r: &impl Serialize) -> Vec<u8> {
        let mut buf = Vec::new();
        ciborium::into_writer(r, &mut buf).unwrap();
        buf
    }

    #[test]
    fn any_dispatches_v2_v3_v4_to_v4_variant() {
        let v2 = DeletionReceiptV4 {
            protocol_version: ProtocolVersion::V2.into(),
            ..golden_v3_receipt()
        };
        for (fixture, label) in [
            (v2, "mktd02-v2"),
            (golden_v3_receipt(), "mktd02-v3"),
            (test_receipt_v4(), "mktd02-v4"),
        ] {
            let json = serde_json::to_value(&fixture).unwrap();
            let bytes = cbor(&fixture);
            let direct_json: DeletionReceiptV4 = serde_json::from_value(json.clone()).unwrap();
            let direct_cbor: DeletionReceiptV4 = ciborium::from_reader(bytes.as_slice()).unwrap();
            let any_json = AnyDeletionReceipt::from_json_value(json).unwrap();
            let any_cbor = AnyDeletionReceipt::from_cbor(&bytes).unwrap();
            assert_eq!(any_json, AnyDeletionReceipt::V4(direct_json.clone()));
            assert_eq!(any_cbor, AnyDeletionReceipt::V4(direct_cbor));
            assert_eq!(any_json.protocol_version(), label);
            assert_eq!(any_json.receipt_id(), direct_json.receipt_id);
            assert_eq!(any_json.state(), direct_json.state());
        }
    }

    #[test]
    fn any_dispatches_v5_to_v5_variant() {
        let r = test_receipt_v5();
        let any_json =
            AnyDeletionReceipt::from_json_value(serde_json::to_value(&r).unwrap()).unwrap();
        let any_cbor = AnyDeletionReceipt::from_cbor(&cbor(&r)).unwrap();
        assert_eq!(any_json, AnyDeletionReceipt::V5(r.clone()));
        assert_eq!(any_cbor, AnyDeletionReceipt::V5(r.clone()));
        assert_eq!(any_json.protocol_version(), "mktd02-v5");
        assert_eq!(any_json.receipt_id(), r.receipt_id);
        assert_eq!(any_json.state(), ReceiptState::FinalizedCandidate);
    }

    #[test]
    fn any_unknown_label_hard_errors() {
        let mut json = serde_json::to_value(test_receipt_v5()).unwrap();
        json["protocol_version"] = json!("mktd02-v9");
        let err = AnyDeletionReceipt::from_json_value(json).unwrap_err();
        assert!(err.contains("unrecognised protocol_version"), "{err}");
        let bytes = v5_cbor_with("protocol_version", ciborium::value::Value::Text("x".into()));
        let err = AnyDeletionReceipt::from_cbor(&bytes).unwrap_err();
        assert!(err.contains("unrecognised protocol_version"), "{err}");
        let mut no_label = serde_json::to_value(test_receipt_v5()).unwrap();
        no_label.as_object_mut().unwrap().remove("protocol_version");
        assert!(AnyDeletionReceipt::from_json_value(no_label).is_err());
    }

    /// Named errors surface unchanged: identical to the direct decode error.
    #[test]
    fn any_surfaces_named_errors_unchanged() {
        // v5 with the retired key -> retired-field:certified_commitment.
        let mut json = serde_json::to_value(test_receipt_v5()).unwrap();
        json["certified_commitment"] = json!(hex::encode([6u8; 32]));
        let err = AnyDeletionReceipt::from_json_value(json).unwrap_err();
        assert_eq!(err, "retired-field:certified_commitment");
        let bytes = v5_cbor_with("certified_commitment", ciborium::value::Value::Null);
        let err = AnyDeletionReceipt::from_cbor(&bytes).unwrap_err();
        let direct = ciborium::from_reader::<DeletionReceiptV5, _>(bytes.as_slice())
            .unwrap_err()
            .to_string();
        assert_eq!(err, direct);
        assert!(err.contains("retired-field:certified_commitment"));
        // v5 zero event hash -> invalid-event-hash:zero.
        let mut json = serde_json::to_value(test_receipt_v5()).unwrap();
        json["deletion_event_hash"] = json!(hex::encode(ZERO_HASH));
        let err = AnyDeletionReceipt::from_json_value(json).unwrap_err();
        assert_eq!(err, "invalid-event-hash:zero");
        // v3 with a stray v4-only field -> DeletionReceiptV4's own error.
        let json = v3_json_with_certs(None, Some("01020304"));
        let direct = serde_json::from_value::<DeletionReceiptV4>(json.clone())
            .unwrap_err()
            .to_string();
        assert_eq!(
            AnyDeletionReceipt::from_json_value(json).unwrap_err(),
            direct
        );
    }

    // 1d: v5 wire rejects unknown keys (fail-closed); v4 path unchanged.

    /// The keys the 1d ruling names, with plausible wire values.
    fn unknown_keys() -> [(&'static str, serde_json::Value); 3] {
        [
            ("nonce", json!(7)),
            (
                "subnet_id",
                json!(Principal::from_text("2vxsx-fae").unwrap()),
            ),
            ("extra", json!("x")),
        ]
    }

    /// Real CBOR of `r` with each of `entries` set (added if absent).
    fn cbor_with_entries(r: &impl Serialize, entries: &[(&str, serde_json::Value)]) -> Vec<u8> {
        use ciborium::value::Value;
        let mut val: Value = ciborium::from_reader(cbor(r).as_slice()).unwrap();
        let map = val.as_map_mut().unwrap();
        for (key, json_value) in entries {
            let value = Value::serialized(json_value).unwrap();
            match map.iter_mut().find(|(k, _)| k.as_text() == Some(key)) {
                Some((_, v)) => *v = value,
                None => map.push((Value::Text((*key).into()), value)),
            }
        }
        let mut out = Vec::new();
        ciborium::into_writer(&val, &mut out).unwrap();
        out
    }

    /// Each unknown key is a hard error: JSON and CBOR, direct and via
    /// AnyDeletionReceipt (whose error equals the direct one).
    #[test]
    fn t1d_v5_unknown_keys_hard_error() {
        for (key, value) in unknown_keys() {
            let expected = format!("unknown field `{key}`");
            let mut json = serde_json::to_value(test_receipt_v5()).unwrap();
            json[key] = value.clone();
            let direct = serde_json::from_value::<DeletionReceiptV5>(json.clone())
                .unwrap_err()
                .to_string();
            assert!(direct.starts_with(&expected), "{direct}");
            assert_eq!(
                AnyDeletionReceipt::from_json_value(json).unwrap_err(),
                direct
            );

            let bytes = cbor_with_entries(&test_receipt_v5(), &[(key, value)]);
            let direct = ciborium::from_reader::<DeletionReceiptV5, _>(bytes.as_slice())
                .unwrap_err()
                .to_string();
            assert!(direct.contains(&expected), "{direct}");
            assert_eq!(AnyDeletionReceipt::from_cbor(&bytes).unwrap_err(), direct);
        }
    }

    /// certified_commitment is still rejected BY NAME, never as an unknown
    /// key: JSON and CBOR, direct and via AnyDeletionReceipt.
    #[test]
    fn t1d_certified_commitment_still_rejected_by_name() {
        let cc = json!(hex::encode([6u8; 32]));
        let mut json = serde_json::to_value(test_receipt_v5()).unwrap();
        json["certified_commitment"] = cc.clone();
        let direct = serde_json::from_value::<DeletionReceiptV5>(json.clone())
            .unwrap_err()
            .to_string();
        assert_eq!(direct, ERR_RETIRED_FIELD_CERTIFIED_COMMITMENT);
        assert_eq!(
            AnyDeletionReceipt::from_json_value(json).unwrap_err(),
            direct
        );

        let bytes = cbor_with_entries(&test_receipt_v5(), &[("certified_commitment", cc)]);
        let direct = ciborium::from_reader::<DeletionReceiptV5, _>(bytes.as_slice())
            .unwrap_err()
            .to_string();
        assert!(
            direct.contains(ERR_RETIRED_FIELD_CERTIFIED_COMMITMENT),
            "{direct}"
        );
        assert!(!direct.contains("unknown field"), "{direct}");
        assert_eq!(AnyDeletionReceipt::from_cbor(&bytes).unwrap_err(), direct);
    }

    /// Precedence (documented): with the retired key AND an unknown key, the
    /// structural unknown-key error is reported before the named check.
    #[test]
    fn t1d_unknown_key_reported_before_retired_field() {
        let mut json = serde_json::to_value(test_receipt_v5()).unwrap();
        json["certified_commitment"] = json!(hex::encode([6u8; 32]));
        json["extra"] = json!("x");
        let err = AnyDeletionReceipt::from_json_value(json).unwrap_err();
        assert!(err.starts_with("unknown field `extra`"), "{err}");
    }

    /// Frozen v4 path UNCHANGED: v2/v3/v4 receipts carrying the same unknown
    /// keys still decode, to the same receipt as without them (JSON and CBOR,
    /// direct and via AnyDeletionReceipt).
    #[test]
    fn t1d_v4_unknown_key_tolerance_unchanged() {
        let v2 = DeletionReceiptV4 {
            protocol_version: ProtocolVersion::V2.into(),
            ..golden_v3_receipt()
        };
        for fixture in [v2, golden_v3_receipt(), test_receipt_v4()] {
            let clean: DeletionReceiptV4 =
                serde_json::from_value(serde_json::to_value(&fixture).unwrap()).unwrap();
            let entries = unknown_keys();
            // A v2 wire already carries nonce/subnet_id; leave those as issued.
            let entries: Vec<(&str, serde_json::Value)> = entries
                .into_iter()
                .filter(|(k, _)| fixture.protocol_version != "mktd02-v2" || *k == "extra")
                .collect();

            let mut json = serde_json::to_value(&fixture).unwrap();
            for (key, value) in &entries {
                json[*key] = value.clone();
            }
            let direct: DeletionReceiptV4 = serde_json::from_value(json.clone()).unwrap();
            assert_eq!(direct, clean);
            assert_eq!(
                AnyDeletionReceipt::from_json_value(json).unwrap(),
                AnyDeletionReceipt::V4(clean.clone())
            );

            let bytes = cbor_with_entries(&fixture, &entries);
            let direct: DeletionReceiptV4 = ciborium::from_reader(bytes.as_slice()).unwrap();
            assert_eq!(direct, clean);
            assert_eq!(
                AnyDeletionReceipt::from_cbor(&bytes).unwrap(),
                AnyDeletionReceipt::V4(clean)
            );
        }
    }

    /// v4-HISTORICAL — retired pins (SR-06, 11 Sep 2026; spec item 3.5).
    ///
    /// The deletion-path `certified_commitment` golden is RETIRED: mktd02-v5
    /// no longer produces a certified_commitment. Retained, not deleted, so
    /// issued v2–v4 receipts stay verifiable and the digest stays on record.
    /// Do not edit, regenerate, or extend.
    mod v4_historical {
        use super::*;

        /// `deletion_event_hash` and `certified_commitment` preimages exclude the
        /// certificates by construction. Recomputed here from receipt fields via
        /// the mktd02 formulas; the certificates never enter either preimage, and
        /// the outputs match independently-verified goldens.
        #[test]
        fn golden_event_and_certified_preimages_cert_independent() {
            use crate::hashing::{DomainTag, TAG_CERTIFIED};
            const TAG_EVENT: DomainTag = DomainTag(b"MKTD02_EVENT_V1");

            // Fixed inputs (same as hashing.rs::golden_deletion_event_hash_v2).
            let pre = [1u8; 32];
            let post = [2u8; 32];
            let module_hash = [3u8; 32];
            let ts: u64 = 1_000_000;
            let seq: u64 = 1;

            let event = hash_with_tag(
                TAG_EVENT,
                &[
                    &pre,
                    &post,
                    &ts.to_be_bytes(),
                    &module_hash,
                    &seq.to_be_bytes(),
                ],
            );
            // Retired tag (SR-06): hash_with_tag refuses it; sanctioned path.
            let certified = TAG_CERTIFIED.hash_historical(&[&post, &event]);

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
            let without_certs = DeletionReceiptV4 {
                bls_certificate: None,
                module_hash_certificate: None,
                ..test_receipt_v4()
            };
            assert_ne!(with_certs.bls_certificate, without_certs.bls_certificate);
            // Neither certificate field appears in the event/certified inputs above.
            assert_eq!(
                event,
                hash_with_tag(
                    TAG_EVENT,
                    &[
                        &pre,
                        &post,
                        &ts.to_be_bytes(),
                        &module_hash,
                        &seq.to_be_bytes()
                    ],
                )
            );
        }
    }
}
