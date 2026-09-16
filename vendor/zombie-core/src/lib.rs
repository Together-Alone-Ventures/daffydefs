//! # zombie-core
//!
//! Shared types, hashing primitives, and receipt structures for the
//! Zombie Delete CVDR (Cryptographically Verifiable Deletion Receipt) system.
//!
//! This crate is **pure Rust** with zero ICP dependencies. It compiles and
//! tests on native targets (`cargo test -p zombie-core`).

pub mod hashing;
pub mod manifest;
pub mod nns_keys;
pub mod protocol;
pub mod receipt;
pub mod serialisation;
pub mod tombstone;

pub use hashing::{
    sha256, sha256_concat, RetiredTag, RETIRED_TAGS, TAG_EVENT_V2, TAG_GENESIS, ZERO_HASH,
};
pub use manifest::{compute_manifest_hash, FieldDescriptor};
pub use nns_keys::{active_key, active_key_id, lookup_key, NnsRootKey, MAINNET_KEY, MAINNET_KEYS};
pub use protocol::MAX_FINALIZATION_DELAY_NS;
pub use receipt::{
    check_certified_data_not_genesis, compute_receipt_id, deletion_event_hash_v1,
    deletion_event_hash_v5, genesis_certified_data, verify_v1, verify_v1_event_hash,
    verify_v1_receipt_id, AnyDeletionReceipt, DeletionReceiptV4, DeletionReceiptV5,
    ProtocolVersion, ReceiptState, ReceiptSummary, ERR_INVALID_EVENT_HASH_ZERO,
    ERR_NO_DELETION_CERTIFIED, ERR_RETIRED_FIELD_CERTIFIED_COMMITMENT, ERR_V1_EVENT_HASH_MISMATCH,
    ERR_V1_RECEIPT_ID_MISMATCH,
};
pub use serialisation::{decode_pii_state, encode_pii_state, SerialisationError};
pub use tombstone::{tombstone_constant, TOMBSTONE_CONSTANT};
