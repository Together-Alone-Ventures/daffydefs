//! # Deletion Engine
//!
//! Domain tags: `MKTD02_TOMBSTONE_HASH_V1`, `MKTD02_EVENT_V1`
//!
//! Core deletion flow is synchronous within a single message.
//!
//! ## v0.2.0 Changes
//!
//! - Phase 1: `manifest_hash` removed from `deletion_event_hash` preimage.
//!   `commit_mode` removed from receipt. New fields added.
//! - Phase 2: After publishing certified commitment, the finalization
//!   lock is acquired. This prevents any code path from changing
//!   certified data until the receipt is finalized via
//!   `mktd_finalize_receipt()`.

use crate::certified::publish_certified_commitment;
use crate::nonce::increment_deletion_seq;
use crate::state::compute_state_hash;
use crate::storage::{
    with_storage, with_storage_mut, Hash32, MetaCell, OptionalTimestamp, ReceiptBytes,
};
use crate::trait_def::MKTdDataSource;
use crate::MktdConfig;
use zombie_core::hashing::{hash_with_tag, TAG_EVENT, TAG_TOMBSTONE_HASH, ZERO_HASH};
use zombie_core::receipt::{compute_receipt_id, DeletionReceipt, ProtocolVersion};
use zombie_core::tombstone::tombstone_constant;

#[derive(Debug, Clone)]
pub enum DeletionError {
    AlreadyTombstoned,
    NotInitialised,
}

impl core::fmt::Display for DeletionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::AlreadyTombstoned => write!(f, "MKTd02: canister is already tombstoned"),
            Self::NotInitialised => write!(f, "MKTd02: not initialised"),
        }
    }
}

/// Execute the full deletion flow (Phase A) using the caller-derived
/// `record_id`. Returns the receipt_id on success.
///
/// Thin wrapper: derives `record_id` from
/// `ic_cdk::caller().as_slice().to_vec()` — exactly as the engine did
/// previously — then delegates to [`execute_deletion_with_record_id`].
///
/// After this call succeeds, the **finalization lock is held**. No
/// code path may change certified data until `finalize_receipt()` is
/// called. This is a hard invariant enforced in `publish_certified_commitment`.
pub fn execute_deletion<A: MKTdDataSource>(
    adapter: &mut A,
    config: &MktdConfig,
) -> Result<[u8; 32], DeletionError> {
    // ic-cdk 0.18: `ic_cdk::caller()` → `ic_cdk::api::msg_caller()` (same ic0
    // msg_caller syscall, behaviour-identical).
    let record_id = ic_cdk::api::msg_caller().as_slice().to_vec();
    execute_deletion_with_record_id(adapter, config, record_id)
}

/// Execute the full deletion flow (Phase A) with a **host-supplied**
/// `record_id`. Returns the receipt_id on success.
///
/// `record_id` is treated as **opaque bytes**: it is stored in the receipt
/// and fed into `compute_receipt_id` verbatim. The engine does not hash,
/// parse, validate, or otherwise reinterpret it (P0 contract).
///
/// The receipt is created with `bls_certificate: None` and
/// `trust_root_key_id: String::new()`. These fields are populated during
/// finalization (Phase C — see `finalize_receipt`).
///
/// After this call succeeds, the **finalization lock is held**. No
/// code path may change certified data until `finalize_receipt()` is
/// called. This is a hard invariant enforced in `publish_certified_commitment`.
pub fn execute_deletion_with_record_id<A: MKTdDataSource>(
    adapter: &mut A,
    _config: &MktdConfig,
    record_id: Vec<u8>,
) -> Result<[u8; 32], DeletionError> {
    // (a) Validate not tombstoned
    if crate::guard::is_tombstoned() {
        return Err(DeletionError::AlreadyTombstoned);
    }
    if !crate::guard::is_initialised() {
        return Err(DeletionError::NotInitialised);
    }

    // ic-cdk 0.18: `ic_cdk::id()` → `ic_cdk::api::canister_self()` (same
    // ic0 canister_self syscall, behaviour-identical).
    let canister_id = ic_cdk::api::canister_self();
    let timestamp = ic_cdk::api::time();

    // (b) Capture pre_state_hash
    let pre_state_hash = compute_state_hash(&adapter.get_state_bytes());

    // (c) Tombstone
    adapter.tombstone_state();

    // (c2) Post-tombstone invariant check
    if !adapter.is_tombstoned() {
        ic_cdk::trap("MKTd02: post-tombstone invariant failed — adapter.is_tombstoned() returned false after tombstone_state()");
    }

    // (d) Capture post_state_hash
    let post_state_hash = compute_state_hash(&adapter.get_state_bytes());

    // (e) Increment deletion sequence
    //     `record_id` is host-supplied (opaque bytes) — see fn signature.
    let deletion_seq = increment_deletion_seq();

    // (f) Compute tombstone_hash
    let tombstone_hash = hash_with_tag(TAG_TOMBSTONE_HASH, &[
        canister_id.as_slice(),
        tombstone_constant(),
        &timestamp.to_be_bytes(),
        &deletion_seq.to_be_bytes(),
    ]);

    // (g) Read module_hash from storage
    let module_hash = with_storage(|s| s.meta.get().module_hash);

    // (h) Compute deletion_event_hash
    //     v0.2.0: manifest_hash removed from preimage
    let deletion_event_hash = hash_with_tag(TAG_EVENT, &[
        &pre_state_hash,
        &post_state_hash,
        &timestamp.to_be_bytes(),
        &module_hash,
        &deletion_seq.to_be_bytes(),
    ]);

    // (i) Store tombstoned_at (engine-owned; see storage.rs docs)
    // is-0.7: `StableCell::set` returns the old value (was `Result` in is-0.6);
    // the `.expect(...)` wrappers are dropped. The written encoding is unchanged.
    with_storage_mut(|s| {
        s.tombstoned_at.set(OptionalTimestamp(Some(timestamp)));
        s.deletion_event_hash.set(Hash32(deletion_event_hash));
        s.state_hash.set(Hash32(post_state_hash));
    });

    // (j) Compute + publish certified_commitment
    //     Note: finalization lock is NOT yet held, so this call succeeds.
    let certified_commitment =
        publish_certified_commitment(&post_state_hash, &deletion_event_hash);

    // (j2) Acquire finalization lock — from this point, no code path
    //      may call certified_data_set() until finalize_receipt() releases it.
    crate::storage::acquire_finalization_lock();

    // (k) Compute and persist pending receipt_id while lock is held
    let receipt_id = compute_receipt_id(&canister_id, &record_id, deletion_seq);
    crate::storage::set_pending_receipt_id(receipt_id);

    // (l) Construct receipt
    let receipt = DeletionReceipt {
        protocol_version: ProtocolVersion::V4.into(),
        receipt_id,
        canister_id,
        record_id,
        pre_state_hash,
        post_state_hash,
        tombstone_hash,
        deletion_event_hash,
        certified_commitment,
        module_hash,
        timestamp,
        deletion_seq,
        bls_certificate: None,      // Populated during finalization (Phase C)
        trust_root_key_id: String::new(),      // Populated during finalization (Phase C)
        module_hash_certificate: None,      // Populated during finalization (Phase C)
    };

    // (m) Store receipt as CBOR in StableBTreeMap
    let mut cbor_buf = Vec::new();
    ciborium::into_writer(&receipt, &mut cbor_buf)
        .expect("MKTd02: failed to CBOR-encode receipt");
    with_storage_mut(|s| {
        s.receipts
            .insert(Hash32(receipt_id), ReceiptBytes(cbor_buf));
    });

    // (n) Return receipt_id
    Ok(receipt_id)
}

/// Upgrade cascade: recompute state hash and update module_hash.
///
/// v0.2.0: Always recomputes state_hash and republishes certified_commitment.
/// If the finalization lock is held (receipt pending), the call to
/// `publish_certified_commitment` will trap — this is intentional.
/// You must finalize the pending receipt before upgrading.
pub(crate) fn upgrade_cascade<A: MKTdDataSource>(
    adapter: &A,
    module_hash: [u8; 32],
) {
    // Always recompute state_hash (defensive — catches adapter changes)
    let state_bytes = adapter.get_state_bytes();
    let new_state_hash = compute_state_hash(&state_bytes);
    with_storage_mut(|s| {
        s.state_hash.set(Hash32(new_state_hash));
    });

    // Always republish certified_commitment
    // (Will trap if finalization lock is held — see certified.rs)
    let existing_event_hash = with_storage(|s| s.deletion_event_hash.get().0);
    publish_certified_commitment(&new_state_hash, &existing_event_hash);

    // Update module_hash unconditionally
    with_storage_mut(|s| {
        let mut meta = s.meta.get().clone();
        meta.module_hash = module_hash;
        s.meta.set(meta);
    });
}

/// First-time initialisation logic.
pub(crate) fn first_init<A: MKTdDataSource>(
    adapter: &A,
    config: &MktdConfig,
    module_hash: [u8; 32],
) {
    let timestamp = ic_cdk::api::time();

    crate::state::init_state_hash(&adapter.get_state_bytes());

    let state_hash = crate::state::read_state_hash();
    publish_certified_commitment(&state_hash, &ZERO_HASH);

    with_storage_mut(|s| {
        let meta = MetaCell {
            schema_version: crate::storage::schema_version(),
            memory_base: config.base_memory_id as u32,
            initialised_at: Some(timestamp),
            module_hash,
            pending_receipt_id: None,
        };
        s.meta.set(meta);
    });
}

#[cfg(test)]
mod tests {
    use candid::Principal;
    use zombie_core::receipt::compute_receipt_id;

    // Locks the LIVE v3 receipt-id formula: `record_id` IS part of the
    // receipt_id preimage (see zombie_core::receipt::compute_receipt_id). This
    // is a pure check — no IC runtime needed — and the source of truth behind
    // the "record_id is bound into receipt identity" finding.
    #[test]
    fn receipt_id_is_sensitive_to_record_id() {
        let canister_id = Principal::from_slice(&[0xCA, 0xFE, 0x01]);
        let seq = 1u64;

        let a = compute_receipt_id(&canister_id, b"subject-A", seq);
        let b = compute_receipt_id(&canister_id, b"subject-B", seq);
        assert_ne!(
            a, b,
            "distinct record_id must yield distinct receipt_id (record_id is in the v3 preimage)"
        );

        // Deterministic for fixed inputs.
        let a_again = compute_receipt_id(&canister_id, b"subject-A", seq);
        assert_eq!(a, a_again, "receipt_id must be deterministic for fixed inputs");
    }
}
