//! # Deletion Engine
//!
//! Domain tags: `MKTD02_TOMBSTONE_HASH_V1` (built here);
//! `MKTD02_EVENT_V2` via `zombie_core::deletion_event_hash_v5` (the engine
//! builds no event-hash preimage of its own).
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
//!
//! ## mktd02-v5 (Direct Certification, SR-06)
//!
//! The deletion path publishes `deletion_event_hash` itself as certified data
//! (no certified commitment) and emits a `DeletionReceiptV5`. It is the only
//! path that sets a NEW certified value (see `certified.rs`).

use crate::certified::publish_deletion_certified;
use crate::nonce::increment_deletion_seq;
use crate::state::compute_state_hash;
use crate::storage::{with_storage, with_storage_mut, Hash32, OptionalTimestamp, ReceiptBytes};
use crate::trait_def::MKTdDataSource;
use crate::MktdConfig;
use candid::Principal;
use zombie_core::hashing::{hash_with_tag, TAG_TOMBSTONE_HASH};
use zombie_core::receipt::{
    compute_receipt_id, deletion_event_hash_v5, DeletionReceiptV5, ProtocolVersion,
};
use zombie_core::tombstone::tombstone_constant;

/// Proof of being on the deletion path. The field is private to this module
/// (which holds only the deletion path), so only the deletion path can
/// construct it — this restricts `certified::publish_deletion_certified` to
/// the deletion path by module visibility.
pub(crate) struct DeletionPath(());

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
/// called. This is a hard invariant enforced in `publish_deletion_certified`.
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
/// called. This is a hard invariant enforced in `publish_deletion_certified`.
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
    let tombstone_hash = compute_tombstone_hash(&canister_id, timestamp, deletion_seq);

    // (g) Read module_hash from storage
    let module_hash = with_storage(|s| s.meta.get().module_hash);

    // (g2) Compute receipt_id BEFORE the event hash — the v5 event preimage
    //      binds it (ruling A-1(a), 12 Sep 2026). Persisting the pending
    //      receipt_id still happens at (k), once the lock is held.
    let receipt_id = compute_receipt_id(&canister_id, &record_id, deletion_seq);

    // (h) Compute deletion_event_hash via the single normative implementation
    //     in zombie-core (MKTD02_EVENT_V2, six parts). The engine builds no
    //     event-hash preimage of its own. manifest_hash is not in the preimage.
    let deletion_event_hash = deletion_event_hash_v5(
        &pre_state_hash,
        &post_state_hash,
        &receipt_id,
        timestamp,
        &module_hash,
        deletion_seq,
    );

    // (i) Store tombstoned_at (engine-owned; see storage.rs docs)
    // is-0.7: `StableCell::set` returns the old value (was `Result` in is-0.6);
    // the `.expect(...)` wrappers are dropped. The written encoding is unchanged.
    with_storage_mut(|s| {
        s.tombstoned_at.set(OptionalTimestamp(Some(timestamp)));
        s.deletion_event_hash.set(Hash32(deletion_event_hash));
        // base+1 (Q7): post_state_hash is kept for diagnostics only — it is
        // not a verification input and never a certified value.
        s.state_hash.set(Hash32(post_state_hash));
    });

    // (j) Publish deletion_event_hash as the certified value (Direct
    //     Certification). Finalization lock is NOT yet held, so this succeeds.
    publish_deletion_certified(DeletionPath(()), &deletion_event_hash);

    // (j2) Acquire finalization lock — from this point, no code path
    //      may call certified_data_set() until finalize_receipt() releases it.
    crate::storage::acquire_finalization_lock();

    // (k) Persist the pending receipt_id while the lock is held. The value was
    //     computed at (g2) because the event hash binds it; the persist step is
    //     unchanged in position and behaviour.
    crate::storage::set_pending_receipt_id(receipt_id);

    // (l) Construct receipt (mktd02-v5: no certified_commitment field)
    let receipt = DeletionReceiptV5 {
        protocol_version: ProtocolVersion::V5.into(),
        receipt_id,
        canister_id,
        record_id,
        pre_state_hash,
        post_state_hash,
        tombstone_hash,
        deletion_event_hash,
        module_hash,
        timestamp,
        deletion_seq,
        bls_certificate: None, // Populated during finalization (Phase C)
        trust_root_key_id: String::new(), // Populated during finalization (Phase C)
        module_hash_certificate: None, // Populated during finalization (Phase C)
    };

    // (m) Store receipt as CBOR in StableBTreeMap
    let cbor_buf = encode_receipt(&receipt)
        .unwrap_or_else(|e| ic_cdk::trap(format!("MKTd02: failed to CBOR-encode receipt: {e}")));
    with_storage_mut(|s| {
        s.receipts
            .insert(Hash32(receipt_id), ReceiptBytes(cbor_buf));
    });

    // (n) Return receipt_id
    Ok(receipt_id)
}

/// `tombstone_hash = hash_with_tag(MKTD02_TOMBSTONE_HASH_V1,
/// canister_id ‖ TOMBSTONE_CONSTANT ‖ u64_be(timestamp) ‖ u64_be(deletion_seq))`.
///
/// The engine's only tombstone-hash construction; the deletion path calls it
/// at (f). Pure, so it is checked directly against the countersigned
/// zombie-core vector gv5-002.
pub(crate) fn compute_tombstone_hash(
    canister_id: &Principal,
    timestamp: u64,
    deletion_seq: u64,
) -> [u8; 32] {
    hash_with_tag(
        TAG_TOMBSTONE_HASH,
        &[
            canister_id.as_slice(),
            tombstone_constant(),
            &timestamp.to_be_bytes(),
            &deletion_seq.to_be_bytes(),
        ],
    )
}

/// Encode a receipt for storage. zombie-core refuses to serialise a v5
/// receipt whose `deletion_event_hash` is all-zero (`invalid-event-hash:zero`),
/// so the engine can never store or emit one; the named error is surfaced in
/// the trap message.
fn encode_receipt(receipt: &DeletionReceiptV5) -> Result<Vec<u8>, String> {
    let mut buf = Vec::new();
    ciborium::into_writer(receipt, &mut buf).map_err(|e| e.to_string())?;
    Ok(buf)
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
        assert_eq!(
            a, a_again,
            "receipt_id must be deterministic for fixed inputs"
        );
    }

    /// T9: the engine cannot produce a receipt whose deletion_event_hash is
    /// ZERO_HASH. A SHA-256 output can't realistically be zero, so the
    /// condition is constructed directly and fed to the engine's encode step,
    /// which refuses it by name.
    #[test]
    fn t9_engine_refuses_zero_deletion_event_hash_by_name() {
        use zombie_core::hashing::ZERO_HASH;
        use zombie_core::receipt::{DeletionReceiptV5, ProtocolVersion};

        let zero = DeletionReceiptV5 {
            protocol_version: ProtocolVersion::V5.into(),
            receipt_id: [1u8; 32],
            canister_id: Principal::from_slice(&[0xCA, 0xFE, 0x01]),
            record_id: b"subject".to_vec(),
            pre_state_hash: [2u8; 32],
            post_state_hash: [3u8; 32],
            tombstone_hash: [4u8; 32],
            deletion_event_hash: ZERO_HASH,
            module_hash: [6u8; 32],
            timestamp: 1,
            deletion_seq: 1,
            bls_certificate: None,
            trust_root_key_id: String::new(),
            module_hash_certificate: None,
        };
        let err = super::encode_receipt(&zero).unwrap_err();
        assert!(
            err.contains(zombie_core::ERR_INVALID_EVENT_HASH_ZERO),
            "expected invalid-event-hash:zero, got: {err}"
        );

        // Control: the same receipt with a non-zero event hash encodes.
        let ok = DeletionReceiptV5 {
            deletion_event_hash: [5u8; 32],
            ..zero
        };
        assert!(super::encode_receipt(&ok).is_ok());
    }

    /// P9.3(b): the engine's tombstone-hash construction reproduces the
    /// countersigned zombie-core vector gv5-002, and the constant it binds is
    /// the vector's TOMBSTONE_CONSTANT.
    #[test]
    fn p9_3_compute_tombstone_hash_matches_signed_gv5_002() {
        use crate::corpus::{hex32_at, hex_at, load_signed_v5_vector};

        let v = load_signed_v5_vector(env!("CARGO_MANIFEST_DIR"), "gv5-002").json;
        let canister_id = Principal::from_slice(&hex_at(&v, &["inputs", "canister_id_hex"]));
        let timestamp = v.u64_at(&["inputs", "timestamp"]);
        let deletion_seq = v.u64_at(&["inputs", "deletion_seq"]);

        assert_eq!(
            super::compute_tombstone_hash(&canister_id, timestamp, deletion_seq),
            hex32_at(&v, &["expected", "tombstone_hash"]),
            "gv5-002: tombstone_hash"
        );
        let expected_constant = hex32_at(&v, &["expected", "tombstone_constant"]);
        assert_eq!(
            *zombie_core::TOMBSTONE_CONSTANT,
            expected_constant,
            "gv5-002: TOMBSTONE_CONSTANT"
        );
        // The accessor the engine actually binds at (f).
        assert_eq!(*super::tombstone_constant(), expected_constant);
    }
}
