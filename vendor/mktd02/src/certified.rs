//! # Certified Data Management
//!
//! Domain tag: `MKTD02_CERTIFIED_V1`
//!
//! certified_commitment = SHA-256(MKTD02_CERTIFIED_V1 || post_state_hash || deletion_event_hash)
//!
//! ## v0.2.0 Changes (Phase 2)
//!
//! `publish_certified_commitment` now checks the finalization lock.
//! If a receipt is pending finalization (lock held), any attempt to
//! change certified data traps. This is a hard invariant — the BLS
//! certificate captured in Phase B must match the certified data
//! published in Phase A.

use crate::storage::{with_storage, with_storage_mut, Hash32};
use zombie_core::hashing::{hash_with_tag, TAG_CERTIFIED};

/// Compute the certified commitment from state_hash and deletion_event_hash.
pub(crate) fn compute_certified_commitment(
    state_hash: &[u8; 32],
    deletion_event_hash: &[u8; 32],
) -> [u8; 32] {
    hash_with_tag(TAG_CERTIFIED, &[state_hash, deletion_event_hash])
}

/// Compute, store, and publish the certified commitment.
///
/// **Finalization lock guard:** If the finalization lock is held
/// (a receipt is pending finalization), this function traps.
/// The lock prevents certified data drift between Phase A
/// (deletion) and Phase C (finalization).
pub(crate) fn publish_certified_commitment(
    state_hash: &[u8; 32],
    deletion_event_hash: &[u8; 32],
) -> [u8; 32] {
    // Finalization lock guard — hard invariant
    if crate::storage::is_finalization_locked() {
        ic_cdk::trap(
            "MKTd02: cannot change certified data while finalization lock is held. \
             Finalize the pending receipt before upgrading, refreshing state, \
             or performing any action that changes certified data."
        );
    }

    let commitment = compute_certified_commitment(state_hash, deletion_event_hash);
    with_storage_mut(|s| {
        s.certified_commitment.set(Hash32(commitment));
    });
    // ic-cdk 0.18: `set_certified_data(&[u8])` → `certified_data_set(AsRef<[u8]>)`.
    // Both call the identical `ic0::certified_data_set` syscall with the same 32
    // bytes — the V2 / Phase-B certified-data path is behaviour-identical.
    ic_cdk::api::certified_data_set(commitment);
    commitment
}

/// Read the current certified commitment.
pub(crate) fn read_certified_commitment() -> [u8; 32] {
    with_storage(|s| s.certified_commitment.get().0)
}

/// Return (state_hash, Option<certificate>) for certified query responses.
pub fn get_certified_state_hash() -> ([u8; 32], Option<Vec<u8>>) {
    let state_hash = crate::state::read_state_hash();
    let cert = ic_cdk::api::data_certificate();
    (state_hash, cert)
}
