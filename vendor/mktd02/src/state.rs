//! # State Hash Computation
//!
//! The per-canister salt is derived at runtime (not stored):
//! `mktd_salt = SHA-256(MKTD02_SALT_V1 || canister_id_bytes)`
//!
//! State hash: `SHA-256(mktd_salt || state_bytes)`
//!
//! Note: state_hash uses sha256_concat (salt is not a domain tag but a
//! derived value), while salt derivation uses hash_with_tag.

use crate::storage::{with_storage, with_storage_mut, Hash32};
use zombie_core::hashing::{hash_with_tag, sha256_concat, TAG_SALT};

/// Derive the per-canister salt. Deterministic from canister_id.
pub(crate) fn compute_salt() -> [u8; 32] {
    // ic-cdk 0.18: `ic_cdk::id()` → `ic_cdk::api::canister_self()` (same ic0
    // canister_self syscall). The salt preimage bytes are unchanged.
    hash_with_tag(TAG_SALT, &[ic_cdk::api::canister_self().as_slice()])
}

/// Compute state_hash from PII state bytes.
///
/// `state_hash = SHA-256(mktd_salt || state_bytes)`
pub(crate) fn compute_state_hash(state_bytes: &[u8]) -> [u8; 32] {
    let salt = compute_salt();
    sha256_concat(&[&salt, state_bytes])
}

/// Compute and store the initial state hash. Called during init().
pub(crate) fn init_state_hash(state_bytes: &[u8]) {
    let hash = compute_state_hash(state_bytes);
    with_storage_mut(|s| {
        s.state_hash.set(Hash32(hash));
    });
}

/// Recompute and store state hash after a PII mutation.
pub(crate) fn refresh_state_hash_internal(state_bytes: &[u8]) {
    let hash = compute_state_hash(state_bytes);
    with_storage_mut(|s| {
        s.state_hash.set(Hash32(hash));
    });
}

/// Read the current state hash.
pub(crate) fn read_state_hash() -> [u8; 32] {
    with_storage(|s| s.state_hash.get().0)
}
