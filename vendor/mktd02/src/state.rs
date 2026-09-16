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
use candid::Principal;
use zombie_core::hashing::{hash_with_tag, sha256_concat, TAG_SALT};

/// Derive the per-canister salt. Deterministic from canister_id. Pure, so it
/// is checked directly against the countersigned zombie-core vector gv5-011.
pub(crate) fn compute_salt_for(canister_id: &Principal) -> [u8; 32] {
    hash_with_tag(TAG_SALT, &[canister_id.as_slice()])
}

/// Compute state_hash from PII state bytes.
///
/// `state_hash = SHA-256(mktd_salt || state_bytes)`
pub(crate) fn compute_state_hash(state_bytes: &[u8]) -> [u8; 32] {
    // ic-cdk 0.18: `ic_cdk::id()` → `ic_cdk::api::canister_self()` (same ic0
    // canister_self syscall). The salt preimage bytes are unchanged.
    compute_state_hash_for(&ic_cdk::api::canister_self(), state_bytes)
}

/// The state-hash construction over an explicit canister_id (pure; see
/// [`compute_salt_for`]).
pub(crate) fn compute_state_hash_for(canister_id: &Principal, state_bytes: &[u8]) -> [u8; 32] {
    let salt = compute_salt_for(canister_id);
    sha256_concat(&[&salt, state_bytes])
}

/// Compute and store the initial state hash. Called during init().
pub(crate) fn init_state_hash(state_bytes: &[u8]) {
    let hash = compute_state_hash(state_bytes);
    with_storage_mut(|s| {
        s.state_hash.set(Hash32(hash));
    });
}

/// Read the current state hash.
pub(crate) fn read_state_hash() -> [u8; 32] {
    with_storage(|s| s.state_hash.get().0)
}

#[cfg(test)]
mod tests {
    use candid::Principal;

    /// P9.4(a): Leaf's salt and state-hash construction reproduce the
    /// countersigned zombie-core vector gv5-011 over its state_bytes and
    /// canister_id.
    #[test]
    fn p9_4_state_hash_construction_matches_signed_gv5_011() {
        use crate::corpus::{hex32_at, hex_at, load_signed_v5_vector};

        let v = load_signed_v5_vector(env!("CARGO_MANIFEST_DIR"), "gv5-011").json;
        let canister_id = Principal::from_slice(&hex_at(&v, &["inputs", "canister_id_hex"]));
        let state_bytes = hex_at(&v, &["inputs", "state_bytes_hex"]);

        assert_eq!(
            super::compute_salt_for(&canister_id),
            hex32_at(&v, &["expected", "mktd_salt"]),
            "gv5-011: mktd_salt"
        );
        assert_eq!(
            super::compute_state_hash_for(&canister_id, &state_bytes),
            hex32_at(&v, &["expected", "state_hash"]),
            "gv5-011: state_hash"
        );
    }
}
