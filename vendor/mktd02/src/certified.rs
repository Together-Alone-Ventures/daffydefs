//! # Certified Data Management (mktd02-v5, Direct Certification)
//!
//! Direct Certification (SR-06): the canister's certified data holds the
//! `deletion_event_hash` itself. Before any deletion it holds the genesis value
//! `zombie_core::genesis_certified_data(canister_id)`. There is no
//! certified commitment, and this module does no hashing.
//!
//! Exactly two functions write certified data:
//! - `publish_deletion_certified` — the ONLY function that may set a NEW
//!   certified value; called from the deletion path only.
//! - `restore_certified` — re-sets the value already recorded at base+4, or
//!   genesis if base+4 is unset; called from the lifecycle hooks only
//!   (`first_init`, `post_upgrade`). Never computes or advances a value.
//!
//! Both trap while the finalization lock is held.
//!
//! **Callers are enforced by module visibility.** Each writer takes a proof
//! token whose field is private to its one permitted caller module:
//! `engine::DeletionPath` (the deletion path) and
//! `lifecycle::LifecycleHook` (`first_init` / `upgrade_cascade`). No
//! other module can construct either token, so no other module can call them.

use crate::engine::DeletionPath;
use crate::lifecycle::LifecycleHook;
use crate::storage::with_storage;
use zombie_core::genesis_certified_data;
use zombie_core::hashing::ZERO_HASH;

/// Finalization lock guard — hard invariant for every certified-data write.
/// See the lock's restated purpose in `storage.rs` ("Finalization lock
/// helpers").
fn trap_if_finalization_locked() {
    if crate::storage::is_finalization_locked() {
        ic_cdk::trap(
            "MKTd02: cannot change certified data while finalization lock is held. \
             Finalize the pending receipt before upgrading or performing any \
             action that changes certified data.",
        );
    }
}

/// Publish `deletion_event_hash` as the canister's certified data.
///
/// The ONLY function that may set a NEW certified value. Deletion path only
/// (enforced: only `engine` can mint a `DeletionPath`). Traps if the
/// finalization lock is held.
pub(crate) fn publish_deletion_certified(_on: DeletionPath, deletion_event_hash: &[u8; 32]) {
    trap_if_finalization_locked();
    ic_cdk::api::certified_data_set(deletion_event_hash);
}

/// Re-set certified data to the value recorded at base+4, or to
/// `genesis_certified_data(canister_id)` if base+4 is unset (all-zero; the
/// engine never produces a zero `deletion_event_hash`).
///
/// Lifecycle hooks only (`first_init`, `post_upgrade`; enforced: only
/// `lifecycle` can mint a `LifecycleHook`). Never computes or advances a
/// value: genesis comes from zombie-core. Traps if the finalization lock is
/// held.
pub(crate) fn restore_certified(_on: LifecycleHook) {
    trap_if_finalization_locked();
    let recorded = with_storage(|s| s.deletion_event_hash.get().0);
    let value = if recorded == ZERO_HASH {
        genesis_certified_data(&ic_cdk::api::canister_self())
    } else {
        recorded
    };
    ic_cdk::api::certified_data_set(value);
}
