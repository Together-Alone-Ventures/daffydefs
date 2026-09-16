//! # Lifecycle Hooks (`first_init`, `upgrade_cascade`)
//!
//! Moved out of `engine.rs` (mktd02-v5, item 4.1) so that module visibility can
//! tell the lifecycle hooks apart from the deletion path: only this module can
//! mint a [`LifecycleHook`], and `certified::restore_certified` requires one.

use crate::certified::restore_certified;
use crate::state::compute_state_hash;
use crate::storage::{with_storage_mut, Hash32, MetaCell};
use crate::trait_def::MKTdDataSource;
use crate::MktdConfig;

/// Proof of being in a lifecycle hook. The field is private to this module, so
/// only `first_init` / `upgrade_cascade` can construct it — this restricts
/// `certified::restore_certified` to the lifecycle hooks by module visibility.
pub(crate) struct LifecycleHook(());

/// Upgrade cascade: recompute state hash and update module_hash.
///
/// mktd02-v5: re-sets certified data via `restore_certified` to the value
/// already recorded at base+4 (or genesis if no deletion has occurred). It
/// never computes or advances a certified value, and does so whether or not
/// the platform preserved certified data across the upgrade.
///
/// R-B (12 Sep 2026): if the finalization lock is held (receipt pending),
/// `restore_certified` traps — an upgrade cannot occur mid-finalization.
/// You must finalize the pending receipt before upgrading. `restore_certified`
/// therefore only ever runs for upgrades outside the pending window.
pub(crate) fn upgrade_cascade<A: MKTdDataSource>(adapter: &A, module_hash: [u8; 32]) {
    // Always recompute state_hash (defensive — catches adapter changes)
    let state_bytes = adapter.get_state_bytes();
    let new_state_hash = compute_state_hash(&state_bytes);
    with_storage_mut(|s| {
        s.state_hash.set(Hash32(new_state_hash));
    });

    // Restore the recorded certified value (never computes or advances one).
    // (Will trap if finalization lock is held — see certified.rs)
    restore_certified(LifecycleHook(()));

    // Update module_hash unconditionally
    with_storage_mut(|s| {
        let mut meta = s.meta.get().clone();
        meta.module_hash = module_hash;
        s.meta.set(meta);
    });
}

/// First-time initialisation logic.
///
/// mktd02-v5: publishes the genesis certified value via `restore_certified`
/// (base+4 is unset at first init). Does not write base+4; touches base+1 only
/// to initialise it.
pub(crate) fn first_init<A: MKTdDataSource>(
    adapter: &A,
    config: &MktdConfig,
    module_hash: [u8; 32],
) {
    let timestamp = ic_cdk::api::time();

    crate::state::init_state_hash(&adapter.get_state_bytes());

    // base+4 is unset at first init, so this publishes genesis.
    restore_certified(LifecycleHook(()));

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
