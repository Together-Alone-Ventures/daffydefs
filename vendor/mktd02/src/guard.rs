//! # Tombstone & Initialisation Guards
//!
//! - `is_tombstoned()` -- reads tombstoned_at from stable memory
//! - `is_initialised()` -- checks meta cell for initialised state
//! - `assert_can_write()` -- traps if tombstoned or not initialised

use crate::storage::{storage_exists, with_storage};

/// Check whether the canister has been tombstoned.
pub fn is_tombstoned() -> bool {
    if !storage_exists() {
        return false;
    }
    with_storage(|s| s.tombstoned_at.get().0.is_some())
}

/// Check whether MKTd02 has been initialised.
pub fn is_initialised() -> bool {
    if !storage_exists() {
        return false;
    }
    with_storage(|s| s.meta.get().initialised_at.is_some())
}

/// Trap if the canister is tombstoned or not initialised.
///
/// For use in non-Result functions that prefer trap-on-error semantics.
/// Functions returning `Result<T, E> where E: GuardError` should use
/// the `#[mktd_guard]` macro instead.
pub fn assert_can_write() {
    if !is_initialised() {
        ic_cdk::trap("MKTd02: not initialised");
    }
    if is_tombstoned() {
        ic_cdk::trap("MKTd02: canister is tombstoned");
    }
}
