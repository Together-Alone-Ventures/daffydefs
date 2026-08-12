//! # Monotonic Deletion Sequence Management
//!
//! Load from stable memory, increment-and-persist, never reuse.
//!
//! ## Trap/Rollback Semantics
//!
//! Deletion-sequence increments are atomic with the enclosing update message.
//! If the message traps after increment, stable memory mutations roll back,
//! so the sequence is **not** advanced. This means the value is not "burned"
//! on trap -- it remains available
//! for the next successful message. This is safe because a trap also
//! aborts receipt emission: no receipt is produced with the rolled-back
//! sequence value.

use crate::storage::{with_storage_mut, StorableU64};

/// Increment the deletion sequence and return the new value.
///
/// The sequence is persisted to stable memory immediately. If the
/// enclosing message traps, stable memory rolls back and the
/// increment does not persist (see module docs on trap semantics).
pub(crate) fn increment_deletion_seq() -> u64 {
    with_storage_mut(|s| {
        let current = s.deletion_seq.get().0;
        let next = current
            .checked_add(1)
            .unwrap_or_else(|| ic_cdk::trap("MKTd02: deletion_seq overflow; cannot issue additional receipts"));
        s.deletion_seq.set(StorableU64(next));
        next
    })
}

