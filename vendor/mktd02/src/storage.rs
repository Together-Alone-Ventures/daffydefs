//! # Stable Memory Layout Manager
//!
//! 8 slots with configurable base MemoryId (default: 100).
//!
//! | Offset  | Content              | Type                                          |
//! |---------|----------------------|-----------------------------------------------|
//! | base+0  | Meta cell            | schema_version, memory_base, init_at, mod_hash, pending_receipt_id |
//! | base+1  | state_hash           | [u8; 32]                                      |
//! | base+2  | deletion_seq         | u64                                           |
//! | base+3  | certified_commitment | [u8; 32]                                      |
//! | base+4  | deletion_event_hash  | [u8; 32]                                      |
//! | base+5  | finalization_lock    | bool (prevents certified_data drift)          |
//! | base+6  | receipt store        | StableBTreeMap<[u8;32], Vec<u8>>              |
//! | base+7  | tombstoned_at        | Option<u64>                                   |
//!
//! Range check on init: base + 7 <= 255, else trap.
//!
//! ## v0.2.0 Changes
//!
//! - Phase 1: Removed `manifest_hash` from slot base+5.
//! - Phase 2: Repurposed base+5 for `finalization_lock` (bool).
//!   When true, all code paths that call `certified_data_set()` trap.
//!   This is a hard invariant that prevents certified data drift
//!   between deletion (Phase A) and finalization (Phase C).
//!
//! ## Endianness Convention
//!
//! - **Stable memory encoding** (Storable impls): little-endian (LE).
//!   This matches ICP's native memory representation.
//! - **Hash preimages** (in hashing.rs, engine.rs, etc.): big-endian (BE).
//!   This follows cryptographic convention for unambiguous byte ordering.
//!
//! These are separate domains and must not be confused.

use ic_stable_structures::memory_manager::{MemoryId, MemoryManager, VirtualMemory};
use ic_stable_structures::storable::Bound;
use ic_stable_structures::{DefaultMemoryImpl, StableBTreeMap, StableCell, Storable};
use std::borrow::Cow;
use std::cell::RefCell;

pub(crate) type Memory = VirtualMemory<DefaultMemoryImpl>;

// ---------------------------------------------------------------------------
// Storable wrapper types
// ---------------------------------------------------------------------------

/// 32-byte hash wrapper with Storable + Ord for use as StableBTreeMap key.
#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Hash32(pub [u8; 32]);

impl Storable for Hash32 {
    fn to_bytes(&self) -> Cow<'_, [u8]> {
        Cow::Borrowed(&self.0)
    }
    fn from_bytes(bytes: Cow<'_, [u8]>) -> Self {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Self(arr)
    }
    // is-0.7 added `into_bytes` as a required trait method. Delegating to
    // `to_bytes().into_owned()` guarantees the bytes WRITTEN to stable memory
    // are byte-identical to the v0.4.0 (is-0.6) encoding — Prime-Directive safe.
    fn into_bytes(self) -> Vec<u8> {
        self.to_bytes().into_owned()
    }
    const BOUND: Bound = Bound::Bounded {
        max_size: 32,
        is_fixed_size: true,
    };
}

/// Meta cell (legacy + current decoding):
///
/// - Legacy layout (49 bytes):
///   schema_version(4) + memory_base(4) + has_init(1) + init_at(8) + module_hash(32)
/// - Current layout (82 bytes):
///   legacy(49) + has_pending_receipt_id(1) + pending_receipt_id(32)
///
/// All integer fields use little-endian encoding (stable memory convention).
#[derive(Clone, Debug)]
pub(crate) struct MetaCell {
    pub schema_version: u32,
    pub memory_base: u32,
    pub initialised_at: Option<u64>,
    pub module_hash: [u8; 32],
    pub pending_receipt_id: Option<[u8; 32]>,
}

impl Default for MetaCell {
    fn default() -> Self {
        Self {
            schema_version: 0,
            memory_base: 0,
            initialised_at: None,
            module_hash: [0u8; 32],
            pending_receipt_id: None,
        }
    }
}

impl Storable for MetaCell {
    fn to_bytes(&self) -> Cow<'_, [u8]> {
        let mut buf = vec![0u8; 82];
        buf[0..4].copy_from_slice(&self.schema_version.to_le_bytes());
        buf[4..8].copy_from_slice(&self.memory_base.to_le_bytes());
        match self.initialised_at {
            Some(ts) => {
                buf[8] = 1;
                buf[9..17].copy_from_slice(&ts.to_le_bytes());
            }
            None => {} // already zeroed
        }
        buf[17..49].copy_from_slice(&self.module_hash);
        if let Some(pending_id) = self.pending_receipt_id {
            buf[49] = 1;
            buf[50..82].copy_from_slice(&pending_id);
        }
        Cow::Owned(buf)
    }
    fn from_bytes(bytes: Cow<'_, [u8]>) -> Self {
        let raw = bytes.as_ref();
        if raw.len() != 49 && raw.len() != 82 {
            ic_cdk::trap(&format!(
                "MKTd02: invalid MetaCell byte length {} (expected 49 or 82)",
                raw.len()
            ));
        }
        let schema_version = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
        let memory_base = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
        let has_init = bytes[8];
        let init_val = u64::from_le_bytes(bytes[9..17].try_into().unwrap());
        let initialised_at = if has_init == 1 { Some(init_val) } else { None };
        let mut module_hash = [0u8; 32];
        module_hash.copy_from_slice(&bytes[17..49]);
        let pending_receipt_id = if raw.len() == 82 && bytes[49] == 1 {
            let mut pending_id = [0u8; 32];
            pending_id.copy_from_slice(&bytes[50..82]);
            Some(pending_id)
        } else {
            None
        };
        Self {
            schema_version,
            memory_base,
            initialised_at,
            module_hash,
            pending_receipt_id,
        }
    }
    fn into_bytes(self) -> Vec<u8> {
        self.to_bytes().into_owned()
    }
    const BOUND: Bound = Bound::Bounded {
        max_size: 82,
        is_fixed_size: false,
    };
}

/// u64 wrapper for deletion sequence storage. Little-endian encoding.
#[derive(Clone, Debug, Default)]
pub(crate) struct StorableU64(pub u64);

impl Storable for StorableU64 {
    fn to_bytes(&self) -> Cow<'_, [u8]> {
        Cow::Owned(self.0.to_le_bytes().to_vec())
    }
    fn from_bytes(bytes: Cow<'_, [u8]>) -> Self {
        Self(u64::from_le_bytes(bytes[0..8].try_into().unwrap()))
    }
    fn into_bytes(self) -> Vec<u8> {
        self.to_bytes().into_owned()
    }
    const BOUND: Bound = Bound::Bounded {
        max_size: 8,
        is_fixed_size: true,
    };
}

/// Bool wrapper for stable memory. 1 byte: 0 = false, 1 = true.
///
/// Used for the finalization lock at base+5.
#[derive(Clone, Debug, Default)]
pub(crate) struct StorableBool(pub bool);

impl Storable for StorableBool {
    fn to_bytes(&self) -> Cow<'_, [u8]> {
        Cow::Owned(vec![if self.0 { 1u8 } else { 0u8 }])
    }
    fn from_bytes(bytes: Cow<'_, [u8]>) -> Self {
        Self(bytes[0] == 1)
    }
    fn into_bytes(self) -> Vec<u8> {
        self.to_bytes().into_owned()
    }
    const BOUND: Bound = Bound::Bounded {
        max_size: 1,
        is_fixed_size: true,
    };
}

/// Optional timestamp for tombstoned_at: 1 byte discriminant + 8 bytes u64 (LE).
///
/// **This field is engine-owned.** Only `execute_deletion()` may set it.
/// External code must not write to this slot directly.
#[derive(Clone, Debug, Default)]
pub(crate) struct OptionalTimestamp(pub Option<u64>);

impl Storable for OptionalTimestamp {
    fn to_bytes(&self) -> Cow<'_, [u8]> {
        let mut buf = vec![0u8; 9];
        if let Some(ts) = self.0 {
            buf[0] = 1;
            buf[1..9].copy_from_slice(&ts.to_le_bytes());
        }
        Cow::Owned(buf)
    }
    fn from_bytes(bytes: Cow<'_, [u8]>) -> Self {
        if bytes[0] == 1 {
            let ts = u64::from_le_bytes(bytes[1..9].try_into().unwrap());
            Self(Some(ts))
        } else {
            Self(None)
        }
    }
    fn into_bytes(self) -> Vec<u8> {
        self.to_bytes().into_owned()
    }
    const BOUND: Bound = Bound::Bounded {
        max_size: 9,
        is_fixed_size: true,
    };
}

/// Receipt value wrapper (CBOR-encoded DeletionReceipt).
///
/// Max size: 16384 bytes. A finalized v4 receipt carries two delegation-bearing
/// certificates (`bls_certificate` + `module_hash_certificate`, ~2 KB each on
/// mainnet) plus the fixed body (~300 B) ≈ 4–6 KB — comfortably within this
/// bound. Raised from 8192 (v0.4.x) as a pre-deploy constant change; no MKTd02
/// instance is deployed, so this is not a storage migration.
#[derive(Clone, Debug)]
pub(crate) struct ReceiptBytes(pub Vec<u8>);

impl Storable for ReceiptBytes {
    fn to_bytes(&self) -> Cow<'_, [u8]> {
        Cow::Borrowed(&self.0)
    }
    fn from_bytes(bytes: Cow<'_, [u8]>) -> Self {
        Self(bytes.to_vec())
    }
    fn into_bytes(self) -> Vec<u8> {
        self.to_bytes().into_owned()
    }
    const BOUND: Bound = Bound::Bounded {
        max_size: 16384,
        is_fixed_size: false,
    };
}

// ---------------------------------------------------------------------------
// Main storage struct
// ---------------------------------------------------------------------------

pub(crate) struct MktdStorage {
    pub meta: StableCell<MetaCell, Memory>,
    pub state_hash: StableCell<Hash32, Memory>,
    pub deletion_seq: StableCell<StorableU64, Memory>,
    pub certified_commitment: StableCell<Hash32, Memory>,
    pub deletion_event_hash: StableCell<Hash32, Memory>,
    pub finalization_lock: StableCell<StorableBool, Memory>,
    pub receipts: StableBTreeMap<Hash32, ReceiptBytes, Memory>,
    pub tombstoned_at: StableCell<OptionalTimestamp, Memory>,
}

thread_local! {
    static STORAGE: RefCell<Option<MktdStorage>> = RefCell::new(None);
}

/// Schema version for the current storage layout.
const SCHEMA_VERSION: u32 = 1;

/// Initialise or reconnect to MKTd02 stable memory slots.
///
/// Called by both `init()` and `on_post_upgrade()`.
pub(crate) fn setup_storage(mm: &MemoryManager<DefaultMemoryImpl>, base: u8) {
    // Range check
    if (base as u16) + 7 > 255 {
        ic_cdk::trap(&format!(
            "MKTd02: base MemoryId {} + 7 exceeds 255. Choose a lower base.",
            base
        ));
    }

    // is-0.7: `StableCell::init` returns `Self` (was `Result` in is-0.6); the
    // `.expect(...)` wrappers are dropped. Slot assignments base..=base+7 and the
    // on-disk Cell/BTreeMap format are unchanged (1d-preserving).
    let storage = MktdStorage {
        meta: StableCell::init(mm.get(MemoryId::new(base)), MetaCell::default()),
        state_hash: StableCell::init(mm.get(MemoryId::new(base + 1)), Hash32::default()),
        deletion_seq: StableCell::init(mm.get(MemoryId::new(base + 2)), StorableU64::default()),
        certified_commitment: StableCell::init(mm.get(MemoryId::new(base + 3)), Hash32::default()),
        deletion_event_hash: StableCell::init(mm.get(MemoryId::new(base + 4)), Hash32::default()),
        finalization_lock: StableCell::init(mm.get(MemoryId::new(base + 5)), StorableBool::default()),
        receipts: StableBTreeMap::init(mm.get(MemoryId::new(base + 6))),
        tombstoned_at: StableCell::init(mm.get(MemoryId::new(base + 7)), OptionalTimestamp::default()),
    };

    // Collision detection (belt-and-suspenders):
    // Check initialised_at, schema_version, or memory_base to detect prior init.
    let existing = storage.meta.get();
    let previously_initialised = existing.initialised_at.is_some()
        || existing.schema_version != 0
        || existing.memory_base != 0;

    if previously_initialised && existing.memory_base != base as u32 {
        ic_cdk::trap(&format!(
            "MKTd02 already initialised at base={}; requested base={}",
            existing.memory_base, base
        ));
    }

    // Schema version gate: refuse to run against an unknown layout.
    if previously_initialised && existing.schema_version != SCHEMA_VERSION {
        ic_cdk::trap(&format!(
            "MKTd02: schema version mismatch — stored={}, expected={}. \
             Downgrade is not supported; upgrade migration required.",
            existing.schema_version, SCHEMA_VERSION
        ));
    }

    STORAGE.with(|s| {
        *s.borrow_mut() = Some(storage);
    });
}

/// Access storage immutably. Traps if not initialised.
pub(crate) fn with_storage<R>(f: impl FnOnce(&MktdStorage) -> R) -> R {
    STORAGE.with(|s| {
        let borrow = s.borrow();
        let storage = borrow
            .as_ref()
            .unwrap_or_else(|| ic_cdk::trap("MKTd02: not initialised. Call init() first."));
        f(storage)
    })
}

/// Access storage mutably. Traps if not initialised.
pub(crate) fn with_storage_mut<R>(f: impl FnOnce(&mut MktdStorage) -> R) -> R {
    STORAGE.with(|s| {
        let mut borrow = s.borrow_mut();
        let storage = borrow
            .as_mut()
            .unwrap_or_else(|| ic_cdk::trap("MKTd02: not initialised. Call init() first."));
        f(storage)
    })
}

/// Check whether storage has been set up (for is_initialised checks).
pub(crate) fn storage_exists() -> bool {
    STORAGE.with(|s| s.borrow().is_some())
}

pub(crate) const fn schema_version() -> u32 {
    SCHEMA_VERSION
}

// ---------------------------------------------------------------------------
// Finalization lock helpers
// ---------------------------------------------------------------------------

/// Check whether the finalization lock is held.
///
/// When true, a receipt is pending finalization and no code path
/// may call `certified_data_set()`.
pub(crate) fn is_finalization_locked() -> bool {
    with_storage(|s| s.finalization_lock.get().0)
}

/// Acquire the finalization lock. Traps if already held.
pub(crate) fn acquire_finalization_lock() {
    if is_finalization_locked() {
        ic_cdk::trap("MKTd02: finalization lock already held — finalize the pending receipt first");
    }
    with_storage_mut(|s| {
        // is-0.7: `set` returns the old value (was `Result`); `.expect` dropped.
        s.finalization_lock.set(StorableBool(true));
    });
}

/// Release the finalization lock. Traps if not held.
pub(crate) fn release_finalization_lock() {
    if !is_finalization_locked() {
        ic_cdk::trap("MKTd02: finalization lock not held — nothing to release");
    }
    with_storage_mut(|s| {
        s.finalization_lock.set(StorableBool(false));
        let mut meta = s.meta.get().clone();
        meta.pending_receipt_id = None;
        s.meta.set(meta);
    });
}

/// Persist the pending receipt ID while finalization lock is held.
pub(crate) fn set_pending_receipt_id(receipt_id: [u8; 32]) {
    with_storage_mut(|s| {
        let mut meta = s.meta.get().clone();
        meta.pending_receipt_id = Some(receipt_id);
        s.meta.set(meta);
    });
}

/// Read the persisted pending receipt ID (if any).
pub(crate) fn pending_receipt_id() -> Option<[u8; 32]> {
    with_storage(|s| s.meta.get().pending_receipt_id)
}

#[cfg(test)]
mod tests {
    use super::{
        acquire_finalization_lock, pending_receipt_id, release_finalization_lock,
        set_pending_receipt_id, setup_storage, MetaCell,
    };
    use ic_stable_structures::memory_manager::MemoryManager;
    use ic_stable_structures::{DefaultMemoryImpl, Storable};
    use std::borrow::Cow;

    fn setup_test_storage(base: u8) {
        let mm = MemoryManager::init(DefaultMemoryImpl::default());
        setup_storage(&mm, base);
    }

    #[test]
    fn meta_cell_decodes_legacy_49_byte_layout() {
        let mut legacy = vec![0u8; 49];
        legacy[0..4].copy_from_slice(&7u32.to_le_bytes());
        legacy[4..8].copy_from_slice(&123u32.to_le_bytes());
        legacy[8] = 1;
        legacy[9..17].copy_from_slice(&42u64.to_le_bytes());
        legacy[17..49].copy_from_slice(&[0x11; 32]);

        let decoded = MetaCell::from_bytes(Cow::Owned(legacy));
        assert_eq!(decoded.schema_version, 7);
        assert_eq!(decoded.memory_base, 123);
        assert_eq!(decoded.initialised_at, Some(42));
        assert_eq!(decoded.module_hash, [0x11; 32]);
        assert_eq!(decoded.pending_receipt_id, None);
    }

    #[test]
    fn meta_cell_roundtrip_preserves_pending_receipt_id() {
        let meta = MetaCell {
            schema_version: 1,
            memory_base: 100,
            initialised_at: Some(99),
            module_hash: [0x22; 32],
            pending_receipt_id: Some([0x33; 32]),
        };
        let encoded = meta.to_bytes();
        assert_eq!(encoded.len(), 82);
        let decoded = MetaCell::from_bytes(encoded);
        assert_eq!(decoded.schema_version, meta.schema_version);
        assert_eq!(decoded.memory_base, meta.memory_base);
        assert_eq!(decoded.initialised_at, meta.initialised_at);
        assert_eq!(decoded.module_hash, meta.module_hash);
        assert_eq!(decoded.pending_receipt_id, meta.pending_receipt_id);
    }

    #[test]
    fn release_lock_clears_pending_receipt_id() {
        setup_test_storage(101);
        acquire_finalization_lock();
        set_pending_receipt_id([0x55; 32]);
        assert_eq!(pending_receipt_id(), Some([0x55; 32]));
        release_finalization_lock();
        assert_eq!(pending_receipt_id(), None);
    }
}
