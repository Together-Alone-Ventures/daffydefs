//! # MKTd02 -- Leaf-Mode CVDR Engine (ICP)
//!
//! MKTd02 provides Leaf-mode deletion receipts for single-subject canisters.
//!
//! ## Canonical flow
//!
//! 1. `init()` / `on_post_upgrade()`
//! 2. Guard PII mutations
//! 3. `execute_deletion()` (Phase A, pending receipt)
//! 4. `get_pending_certificate()` in query context (Phase B)
//! 5. `finalize_receipt()` (Phase C)
//!
//! mktd02-v5: there is no per-write state-hash refresh (removed); the only
//! certified value a canister ever publishes is genesis, then its
//! `deletion_event_hash`.
//!
//! ## Platform constraint
//!
//! Phase B exists because `ic0.data_certificate()` is query-only on ICP.
//!
//! ## Clarification
//!
//! Deterministic CBOR statements in this project are based on project encoder
//! constraints and integration rules, not a blanket RFC canonical-CBOR claim.

pub mod certified;
#[cfg(test)]
mod corpus;
pub mod engine;
pub mod export;
pub mod finalization;
pub mod guard;
mod lifecycle;
pub mod nonce;
pub mod state;
pub mod storage;
pub mod trait_def;

// --- Re-exports ---
pub use engine::DeletionError;
pub use finalization::{FinalizationError, PendingCertificate};
pub use trait_def::{CommitMode, GuardError, MKTdDataSource};
pub use zombie_core::{
    AnyDeletionReceipt, DeletionReceiptV4, DeletionReceiptV5, FieldDescriptor, ProtocolVersion,
    ReceiptSummary,
};

use ic_stable_structures::memory_manager::MemoryManager;
use ic_stable_structures::DefaultMemoryImpl;
use storage::Hash32;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration for MKTd02 initialisation.
pub struct MktdConfig {
    /// Base MemoryId for MKTd02's 8 stable memory slots (default: 100).
    /// Range: base + 7 must be <= 255.
    pub base_memory_id: u8,
}

impl Default for MktdConfig {
    fn default() -> Self {
        Self {
            base_memory_id: 100,
        }
    }
}

// ---------------------------------------------------------------------------
// Public API — Lifecycle
// ---------------------------------------------------------------------------

/// First-time initialisation. Call from `#[init]`.
///
/// Sets up stable memory, computes initial state hash, publishes the genesis
/// certified value (`genesis_certified_data(canister_id)`, mktd02-v5). Module
/// hash is provided by the deployer
/// (see Module Hash: Deployment Patterns in the Integration Guide).
pub fn init<A: MKTdDataSource>(
    adapter: &A,
    memory_manager: &MemoryManager<DefaultMemoryImpl>,
    config: MktdConfig,
    module_hash: [u8; 32],
) {
    storage::setup_storage(memory_manager, config.base_memory_id);
    if guard::is_initialised() {
        return;
    }
    lifecycle::first_init(adapter, &config, module_hash);
}

/// Post-upgrade handler. Call from `#[post_upgrade]`.
///
/// Reconnects to stable memory, recomputes state hash, restores the recorded
/// certified value (the last `deletion_event_hash`, or genesis if none — never
/// a new value), and updates module_hash unconditionally.
///
/// **If the finalization lock is held** (a receipt is pending
/// finalization), the upgrade will trap. Finalize the pending receipt
/// before upgrading.
pub fn on_post_upgrade<A: MKTdDataSource>(
    adapter: &A,
    memory_manager: &MemoryManager<DefaultMemoryImpl>,
    config: MktdConfig,
    module_hash: [u8; 32],
) {
    storage::setup_storage(memory_manager, config.base_memory_id);

    // If not yet initialised (upgrade that adds MKTd02), run first_init.
    if !guard::is_initialised() {
        lifecycle::first_init(adapter, &config, module_hash);
    }

    lifecycle::upgrade_cascade(adapter, module_hash);
}

// ---------------------------------------------------------------------------
// Public API — Deletion (Phase A)
// ---------------------------------------------------------------------------

/// Execute deletion: tombstone PII and generate a CVDR (Phase A).
///
/// Returns the 32-byte receipt_id on success. The receipt is in
/// **pending** state (bls_certificate = None). Call
/// `get_pending_certificate()` then `finalize_receipt()` to complete
/// the three-phase flow.
///
/// After this call, the **finalization lock is held** — no upgrades or
/// other certified data changes are permitted until the receipt is
/// finalized.
pub fn execute_deletion<A: MKTdDataSource>(
    adapter: &mut A,
    config: &MktdConfig,
) -> Result<[u8; 32], DeletionError> {
    engine::execute_deletion(adapter, config)
}

/// Execute deletion with a **host-supplied** `record_id` (Phase A).
///
/// Identical to [`execute_deletion`] except `record_id` is supplied by the
/// caller instead of being derived from `ic_cdk::caller()`. The `record_id`
/// is treated as opaque bytes — stored in the receipt and fed into the
/// receipt-id computation verbatim, with no hashing, parsing, or validation.
pub fn execute_deletion_with_record_id<A: MKTdDataSource>(
    adapter: &mut A,
    config: &MktdConfig,
    record_id: Vec<u8>,
) -> Result<[u8; 32], DeletionError> {
    engine::execute_deletion_with_record_id(adapter, config, record_id)
}

// ---------------------------------------------------------------------------
// Public API — Certificate Retrieval (Phase B)
// ---------------------------------------------------------------------------

/// Retrieve the BLS certificate for the pending receipt (Phase B).
///
/// **Must be called from a query endpoint.** `ic0.data_certificate()`
/// is only available in query context.
///
/// Returns `None` if:
/// - No receipt is pending finalization
/// - The IC runtime does not provide a certificate
///
/// The orchestrator passes `PendingCertificate.certificate` and the
/// NNS root key to `finalize_receipt()`.
pub fn get_pending_certificate() -> Option<PendingCertificate> {
    finalization::get_pending_certificate()
}

// ---------------------------------------------------------------------------
// Public API — Finalization (Phase C)
// ---------------------------------------------------------------------------

/// Finalize a pending receipt by embedding certificate material (Phase C).
///
/// Parameters:
/// - `receipt_id`: receipt ID expected for the current pending flow
/// - `certificate`: BLS certificate blob captured in Phase B
/// - `module_hash_certificate`: certificate captured by the off-canister helper
///   from a `read_state` over `/canister/<id>/module_hash`. Stored **opaquely**
///   (no in-canister parsing/validation; the verifier is the trust point).
///
/// Guard semantics (see `finalization.rs` for exact behavior):
/// - pending/finalization-lock state must be valid
/// - provided `receipt_id` must match expected pending receipt ID
/// - receipt must not already be finalized
/// - caller authorization checks are enforced by finalization logic
///
/// On success:
/// - both certificates + `trust_root_key_id` are embedded into the receipt
///   (it becomes a `FinalizedCandidate`)
/// - finalization lock is released
///
/// Note:
/// A→B→C orchestration follows ICP query/update semantics.
pub fn finalize_receipt(
    receipt_id: &[u8; 32],
    certificate: Vec<u8>,
    module_hash_certificate: Vec<u8>,
) -> Result<(), FinalizationError> {
    finalization::finalize_receipt(receipt_id, certificate, module_hash_certificate)
}

/// Host-authorized Phase C finalize — **no controller check** (Phase C).
///
/// # SECURITY
///
/// Performs **no caller/controller check**. The host delete-pipeline **MUST**
/// complete its own authorization of the deletion subject **before** calling
/// this. **Crate/library API only — do NOT expose it directly as a Candid
/// `#[update]` method.** See
/// [`finalization::finalize_receipt_after_host_authorization`] for the full
/// security contract.
pub fn finalize_receipt_after_host_authorization(
    receipt_id: &[u8; 32],
    certificate: Vec<u8>,
    module_hash_certificate: Vec<u8>,
) -> Result<(), FinalizationError> {
    finalization::finalize_receipt_after_host_authorization(
        receipt_id,
        certificate,
        module_hash_certificate,
    )
}

/// Check whether a receipt is pending finalization.
pub fn is_pending_finalization() -> bool {
    finalization::is_pending_finalization()
}

// ---------------------------------------------------------------------------
// Public API — Queries & State
// ---------------------------------------------------------------------------

/// Check whether the canister is tombstoned.
pub fn is_tombstoned() -> bool {
    guard::is_tombstoned()
}

/// Check whether MKTd02 has been initialised.
pub fn is_initialised() -> bool {
    guard::is_initialised()
}

/// **Operational diagnostic** (4.7): the state hash stored at base+1. Call
/// from a QUERY; reads and returns only. Not a verification input and never a
/// certified value — no PASS/FAIL path reads it.
pub fn diag_state_hash() -> [u8; 32] {
    state::read_state_hash()
}

/// Retrieve a stored receipt by ID.
///
/// Stored receipts may predate mktd02-v5 (an issued v2/v3/v4 receipt of a
/// canister upgraded onto v5 code), so decode dispatches on
/// `protocol_version` via [`AnyDeletionReceipt`].
pub fn get_receipt(receipt_id: &[u8; 32]) -> Option<AnyDeletionReceipt> {
    storage::with_storage(|s| {
        s.receipts
            .get(&Hash32(*receipt_id))
            .and_then(|bytes| AnyDeletionReceipt::from_cbor(bytes.0.as_slice()).ok())
    })
}

/// Retrieve a lightweight receipt summary by ID.
pub fn get_receipt_summary(receipt_id: &[u8; 32]) -> Option<ReceiptSummary> {
    get_receipt(receipt_id).map(|r| match &r {
        AnyDeletionReceipt::V4(r) => ReceiptSummary::from(r),
        AnyDeletionReceipt::V5(r) => ReceiptSummary::from(r),
    })
}

/// Get tombstone status (timestamp if tombstoned).
pub fn get_tombstone_status() -> Option<u64> {
    storage::with_storage(|s| s.tombstoned_at.get().0)
}

/// Get the number of stored receipts.
pub fn receipt_count() -> u64 {
    storage::with_storage(|s| s.receipts.len())
}

/// Trap if not initialised or tombstoned. For non-Result functions.
pub fn assert_can_write() {
    guard::assert_can_write();
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_stable_structures::memory_manager::MemoryManager;
    use ic_stable_structures::DefaultMemoryImpl;
    use storage::ReceiptBytes;

    /// An ISSUED mktd02-v3 receipt, byte-for-byte: zombie-core's pinned v3 CBOR
    /// golden (`V3_CBOR_HEX` in zombie-core src/receipt.rs; identical at revs
    /// f0487865 and 70f62a6).
    const ISSUED_V3_CBOR_HEX: &str = "ae7070726f746f636f6c5f76657273696f6e696d6b746430322d76336a726563656970745f6964982001010101010101010101010101010101010101010101010101010101010101016b63616e69737465725f69644401020304697265636f72645f6964830a0b0c6e7072655f73746174655f68617368982002020202020202020202020202020202020202020202020202020202020202026f706f73745f73746174655f68617368982003030303030303030303030303030303030303030303030303030303030303036e746f6d6273746f6e655f68617368982004040404040404040404040404040404040404040404040404040404040404047364656c6574696f6e5f6576656e745f6861736898200505050505050505050505050505050505050505050505050505050505050505746365727469666965645f636f6d6d69746d656e74982006060606060606060606060606060606060606060606060606060606060606066b6d6f64756c655f68617368982007070707070707070707070707070707070707070707070707070707070707076974696d657374616d701a000f42406c64656c6574696f6e5f736571076f626c735f63657274696669636174658318aa18bb18cc7174727573745f726f6f745f6b65795f6964676d61696e6e6574";

    fn encode_v4(r: &DeletionReceiptV4) -> Vec<u8> {
        let mut buf = Vec::new();
        ciborium::into_writer(r, &mut buf).unwrap();
        buf
    }

    /// T10: issued v2/v3/v4 receipts in the receipt store decode through
    /// `get_receipt` (AnyDeletionReceipt) as DeletionReceiptV4 and re-export
    /// byte-for-byte.
    #[test]
    fn t10_issued_v2_v3_v4_receipts_decode_as_v4_and_reexport_byte_for_byte() {
        storage::setup_storage(&MemoryManager::init(DefaultMemoryImpl::default()), 130);

        let v3_bytes = hex::decode(ISSUED_V3_CBOR_HEX).unwrap();
        let v3: DeletionReceiptV4 = ciborium::from_reader(v3_bytes.as_slice()).unwrap();
        let v4 = DeletionReceiptV4 {
            protocol_version: ProtocolVersion::V4.into(),
            module_hash_certificate: Some(vec![0x01, 0x02, 0x03, 0x04]),
            ..v3.clone()
        };
        let v2 = DeletionReceiptV4 {
            protocol_version: ProtocolVersion::V2.into(),
            record_id: Vec::new(),
            ..v3.clone()
        };

        let fixtures = [
            ("mktd02-v3", v3_bytes),
            ("mktd02-v4", encode_v4(&v4)),
            ("mktd02-v2", encode_v4(&v2)),
        ];
        for (i, (label, bytes)) in fixtures.into_iter().enumerate() {
            let id = [0x70 + i as u8; 32];
            storage::with_storage_mut(|s| {
                s.receipts.insert(Hash32(id), ReceiptBytes(bytes.clone()));
            });
            let any = get_receipt(&id).expect("issued receipt must decode");
            match &any {
                AnyDeletionReceipt::V4(r) => assert_eq!(r.protocol_version, label),
                AnyDeletionReceipt::V5(_) => panic!("{label} must decode as DeletionReceiptV4"),
            }
            assert_eq!(
                export::to_cbor_bytes(&any),
                bytes,
                "{label} must re-export byte-for-byte"
            );
            assert_eq!(get_receipt_summary(&id).unwrap().protocol_version, label);
        }
    }
}
