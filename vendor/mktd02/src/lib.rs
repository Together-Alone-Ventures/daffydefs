//! # MKTd02 -- Leaf-Mode CVDR Engine (ICP)
//!
//! MKTd02 provides Leaf-mode deletion receipts for single-subject canisters.
//!
//! ## Canonical flow
//!
//! 1. `init()` / `on_post_upgrade()`
//! 2. Guard PII mutations
//! 3. `refresh_state_hash()` after successful PII writes
//! 4. `execute_deletion()` (Phase A, pending receipt)
//! 5. `get_pending_certificate()` in query context (Phase B)
//! 6. `finalize_receipt()` (Phase C)
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
pub mod engine;
pub mod export;
pub mod finalization;
pub mod guard;
pub mod nonce;
pub mod state;
pub mod storage;
pub mod trait_def;

// --- Re-exports ---
pub use engine::DeletionError;
pub use finalization::{FinalizationError, PendingCertificate};
pub use trait_def::{CommitMode, GuardError, MKTdDataSource};
pub use zombie_core::{DeletionReceipt, FieldDescriptor, ProtocolVersion, ReceiptSummary};

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
/// Sets up stable memory, computes initial state hash, publishes
/// certified commitment. Module hash is provided by the deployer
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
    engine::first_init(adapter, &config, module_hash);
}

/// Post-upgrade handler. Call from `#[post_upgrade]`.
///
/// Reconnects to stable memory, recomputes state hash, updates
/// module_hash unconditionally.
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
        engine::first_init(adapter, &config, module_hash);
    }

    engine::upgrade_cascade(adapter, module_hash);
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
/// After this call, the **finalization lock is held** — no upgrades,
/// state hash refreshes, or other certified data changes are permitted
/// until the receipt is finalized.
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

/// Get the current state hash.
pub fn get_state_hash() -> [u8; 32] {
    state::read_state_hash()
}

/// Get state hash with optional ICP certificate (for certified queries).
pub fn get_certified_state_hash() -> ([u8; 32], Option<Vec<u8>>) {
    certified::get_certified_state_hash()
}

/// Retrieve a stored receipt by ID.
pub fn get_receipt(receipt_id: &[u8; 32]) -> Option<DeletionReceipt> {
    storage::with_storage(|s| {
        s.receipts.get(&Hash32(*receipt_id)).and_then(|bytes| {
            ciborium::from_reader(bytes.0.as_slice()).ok()
        })
    })
}

/// Retrieve a lightweight receipt summary by ID.
pub fn get_receipt_summary(receipt_id: &[u8; 32]) -> Option<ReceiptSummary> {
    get_receipt(receipt_id).map(|r| ReceiptSummary::from(&r))
}

/// Get tombstone status (timestamp if tombstoned).
pub fn get_tombstone_status() -> Option<u64> {
    storage::with_storage(|s| s.tombstoned_at.get().0)
}

/// Recompute state hash after a PII mutation.
///
/// Call this after every write to PII fields (e.g., after upsert_profile).
///
/// **Traps if finalization lock is held** — no state changes are
/// permitted while a receipt is pending finalization.
pub fn refresh_state_hash<A: MKTdDataSource>(adapter: &A) {
    state::refresh_state_hash_internal(&adapter.get_state_bytes());

    // Re-publish certified commitment with updated state_hash
    // (Will trap if finalization lock is held — see certified.rs)
    let new_state_hash = state::read_state_hash();
    let existing_event_hash =
        storage::with_storage(|s| s.deletion_event_hash.get().0);
    certified::publish_certified_commitment(&new_state_hash, &existing_event_hash);
}

/// Get the number of stored receipts.
pub fn receipt_count() -> u64 {
    storage::with_storage(|s| s.receipts.len())
}

/// Trap if not initialised or tombstoned. For non-Result functions.
pub fn assert_can_write() {
    guard::assert_can_write();
}
