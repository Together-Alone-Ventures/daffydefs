//! # `MKTdDataSource` Integration Boundary
//!
//! This module defines the host-canister adapter contract for MKTd02.
//!
//! ## Leaf-mode boundary
//!
//! MKTd02 integrations are Leaf mode (single subject per canister).
//! Multi-subject-per-canister architecture is out of scope for MKTd02.
//!
//! ## v0.2.x note
//!
//! `manifest_hash()` is not part of the `MKTdDataSource` trait contract.

use zombie_core::FieldDescriptor;

/// Commit mode for CVDR generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommitMode {
    /// Single data subject per canister (MKTd02).
    Leaf,
    /// Multiple data subjects per canister (MKTd03).
    Tree,
}

impl CommitMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            CommitMode::Leaf => "Leaf",
            CommitMode::Tree => "Tree",
        }
    }
}

/// Adapter trait for mapping host-canister state to MKTd02.
///
/// Integration intent:
/// - `mode()` declares integration mode (`CommitMode::Leaf` for MKTd02 usage)
/// - `pii_field_manifest()` describes boundary metadata
/// - `get_state_bytes()` returns deterministic bytes for hashing
/// - `tombstone_state()` applies tombstone writes to declared fields
/// - `is_tombstoned()` reports the expected post-condition
///
/// Clarification:
/// Deterministic encoding requirements are project-rule-specific and should
/// not be interpreted as a blanket RFC canonical-CBOR equivalence claim.
pub trait MKTdDataSource {
    fn mode(&self) -> CommitMode;
    fn pii_field_manifest(&self) -> Vec<FieldDescriptor>;

    /// Return deterministic CBOR bytes of current PII state.
    /// **Must** use `zombie_core::encode_pii_state()`.
    fn get_state_bytes(&self) -> Vec<u8>;

    /// Overwrite all PII fields with TOMBSTONE_CONSTANT.
    fn tombstone_state(&mut self);

    /// Post-condition check: all PII fields == TOMBSTONE_CONSTANT.
    fn is_tombstoned(&self) -> bool;
}

/// Trait for host canister error types to support the `#[mktd_guard]` macro.
///
/// The host canister's error enum implements this to provide typed
/// error variants for tombstone and initialisation violations.
pub trait GuardError {
    fn tombstone_violation() -> Self;
    fn not_initialised() -> Self;
}
