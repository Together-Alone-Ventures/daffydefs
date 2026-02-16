// ============================================================
// DaffyDefs — Per-User Profile Canister (Scaffold)
// ============================================================
//
// This is an empty scaffold that compiles and deploys.
// Full implementation will be added in Phase 2, Step 2.1.
//
// Memory layout (frozen — do not reorder or reuse):
//   MemoryId(0) = metadata (schema version)
//   MemoryId(1) = profile data
//
// Access control:
//   get_display_name()  — public (any caller)
//   get_profile()       — owner only
//   upsert_profile()    — owner only
//   delete_profile()    — owner only

use candid::Principal;

/// Returns the canister version identifier.
#[ic_cdk::query]
fn version() -> String {
    "profile_canister v0.1.0 (scaffold)".to_string()
}

// Export the Candid interface
ic_cdk::export_candid!();
