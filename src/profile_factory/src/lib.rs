// ============================================================
// DaffyDefs — Profile Factory / Registry Canister (Scaffold)
// ============================================================
//
// This is an empty scaffold that compiles and deploys.
// Full implementation will be added in Phase 2, Step 2.2.
//
// Memory layout (frozen — do not reorder or reuse):
//   MemoryId(0) = metadata (schema version)
//   MemoryId(1) = principal → canister_id mapping
//   MemoryId(2) = deletion tombstones (principal, deleted_at)
//   MemoryId(3) = resolve rate limit buckets
//
// Controller model:
//   Factory is controller of all created profile canisters.
//   Users are authorized at the application level.

/// Returns the canister version identifier.
#[ic_cdk::query]
fn version() -> String {
    "profile_factory v0.1.0 (scaffold)".to_string()
}

// Export the Candid interface
ic_cdk::export_candid!();
