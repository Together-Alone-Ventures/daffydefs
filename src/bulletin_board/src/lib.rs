// ============================================================
// DaffyDefs — Bulletin Board Canister (Scaffold)
// ============================================================
//
// This is an empty scaffold that compiles and deploys.
// Full implementation will be added in Phase 2, Step 2.3.
//
// Memory layout (frozen — do not reorder or reuse):
//   MemoryId(0) = metadata (schema version + ID counters)
//   MemoryId(1) = challenges map (keyed by u64::MAX - challenge_id)
//   MemoryId(2) = comments map (keyed by comment_id for direct lookup)
//   MemoryId(3) = comments-by-challenge index (keyed by (challenge_id, u64::MAX - comment_id))
//   MemoryId(4) = like counts
//   MemoryId(5) = like edges
//   MemoryId(6) = rate limit buckets
//
// This canister makes NO inter-canister calls.

/// Returns the canister version identifier.
#[ic_cdk::query]
fn version() -> String {
    "bulletin_board v0.1.0 (scaffold)".to_string()
}

// Export the Candid interface
ic_cdk::export_candid!();
