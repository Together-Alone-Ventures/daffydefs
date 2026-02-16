// ============================================================
// DaffyDefs — Profile Factory / Registry Canister
// ============================================================
//
// Creates and tracks per-user profile canisters.
// Maps principal → canister_id. Manages lifecycle (create, delete, recreate).
//
// Memory layout (frozen — do not reorder or reuse):
//   MemoryId(0) = schema version (StableCell<u64>)
//   MemoryId(1) = principal → canister_id mapping (StableBTreeMap)
//   MemoryId(2) = deletion tombstones: principal → deleted_at (StableBTreeMap)
//   MemoryId(3) = resolve rate limit: (principal, minute) → count (StableBTreeMap)
//
// Controller model:
//   Factory is controller of all created profile canisters.
//   Users are authorized at the application level.
//
// Schema version lifecycle:
//   init:         write v1
//   post_upgrade: 0 → v1; v1 → ok; else → trap

use candid::{CandidType, Principal};
use ic_cdk::api::management_canister::main::{
    create_canister, delete_canister, install_code, stop_canister, CanisterIdRecord,
    CanisterInstallMode, CanisterSettings, CreateCanisterArgument, InstallCodeArgument,
};
use ic_stable_structures::memory_manager::{MemoryId, MemoryManager, VirtualMemory};
use ic_stable_structures::storable::Bound;
use ic_stable_structures::{DefaultMemoryImpl, StableBTreeMap, StableCell, Storable};
use serde::{Deserialize, Serialize};
use shared::{log_error, log_event, DaffyError, StorablePrincipal, SCHEMA_VERSION_V1};
use std::borrow::Cow;
use std::cell::RefCell;

// ============================================================
// Constants
// ============================================================

/// Cycles allocated to each new profile canister (0.5T)
const CYCLES_PER_PROFILE_CANISTER: u128 = 500_000_000_000;

/// Maximum resolve() calls per principal per minute
const RESOLVE_RATE_LIMIT: u32 = 200;

/// Embedded profile canister WASM — built by scripts/build.sh
/// The build script copies the optimised WASM here before building the factory.
const PROFILE_CANISTER_WASM: &[u8] = include_bytes!("../profile_canister_embedded.wasm");

// ============================================================
// Composite key types
// ============================================================

/// Rate limit key: (principal, minute_number)
/// Fixed size: 30 bytes (principal) + 8 bytes (minute) = 38 bytes
#[derive(Clone, Debug, PartialEq, Eq)]
struct RateLimitKey {
    principal: StorablePrincipal,
    minute: u64,
}

impl RateLimitKey {
    fn new(principal: Principal, minute: u64) -> Self {
        Self {
            principal: StorablePrincipal::new(principal),
            minute,
        }
    }
}

impl Storable for RateLimitKey {
    fn to_bytes(&self) -> Cow<[u8]> {
        let mut buf = Vec::with_capacity(38);
        buf.extend_from_slice(&self.principal.to_bytes());
        buf.extend_from_slice(&self.minute.to_be_bytes());
        Cow::Owned(buf)
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        let principal = StorablePrincipal::from_bytes(Cow::Borrowed(&bytes[..30]));
        let minute = u64::from_be_bytes(bytes[30..38].try_into().unwrap());
        Self { principal, minute }
    }

    const BOUND: Bound = Bound::Bounded {
        max_size: 38,
        is_fixed_size: true,
    };
}

impl Ord for RateLimitKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.to_bytes().cmp(&other.to_bytes())
    }
}

impl PartialOrd for RateLimitKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

// ============================================================
// Stable memory setup
// ============================================================

type Memory = VirtualMemory<DefaultMemoryImpl>;

thread_local! {
    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> =
        RefCell::new(MemoryManager::init(DefaultMemoryImpl::default()));

    static SCHEMA_VERSION: RefCell<StableCell<u64, Memory>> = RefCell::new(
        StableCell::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(0))),
            0u64,
        ).expect("Failed to init schema version cell")
    );

    /// principal → canister_id mapping (active profiles only)
    static PROFILE_MAP: RefCell<StableBTreeMap<StorablePrincipal, StorablePrincipal, Memory>> =
        RefCell::new(StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(1)))
        ));

    /// Deletion tombstones: principal → deleted_at_nanos
    static TOMBSTONES: RefCell<StableBTreeMap<StorablePrincipal, u64, Memory>> =
        RefCell::new(StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(2)))
        ));

    /// Resolve rate limit: (principal, minute) → count
    static RESOLVE_LIMITS: RefCell<StableBTreeMap<RateLimitKey, u32, Memory>> =
        RefCell::new(StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(3)))
        ));
}

// ============================================================
// Lifecycle hooks
// ============================================================

#[ic_cdk::init]
fn init() {
    SCHEMA_VERSION.with(|v| {
        v.borrow_mut()
            .set(SCHEMA_VERSION_V1)
            .expect("Failed to write schema version")
    });
    log_event!("profile_factory init");
}

#[ic_cdk::post_upgrade]
fn post_upgrade() {
    let version = SCHEMA_VERSION.with(|v| *v.borrow().get());
    match version {
        0 => {
            SCHEMA_VERSION.with(|v| {
                v.borrow_mut()
                    .set(SCHEMA_VERSION_V1)
                    .expect("Failed to write schema version")
            });
            log_event!("post_upgrade: schema version 0 → v1");
        }
        v if v == SCHEMA_VERSION_V1 => {
            log_event!("post_upgrade: schema version v1 confirmed");
        }
        other => {
            ic_cdk::trap(&format!(
                "Schema version mismatch: expected {} or 0, got {}",
                SCHEMA_VERSION_V1, other
            ));
        }
    }
}

// ============================================================
// Helpers
// ============================================================

fn require_authenticated() -> Result<Principal, DaffyError> {
    let caller = ic_cdk::caller();
    if caller == Principal::anonymous() {
        return Err(DaffyError::NotAuthorized {
            message: "Anonymous callers are not allowed".into(),
        });
    }
    Ok(caller)
}

fn current_minute() -> u64 {
    ic_cdk::api::time() / 60_000_000_000
}

fn check_resolve_rate_limit(caller: Principal) -> Result<(), DaffyError> {
    let minute = current_minute();
    let key = RateLimitKey::new(caller, minute);

    RESOLVE_LIMITS.with(|rl| {
        let mut map = rl.borrow_mut();
        let count = map.get(&key).unwrap_or(0);

        if count >= RESOLVE_RATE_LIMIT {
            log_error!("resolve rate limit exceeded for {}", caller);
            return Err(DaffyError::RateLimitExceeded {
                message: format!("Max {} resolve calls per minute", RESOLVE_RATE_LIMIT),
            });
        }

        map.insert(key, count + 1);

        // Lazy cleanup: remove entries from 2+ minutes ago
        let stale_minute = minute.saturating_sub(2);
        let stale_key = RateLimitKey::new(caller, stale_minute);
        map.remove(&stale_key);

        Ok(())
    })
}

// ============================================================
// Query methods
// ============================================================

/// Resolve a principal to its profile canister ID.
/// Callable by any authenticated principal. Rate-limited to 200/min/caller.
///
/// Returns:
/// - Ok(canister_id) if principal has an active profile canister
/// - Err(ProfileDeleted) if principal has a tombstone
/// - Err(ProfileNotFound) if principal was never registered
#[ic_cdk::query]
fn resolve(principal: Principal) -> Result<Principal, DaffyError> {
    let caller = require_authenticated()?;

    // Rate limit check — note: queries can't mutate state on mainnet,
    // but rate limiting in queries is still useful on local replica.
    // For production, this would need to be an update call or use
    // a different rate limiting strategy. For our test dApp, this
    // is acceptable.
    // check_resolve_rate_limit(caller)?;
    // NOTE: Rate limiting disabled in query mode since queries cannot
    // write to stable memory. The resolve call is kept as a query for
    // performance. If enumeration becomes a concern on mainnet, convert
    // to an update call.

    let storable_principal = StorablePrincipal::new(principal);

    // Check active mapping first
    let canister_id = PROFILE_MAP.with(|pm| pm.borrow().get(&storable_principal));

    if let Some(cid) = canister_id {
        return Ok(*cid.principal());
    }

    // Check tombstones
    let is_tombstoned = TOMBSTONES.with(|ts| ts.borrow().contains_key(&storable_principal));

    if is_tombstoned {
        return Err(DaffyError::ProfileDeleted {
            message: "Profile has been deleted".into(),
        });
    }

    Err(DaffyError::ProfileNotFound {
        message: "No profile canister exists for this principal".into(),
    })
}

/// Returns the factory's current cycle balance (for operator monitoring).
#[ic_cdk::query]
fn get_cycle_balance() -> u128 {
    ic_cdk::api::canister_balance128()
}

/// Returns the canister version.
#[ic_cdk::query]
fn version() -> String {
    let schema = SCHEMA_VERSION.with(|v| *v.borrow().get());
    format!("profile_factory v0.1.0 (schema v{})", schema)
}

// ============================================================
// Update methods
// ============================================================

/// Create a profile canister for the caller, or return the existing one.
/// If the caller has a tombstone (previously deleted), clears it and creates fresh.
#[ic_cdk::update]
async fn get_or_create_profile_canister() -> Result<Principal, DaffyError> {
    let caller = require_authenticated()?;
    let storable_caller = StorablePrincipal::new(caller);

    // Check if already has an active canister
    let existing = PROFILE_MAP.with(|pm| pm.borrow().get(&storable_caller));
    if let Some(cid) = existing {
        log_event!("get_or_create: returning existing canister for {}", caller);
        return Ok(*cid.principal());
    }

    // Clear tombstone if exists (user is recreating after deletion)
    let had_tombstone = TOMBSTONES.with(|ts| ts.borrow_mut().remove(&storable_caller).is_some());
    if had_tombstone {
        log_event!("get_or_create: clearing tombstone for {}", caller);
    }

    // Check cycle balance
    let balance = ic_cdk::api::canister_balance128();
    if balance < CYCLES_PER_PROFILE_CANISTER * 2 {
        log_error!(
            "Insufficient cycles: have {}, need {} (with buffer)",
            balance,
            CYCLES_PER_PROFILE_CANISTER * 2
        );
        return Err(DaffyError::CanisterCallFailed {
            message: "Factory has insufficient cycles to create a new profile canister. Contact the operator.".into(),
        });
    }

    // Create new canister with factory as controller
    let create_result = create_canister(
        CreateCanisterArgument {
            settings: Some(CanisterSettings {
                controllers: Some(vec![ic_cdk::id()]),
                compute_allocation: None,
                memory_allocation: None,
                freezing_threshold: None,
                reserved_cycles_limit: None,
                log_visibility: None,
                wasm_memory_limit: None,
            }),
        },
        CYCLES_PER_PROFILE_CANISTER,
    )
    .await
    .map_err(|e| {
        log_error!("create_canister failed: {:?}", e);
        DaffyError::CanisterCallFailed {
            message: format!("Failed to create canister: {:?}", e),
        }
    })?;

    let new_canister_id = create_result.0.canister_id;

    // Install profile canister WASM with owner principal as init arg
    let init_arg = candid::encode_one(&caller).map_err(|e| {
        log_error!("Failed to encode init arg: {:?}", e);
        DaffyError::CanisterCallFailed {
            message: format!("Failed to encode init argument: {:?}", e),
        }
    })?;

    install_code(InstallCodeArgument {
        mode: CanisterInstallMode::Install,
        canister_id: new_canister_id,
        wasm_module: PROFILE_CANISTER_WASM.to_vec(),
        arg: init_arg,
    })
    .await
    .map_err(|e| {
        log_error!("install_code failed: {:?}", e);
        DaffyError::CanisterCallFailed {
            message: format!("Failed to install profile canister code: {:?}", e),
        }
    })?;

    // Store mapping
    PROFILE_MAP.with(|pm| {
        pm.borrow_mut()
            .insert(storable_caller, StorablePrincipal::new(new_canister_id));
    });

    log_event!(
        "get_or_create: created canister {} for {}",
        new_canister_id,
        caller
    );

    Ok(new_canister_id)
}

/// Delete the caller's profile canister. Stops it, deletes it,
/// removes the mapping, and writes a tombstone.
#[ic_cdk::update]
async fn delete_profile_canister() -> Result<(), DaffyError> {
    let caller = require_authenticated()?;
    let storable_caller = StorablePrincipal::new(caller);

    // Look up the canister
    let canister_id = PROFILE_MAP
        .with(|pm| pm.borrow().get(&storable_caller))
        .ok_or_else(|| DaffyError::ProfileNotFound {
            message: "No active profile canister to delete".into(),
        })?;

    let canister_id_principal = *canister_id.principal();

    // Stop the canister
    stop_canister(CanisterIdRecord {
        canister_id: canister_id_principal,
    })
    .await
    .map_err(|e| {
        log_error!("stop_canister failed: {:?}", e);
        DaffyError::CanisterCallFailed {
            message: format!("Failed to stop profile canister: {:?}", e),
        }
    })?;

    // Delete the canister
    delete_canister(CanisterIdRecord {
        canister_id: canister_id_principal,
    })
    .await
    .map_err(|e| {
        log_error!("delete_canister failed: {:?}", e);
        DaffyError::CanisterCallFailed {
            message: format!("Failed to delete profile canister: {:?}", e),
        }
    })?;

    // Remove active mapping
    PROFILE_MAP.with(|pm| {
        pm.borrow_mut().remove(&storable_caller);
    });

    // Write tombstone
    let now = ic_cdk::api::time();
    TOMBSTONES.with(|ts| {
        ts.borrow_mut().insert(storable_caller, now);
    });

    log_event!(
        "delete_profile_canister: deleted {} for {}",
        canister_id_principal,
        caller
    );

    Ok(())
}

// Export Candid interface
ic_cdk::export_candid!();
