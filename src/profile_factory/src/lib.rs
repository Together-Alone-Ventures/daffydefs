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
//   MemoryId(2) = RESERVED (was tombstones, removed — do not reuse)
//   MemoryId(3) = resolve rate limit: (principal, minute) → count (StableBTreeMap)
//
// Controller model:
//   Factory is controller of all created profile canisters.
//   Users are authorized at the application level.
//
// Schema version lifecycle:
//   init:         write v1
//   post_upgrade: 0 → v1; v1 → ok; else → trap

use candid::Principal;
use ic_cdk::api::management_canister::main::{
    create_canister, delete_canister, install_code, stop_canister, CanisterIdRecord,
    CanisterInstallMode, CanisterSettings, CreateCanisterArgument, InstallCodeArgument,
};
use ic_stable_structures::memory_manager::{MemoryId, MemoryManager, VirtualMemory};
use ic_stable_structures::{DefaultMemoryImpl, StableBTreeMap, StableCell};
use shared::{log_error, log_event, DaffyError, StorablePrincipal, SCHEMA_VERSION_V1};
use std::cell::RefCell;

const CYCLES_PER_PROFILE_CANISTER: u128 = 1_000_000_000_000;
const PROFILE_CANISTER_WASM: &[u8] = include_bytes!("../profile_canister_embedded.wasm");

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

    static PROFILE_MAP: RefCell<StableBTreeMap<StorablePrincipal, StorablePrincipal, Memory>> =
        RefCell::new(StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(1)))
        ));
}

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

fn require_authenticated() -> Result<Principal, DaffyError> {
    let caller = ic_cdk::caller();
    if caller == Principal::anonymous() {
        return Err(DaffyError::NotAuthorized {
            message: "Anonymous callers are not allowed".into(),
        });
    }
    Ok(caller)
}

/// Resolve a principal to its profile canister ID.
/// Returns ProfileNotFound for both never-existed and deleted principals.
#[ic_cdk::query]
fn resolve(principal: Principal) -> Result<Principal, DaffyError> {
    let _caller = require_authenticated()?;
    let storable_principal = StorablePrincipal::new(principal);

    let canister_id = PROFILE_MAP.with(|pm| pm.borrow().get(&storable_principal));

    match canister_id {
        Some(cid) => Ok(*cid.principal()),
        None => Err(DaffyError::ProfileNotFound {
            message: "No profile canister exists for this principal".into(),
        }),
    }
}

#[ic_cdk::query]
fn get_cycle_balance() -> u128 {
    ic_cdk::api::canister_balance128()
}

#[ic_cdk::query]
fn version() -> String {
    let schema = SCHEMA_VERSION.with(|v| *v.borrow().get());
    format!("profile_factory v0.1.0 (schema v{})", schema)
}

#[ic_cdk::update]
async fn get_or_create_profile_canister() -> Result<Principal, DaffyError> {
    let caller = require_authenticated()?;
    let storable_caller = StorablePrincipal::new(caller);

    let existing = PROFILE_MAP.with(|pm| pm.borrow().get(&storable_caller));
    if let Some(cid) = existing {
        log_event!("get_or_create: returning existing canister for {}", caller);
        return Ok(*cid.principal());
    }

    let balance = ic_cdk::api::canister_balance128();
    if balance < CYCLES_PER_PROFILE_CANISTER + 100_000_000_000 {
        log_error!(
            "Insufficient cycles: have {}, need {} (with buffer)",
            balance,
            CYCLES_PER_PROFILE_CANISTER * 2
        );
        return Err(DaffyError::CanisterCallFailed {
            message: "Factory has insufficient cycles to create a new profile canister. Contact the operator.".into(),
        });
    }

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
/// and removes the mapping. No tombstone — resolve() will return
/// ProfileNotFound for this principal going forward.
#[ic_cdk::update]
async fn delete_profile_canister() -> Result<(), DaffyError> {
    let caller = require_authenticated()?;
    let storable_caller = StorablePrincipal::new(caller);

    let canister_id = PROFILE_MAP
        .with(|pm| pm.borrow().get(&storable_caller))
        .ok_or_else(|| DaffyError::ProfileNotFound {
            message: "No active profile canister to delete".into(),
        })?;

    let canister_id_principal = *canister_id.principal();

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

    PROFILE_MAP.with(|pm| {
        pm.borrow_mut().remove(&storable_caller);
    });

    log_event!(
        "delete_profile_canister: deleted {} for {}",
        canister_id_principal,
        caller
    );

    Ok(())
}

ic_cdk::export_candid!();
