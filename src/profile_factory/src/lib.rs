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
use sha2::{Sha256, Digest};
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

    let module_hash_bytes = Sha256::digest(PROFILE_CANISTER_WASM);
    let module_hash_hex: Option<String> = Some(hex::encode(&module_hash_bytes));
    let init_arg = candid::encode_args((&caller, &module_hash_hex)).map_err(|e| {
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

/// Checks that the caller is a controller of this factory canister.
/// Controllers are set at canister creation/update-settings time.
fn require_admin() -> Result<Principal, DaffyError> {
    let caller = ic_cdk::caller();
    if !ic_cdk::api::is_controller(&caller) {
        return Err(DaffyError::NotAuthorized {
            message: "Only factory controllers can perform this action".into(),
        });
    }
    Ok(caller)
}

/// ADMIN ONLY — upgrade a user's profile canister to the latest embedded WASM.
/// This pushes the current factory-embedded profile_canister code to an existing
/// profile canister. Used when the profile canister code has been updated
/// (e.g., MKTd02 integration) and needs to be rolled out to existing users.
///
/// The target canister's post_upgrade() hook will run automatically after
/// the new code is installed, preserving all stable memory data.
#[ic_cdk::update]
async fn upgrade_profile_canister(user_principal: Principal) -> Result<(), DaffyError> {
    let admin = require_admin()?;
    let storable_principal = StorablePrincipal::new(user_principal);

    // Look up the user's profile canister
    let canister_id = PROFILE_MAP
        .with(|pm| pm.borrow().get(&storable_principal))
        .ok_or_else(|| DaffyError::ProfileNotFound {
            message: format!("No profile canister found for {}", user_principal),
        })?;

    let canister_id_principal = *canister_id.principal();

    // Compute SHA-256 of the embedded WASM — "hash what you ship"
    // This is the exact bytes that get deployed, post ic-wasm shrink.
    let module_hash_bytes = Sha256::digest(PROFILE_CANISTER_WASM);
    let module_hash_hex: Option<String> = Some(hex::encode(&module_hash_bytes));
    let upgrade_arg = candid::encode_one(&module_hash_hex)
        .expect("Failed to encode module_hash for upgrade arg");

    install_code(InstallCodeArgument {
        mode: CanisterInstallMode::Upgrade(None),
        canister_id: canister_id_principal,
        wasm_module: PROFILE_CANISTER_WASM.to_vec(),
        arg: upgrade_arg,
    })
    .await
    .map_err(|e| {
        log_error!("upgrade install_code failed for {}: {:?}", canister_id_principal, e);
        DaffyError::CanisterCallFailed {
            message: format!("Failed to upgrade profile canister: {:?}", e),
        }
    })?;

    log_event!(
        "upgrade_profile_canister: upgraded {} for {} (by admin {})",
        canister_id_principal,
        user_principal,
        admin
    );

    Ok(())
}

/// ADMIN ONLY — list all principal → canister_id mappings.
/// Returns a Vec of (user_principal, canister_id) pairs.
#[ic_cdk::query]
fn list_all_profiles() -> Result<Vec<(Principal, Principal)>, DaffyError> {
    require_admin()?;
    
    let entries: Vec<(Principal, Principal)> = PROFILE_MAP.with(|pm| {
        pm.borrow()
            .iter()
            .map(|(k, v)| (*k.principal(), *v.principal()))
            .collect()
    });

    Ok(entries)
}



/// Remove the mapping for a deleted (tombstoned) profile canister.
/// The old canister is NOT destroyed — its CVDR remains queryable.
/// After this, get_or_create_profile_canister() will create a fresh canister.
#[ic_cdk::update]
fn unmap_deleted_profile() -> Result<(), DaffyError> {
    let caller = require_authenticated()?;
    let storable_caller = StorablePrincipal::new(caller);

    let _old = PROFILE_MAP
        .with(|pm| pm.borrow().get(&storable_caller))
        .ok_or_else(|| DaffyError::ProfileNotFound {
            message: "No profile canister exists for this principal".into(),
        })?;

    PROFILE_MAP.with(|pm| {
        pm.borrow_mut().remove(&storable_caller);
    });

    log_event!("unmap_deleted_profile: unmapped canister for {}", caller);
    Ok(())
}
/// ADMIN ONLY — Finalize a pending CVDR on a profile canister (Phase C proxy).
///
/// The factory is the sole controller of profile canisters, so only the
/// factory can call mktd_finalize_receipt() on them. This endpoint lets
/// an admin trigger finalization via the factory.
///
/// Three-phase deletion flow:
///   Phase A: User calls delete_profile() on their profile canister
///   Phase B: Script queries mktd_get_certificate() on the profile canister
///   Phase C: Admin calls THIS endpoint, factory forwards to profile canister
///
/// Parameters:
///   canister_id    — the profile canister to finalize
///   receipt_id_hex — hex-encoded receipt ID (from Phase A / Phase B)
///   certificate    — raw BLS certificate blob (from Phase B)
///   trust_root_key — NNS root public key (96 bytes for mainnet)
#[ic_cdk::update]
async fn finalize_profile_receipt(
    canister_id: Principal,
    receipt_id_hex: String,
    certificate: Vec<u8>,
    trust_root_key: Vec<u8>,
) -> Result<String, DaffyError> {
    let admin = require_admin()?;

    // Verify this canister is one we manage
    let is_managed = PROFILE_MAP.with(|pm| {
        pm.borrow().iter().any(|(_, v)| *v.principal() == canister_id)
    });
    if !is_managed {
        return Err(DaffyError::ProfileNotFound {
            message: format!("Canister {} is not a managed profile canister", canister_id),
        });
    }

    // Inter-canister call to the profile canister's mktd_finalize_receipt.
    // The factory is the controller, so the is_controller() guard passes.
    let call_result: Result<(Result<String, DaffyError>,), _> = ic_cdk::call(
        canister_id,
        "mktd_finalize_receipt",
        (receipt_id_hex.clone(), certificate, trust_root_key),
    )
    .await;

    match call_result {
        Ok((inner_result,)) => {
            match &inner_result {
                Ok(_) => log_event!(
                    "finalize_profile_receipt: {} finalized by admin {}",
                    receipt_id_hex, admin
                ),
                Err(e) => log_error!(
                    "finalize_profile_receipt: profile canister returned error: {}",
                    e
                ),
            }
            inner_result
        }
        Err((code, msg)) => {
            log_error!(
                "finalize_profile_receipt: inter-canister call failed: {:?} — {}",
                code, msg
            );
            Err(DaffyError::CanisterCallFailed {
                message: format!("Inter-canister call to {} failed: {:?} — {}", canister_id, code, msg),
            })
        }
    }
}
/// ADMIN ONLY — Finalize a pending CVDR on a profile canister (Phase C proxy).
///
/// The factory is the sole controller of profile canisters, so only the
/// factory can call mktd_finalize_receipt() on them. This endpoint lets
/// an admin trigger finalization via the factory.
///
/// Three-phase deletion flow:
///   Phase A: User calls delete_profile() on their profile canister
///   Phase B: Script queries mktd_get_certificate() on the profile canister
///   Phase C: Admin calls THIS endpoint, factory forwards to profile canister
///
/// Parameters:
///   canister_id    — the profile canister to finalize
///   receipt_id_hex — hex-encoded receipt ID (from Phase A / Phase B)
///   certificate    — raw BLS certificate blob (from Phase B)
///   trust_root_key — NNS root public key (96 bytes for mainnet)
#[ic_cdk::update]
async fn finalize_profile_receipt(
    canister_id: Principal,
    receipt_id_hex: String,
    certificate: Vec<u8>,
    trust_root_key: Vec<u8>,
) -> Result<String, DaffyError> {
    let admin = require_admin()?;

    // Verify this canister is one we manage
    let is_managed = PROFILE_MAP.with(|pm| {
        pm.borrow().iter().any(|(_, v)| *v.principal() == canister_id)
    });
    if !is_managed {
        return Err(DaffyError::ProfileNotFound {
            message: format!("Canister {} is not a managed profile canister", canister_id),
        });
    }

    // Inter-canister call to the profile canister's mktd_finalize_receipt.
    // The factory is the controller, so the is_controller() guard passes.
    let call_result: Result<(Result<String, DaffyError>,), _> = ic_cdk::call(
        canister_id,
        "mktd_finalize_receipt",
        (receipt_id_hex.clone(), certificate, trust_root_key),
    )
    .await;

    match call_result {
        Ok((inner_result,)) => {
            match &inner_result {
                Ok(_) => log_event!(
                    "finalize_profile_receipt: {} finalized by admin {}",
                    receipt_id_hex, admin
                ),
                Err(e) => log_error!(
                    "finalize_profile_receipt: profile canister returned error: {}",
                    e
                ),
            }
            inner_result
        }
        Err((code, msg)) => {
            log_error!(
                "finalize_profile_receipt: inter-canister call failed: {:?} — {}",
                code, msg
            );
            Err(DaffyError::CanisterCallFailed {
                message: format!("Inter-canister call to {} failed: {:?} — {}", canister_id, code, msg),
            })
        }
    }
}
ic_cdk::export_candid!();
