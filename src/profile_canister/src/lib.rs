// ============================================================
// DaffyDefs — Per-User Profile Canister
// ============================================================
//
// One canister per user. Created by the Profile Factory.
// Stores PII: email, birthdate, gender, display_name.
//
// Memory layout (frozen — do not reorder or reuse):
//   MemoryId(0)       = schema version (StableCell<u64>)
//   MemoryId(1)       = profile data (StableCell<StoredProfile>)
//   MemoryId(100–107) = MKTd02 stable memory slots
//
// Access control:
//   get_display_name()  — public (any caller)
//   get_profile()       — owner only
//   upsert_profile()    — owner only
//   delete_profile()    — owner only (now generates CVDR via MKTd02)
//
// MKTd02 integration:
//   ProfileAdapter implements MKTdDataSource
//   mktd02::init() called in #[init]
//   mktd02::on_post_upgrade() called in #[post_upgrade]
//   mktd02::refresh_state_hash() called after every PII write
//   mktd02::execute_deletion() called in delete_profile()

use candid::{CandidType, Principal};
use ic_stable_structures::memory_manager::{MemoryId, MemoryManager, VirtualMemory};
use ic_stable_structures::storable::Bound;
use ic_stable_structures::{DefaultMemoryImpl, StableCell, Storable};
use serde::{Deserialize, Serialize};
use shared::{log_error, log_event, DaffyError, SCHEMA_VERSION_V1};
use std::borrow::Cow;
use std::cell::RefCell;

// MKTd02 imports
use mktd02::trait_def::{CommitMode, MKTdDataSource};
use mktd02::MktdConfig;
use zombie_core::manifest::{compute_manifest_hash, FieldDescriptor};
use zombie_core::serialisation::encode_pii_state;
use zombie_core::tombstone::tombstone_constant;

// ============================================================
// Types
// ============================================================

/// Profile state: tracks whether profile data has been set
#[derive(Debug, Clone, CandidType, Serialize, Deserialize, PartialEq)]
pub enum ProfileState {
    /// Canister created but user hasn't filled in profile yet
    NotSet,
    /// Profile is active with data
    Active,
    /// Profile has been deleted/tombstoned
    Deleted,
}

/// Internal storage representation
#[derive(Debug, Clone, CandidType, Serialize, Deserialize)]
pub struct StoredProfile {
    pub owner: Principal,
    pub state: ProfileState,
    pub email: String,
    pub birthdate: String,
    pub gender: String,
    pub display_name: String,
}

impl Default for StoredProfile {
    fn default() -> Self {
        Self {
            owner: Principal::anonymous(),
            state: ProfileState::NotSet,
            email: String::new(),
            birthdate: String::new(),
            gender: String::new(),
            display_name: String::new(),
        }
    }
}

impl Storable for StoredProfile {
    fn to_bytes(&self) -> Cow<'_, [u8]> {
        Cow::Owned(candid::encode_one(self).expect("Failed to encode profile"))
    }
    fn from_bytes(bytes: Cow<'_, [u8]>) -> Self {
        candid::decode_one(&bytes).expect("Failed to decode profile")
    }
    const BOUND: Bound = Bound::Bounded {
        max_size: 1024,
        is_fixed_size: false,
    };
}

/// Public-facing profile info returned to the owner
#[derive(Debug, Clone, CandidType, Serialize, Deserialize)]
pub struct ProfileInfo {
    pub owner: Principal,
    pub email: String,
    pub birthdate: String,
    pub gender: String,
    pub display_name: String,
}

/// Input for creating/updating a profile
#[derive(Debug, Clone, CandidType, Serialize, Deserialize)]
pub struct ProfileInput {
    pub email: String,
    pub birthdate: String,
    pub gender: String,
    pub display_name: String,
}

/// MKTd02 state hash response for certified queries
#[derive(Debug, Clone, CandidType, Serialize, Deserialize)]
pub struct MktdStateHashResponse {
    pub hash: Vec<u8>,
    pub certificate: Option<Vec<u8>>,
}

/// MKTd02 tombstone status response
#[derive(Debug, Clone, CandidType, Serialize, Deserialize)]
pub struct MktdTombstoneStatus {
    pub is_tombstoned: bool,
    pub tombstoned_at: Option<u64>,
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

    static PROFILE: RefCell<StableCell<StoredProfile, Memory>> = RefCell::new(
        StableCell::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(1))),
            StoredProfile::default(),
        ).expect("Failed to init profile cell")
    );
}

// ============================================================
// MKTd02 Integration: Adapter + Guard
// ============================================================

/// PII-only subset of the profile, in manifest field_order.
/// This struct is what gets CBOR-encoded for state hashing.
/// Field order matches pii_field_manifest() exactly.
#[derive(Serialize, Deserialize)]
struct PiiState {
    email: String,        // field_order: 0
    birthdate: String,    // field_order: 1
    gender: String,       // field_order: 2
    display_name: String, // field_order: 3
}

/// Adapter that maps DaffyDefs' StoredProfile to the MKTdDataSource trait.
///
/// This is the only DaffyDefs-specific code required for MKTd02 integration.
/// Everything else is mechanical wiring (lifecycle hooks, guard, refresh).
struct ProfileAdapter;

impl MKTdDataSource for ProfileAdapter {
    fn mode(&self) -> CommitMode {
        CommitMode::Leaf
    }

    fn pii_field_manifest(&self) -> Vec<FieldDescriptor> {
        vec![
            FieldDescriptor {
                field_name: "email".into(),
                field_type: "String".into(),
                field_order: 0,
            },
            FieldDescriptor {
                field_name: "birthdate".into(),
                field_type: "String".into(),
                field_order: 1,
            },
            FieldDescriptor {
                field_name: "gender".into(),
                field_type: "String".into(),
                field_order: 2,
            },
            FieldDescriptor {
                field_name: "display_name".into(),
                field_type: "String".into(),
                field_order: 3,
            },
        ]
    }

    fn manifest_hash(&self) -> [u8; 32] {
        compute_manifest_hash(&self.pii_field_manifest())
    }

    fn get_state_bytes(&self) -> Vec<u8> {
        PROFILE.with(|p| {
            let profile = p.borrow().get().clone();
            let pii = PiiState {
                email: profile.email,
                birthdate: profile.birthdate,
                gender: profile.gender,
                display_name: profile.display_name,
            };
            encode_pii_state(&pii).expect("PII state encoding failed")
        })
    }

    fn tombstone_state(&mut self) {
        let tc = tombstone_constant();
        let tc_str = hex::encode(tc);

        PROFILE.with(|p| {
            let current = p.borrow().get().clone();
            let tombstoned = StoredProfile {
                owner: current.owner,              // Non-PII: survives
                state: ProfileState::Deleted,      // Non-PII: operational
                email: tc_str.clone(),
                birthdate: tc_str.clone(),
                gender: tc_str.clone(),
                display_name: tc_str.clone(),
            };
            p.borrow_mut()
                .set(tombstoned)
                .expect("Failed to write tombstoned profile");
        });
    }

    fn is_tombstoned(&self) -> bool {
        let tc = tombstone_constant();
        let tc_str = hex::encode(tc);

        PROFILE.with(|p| {
            let profile = p.borrow().get().clone();
            profile.email == tc_str
                && profile.birthdate == tc_str
                && profile.gender == tc_str
                && profile.display_name == tc_str
        })
    }
}

/// MKTd02 guard: check that the library is initialised and the
/// canister is not tombstoned. Returns Result-based errors using
/// DaffyError variants.
///
/// This is equivalent to the #[mktd_guard] macro but works with
/// DaffyError defined in a separate crate (orphan rule workaround).
fn mktd_guard_check() -> Result<(), DaffyError> {
    if !mktd02::is_initialised() {
        return Err(DaffyError::CanisterCallFailed {
            message: "MKTd02 not initialised".into(),
        });
    }
    if mktd02::is_tombstoned() {
        return Err(DaffyError::ProfileDeleted {
            message: "Profile has been deleted (tombstoned)".into(),
        });
    }
    Ok(())
}

/// Helper: build the MktdConfig for this canister.
fn mktd_config() -> MktdConfig {
    MktdConfig {
        base_memory_id: 100,
        subnet_id: Principal::from_text("jtdsg-3h6gi-hs7o5-z2soi-43w3z-soyl3-ajnp3-ekni5-sw553-5kw67-nqe").unwrap(), // Set to real subnet ID for production
    }
}

/// Decode a hex-encoded module hash, or return zeros if absent.
/// Traps if the hex is present but malformed or wrong length.
fn decode_module_hash(hex_opt: &Option<String>) -> [u8; 32] {
    match hex_opt {
        Some(hex_str) if !hex_str.is_empty() => {
            let bytes = hex::decode(hex_str)
                .unwrap_or_else(|e| ic_cdk::trap(&format!("Invalid module_hash hex: {}", e)));
            if bytes.len() != 32 {
                ic_cdk::trap(&format!(
                    "module_hash must be 32 bytes (64 hex chars), got {} bytes",
                    bytes.len()
                ));
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            arr
        }
        _ => [0u8; 32],
    }
}

// ============================================================
// Lifecycle hooks
// ============================================================

/// Called when the canister is first created.
/// The factory passes the owner principal as the init argument.
#[ic_cdk::init]
fn init(owner: Principal, module_hash_hex: Option<String>) {
    // Write schema version
    SCHEMA_VERSION.with(|v| {
        v.borrow_mut()
            .set(SCHEMA_VERSION_V1)
            .expect("Failed to write schema version")
    });

    // Store owner with empty profile (NotSet state)
    PROFILE.with(|p| {
        p.borrow_mut()
            .set(StoredProfile {
                owner,
                state: ProfileState::NotSet,
                email: String::new(),
                birthdate: String::new(),
                gender: String::new(),
                display_name: String::new(),
            })
            .expect("Failed to write initial profile")
    });

    // Decode module hash: deployer passes hex-encoded SHA-256 of the
    // installed WASM. Falls back to zeros if omitted (local dev only —
    // V3 verification is non-functional with zeros).
    let module_hash = decode_module_hash(&module_hash_hex);

    let adapter = ProfileAdapter;
    MEMORY_MANAGER.with(|mm| {
        mktd02::init(&adapter, &mm.borrow(), mktd_config(), module_hash);
    });

    log_event!("profile_canister init for owner {} (MKTd02 enabled, module_hash: {})",
        owner, module_hash_hex.as_deref().unwrap_or("zeros"));
}

/// Called on canister upgrade. Checks schema version, then runs
/// MKTd02 upgrade cascade (manifest check + module hash update).
#[ic_cdk::post_upgrade]
fn post_upgrade(module_hash_hex: Option<String>) {
    let version = SCHEMA_VERSION.with(|v| *v.borrow().get());
    match version {
        0 => {
            SCHEMA_VERSION.with(|v| {
                v.borrow_mut()
                    .set(SCHEMA_VERSION_V1)
                    .expect("Failed to write schema version on upgrade from 0")
            });
            log_event!("post_upgrade: schema version 0 → v1");
        }
        v if v == SCHEMA_VERSION_V1 => {
            log_event!("post_upgrade: schema version v1 confirmed");
        }
        other => {
            ic_cdk::trap(&format!(
                "Schema version mismatch: expected {} or 0, got {}. Cannot upgrade safely.",
                SCHEMA_VERSION_V1, other
            ));
        }
    }

    // Decode module hash from deploy argument. Falls back to zeros if
    // omitted (local dev only — V3 non-functional with zeros).
    let module_hash = decode_module_hash(&module_hash_hex);

    let adapter = ProfileAdapter;
    MEMORY_MANAGER.with(|mm| {
        mktd02::on_post_upgrade(&adapter, &mm.borrow(), mktd_config(), module_hash);
    });

    log_event!("post_upgrade: MKTd02 cascade complete (module_hash: {})",
        module_hash_hex.as_deref().unwrap_or("zeros"));
}

// ============================================================
// Validation helpers
// ============================================================

fn validate_display_name(name: &str) -> Result<(), DaffyError> {
    if name.len() < 2 || name.len() > 30 {
        return Err(DaffyError::InvalidInput {
            message: "Display name must be 2–30 characters".into(),
        });
    }
    if name.chars().any(|c| c.is_control()) {
        return Err(DaffyError::InvalidInput {
            message: "Display name must not contain control characters".into(),
        });
    }
    Ok(())
}

fn require_owner() -> Result<Principal, DaffyError> {
    let caller = ic_cdk::caller();
    let owner = PROFILE.with(|p| p.borrow().get().owner);
    if caller != owner {
        return Err(DaffyError::NotAuthorized {
            message: "Only the profile owner can perform this action".into(),
        });
    }
    Ok(caller)
}

// ============================================================
// Query methods
// ============================================================

/// PUBLIC — any caller can read the display name.
/// Returns Some(name) if active, None if not set or deleted.
#[ic_cdk::query]
fn get_display_name() -> Option<String> {
    PROFILE.with(|p| {
        let profile = p.borrow().get().clone();
        match profile.state {
            ProfileState::Active => Some(profile.display_name),
            _ => None,
        }
    })
}

/// OWNER ONLY — returns full profile info.
#[ic_cdk::query]
fn get_profile() -> Result<ProfileInfo, DaffyError> {
    let _owner = require_owner()?;
    PROFILE.with(|p| {
        let profile = p.borrow().get().clone();
        match profile.state {
            ProfileState::Active => Ok(ProfileInfo {
                owner: profile.owner,
                email: profile.email,
                birthdate: profile.birthdate,
                gender: profile.gender,
                display_name: profile.display_name,
            }),
            ProfileState::NotSet => Err(DaffyError::ProfileNotFound {
                message: "Profile has not been set up yet".into(),
            }),
            ProfileState::Deleted => Err(DaffyError::ProfileDeleted {
                message: "Profile has been deleted".into(),
            }),
        }
    })
}

/// Returns the schema version (for diagnostics).
#[ic_cdk::query]
fn version() -> String {
    let schema = SCHEMA_VERSION.with(|v| *v.borrow().get());
    format!("profile_canister v0.1.0 (schema v{}, MKTd02 enabled)", schema)
}

// ============================================================
// Update methods
// ============================================================

/// OWNER ONLY — create or update profile fields.
/// Protected by MKTd02 guard (rejects writes if tombstoned or uninitialised).
/// State hash is refreshed after every successful write.
#[ic_cdk::update]
fn upsert_profile(input: ProfileInput) -> Result<ProfileInfo, DaffyError> {
    let owner = require_owner()?;
    mktd_guard_check()?;
    validate_display_name(&input.display_name)?;

    let result = PROFILE.with(|p| {
        let current = p.borrow().get().clone();

        let updated = StoredProfile {
            owner: current.owner,
            state: ProfileState::Active,
            email: input.email,
            birthdate: input.birthdate,
            gender: input.gender,
            display_name: input.display_name,
        };

        p.borrow_mut()
            .set(updated.clone())
            .expect("Failed to write profile");

        log_event!("upsert_profile by {}", owner);

        Ok(ProfileInfo {
            owner: updated.owner,
            email: updated.email,
            birthdate: updated.birthdate,
            gender: updated.gender,
            display_name: updated.display_name,
        })
    })?;

    // Refresh MKTd02 state hash after successful PII write
    mktd02::refresh_state_hash(&ProfileAdapter);

    Ok(result)
}

/// OWNER ONLY — tombstone all profile fields and generate a CVDR.
///
/// This replaces the old delete_profile() with cryptographically
/// verifiable deletion. The receipt_id is returned as a hex string
/// for easy reference. Full receipt can be queried via mktd_get_receipt().
#[ic_cdk::update]
fn delete_profile() -> Result<String, DaffyError> {
    let owner = require_owner()?;

    // Check if already tombstoned via MKTd02
    if mktd02::is_tombstoned() {
        return Err(DaffyError::ProfileDeleted {
            message: "Profile is already deleted".into(),
        });
    }

    // Check if profile was manually deleted before MKTd02 was installed
    PROFILE.with(|p| {
        let current = p.borrow().get().clone();
        if current.state == ProfileState::Deleted {
            return Err(DaffyError::ProfileDeleted {
                message: "Profile is already deleted".into(),
            });
        }
        Ok(())
    })?;

    // Execute deletion via MKTd02 — this handles:
    // - Pre-state hash capture
    // - Tombstoning all PII fields (via adapter)
    // - Post-tombstone invariant check
    // - Post-state hash capture
    // - Nonce increment
    // - All hash computations (tombstone_hash, deletion_event_hash, etc.)
    // - Certified commitment publication
    // - Receipt generation and storage
    let mut adapter = ProfileAdapter;
    let receipt_id = mktd02::execute_deletion(&mut adapter, &mktd_config())
        .map_err(|e| match e {
            mktd02::DeletionError::AlreadyTombstoned => DaffyError::ProfileDeleted {
                message: "Profile is already deleted".into(),
            },
            mktd02::DeletionError::NotInitialised => DaffyError::CanisterCallFailed {
                message: "MKTd02 not initialised".into(),
            },
        })?;

    log_event!("delete_profile by {} — CVDR generated: {}", owner, hex::encode(receipt_id));

    Ok(hex::encode(receipt_id))
}

// ============================================================
// MKTd02 query endpoints
// ============================================================

/// Returns the current state hash with optional ICP certificate.
/// Use this for certified verification of the canister's PII state.
#[ic_cdk::query]
fn mktd_get_state_hash() -> MktdStateHashResponse {
    let (hash, certificate) = mktd02::get_certified_state_hash();
    MktdStateHashResponse {
        hash: hash.to_vec(),
        certificate,
    }
}

/// Returns the tombstone status of this canister.
#[ic_cdk::query]
fn mktd_get_tombstone_status() -> MktdTombstoneStatus {
    MktdTombstoneStatus {
        is_tombstoned: mktd02::is_tombstoned(),
        tombstoned_at: mktd02::get_tombstone_status(),
    }
}

/// Returns a full deletion receipt by ID (hex-encoded receipt_id).
/// Returns None if the receipt does not exist.
#[ic_cdk::query]
fn mktd_get_receipt(receipt_id_hex: String) -> Option<MktdReceiptResponse> {
    let receipt_id_bytes = hex::decode(&receipt_id_hex).ok()?;
    if receipt_id_bytes.len() != 32 {
        return None;
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&receipt_id_bytes);

    mktd02::get_receipt(&arr).map(|r| MktdReceiptResponse {
        receipt_id: hex::encode(r.receipt_id),
        canister_id: r.canister_id,
        subnet_id: r.subnet_id,
        commit_mode: r.commit_mode,
        pre_state_hash: hex::encode(r.pre_state_hash),
        post_state_hash: hex::encode(r.post_state_hash),
        tombstone_hash: hex::encode(r.tombstone_hash),
        deletion_event_hash: hex::encode(r.deletion_event_hash),
        certified_commitment: hex::encode(r.certified_commitment),
        manifest_hash: hex::encode(r.manifest_hash),
        module_hash: hex::encode(r.module_hash),
        timestamp: r.timestamp,
        nonce: r.nonce,
    })
}

/// Returns the number of stored receipts (should be 0 or 1 for Leaf mode).
#[ic_cdk::query]
fn mktd_receipt_count() -> u64 {
    mktd02::receipt_count()
}

/// Human-readable receipt response with hex-encoded hashes.
#[derive(Debug, Clone, CandidType, Serialize, Deserialize)]
pub struct MktdReceiptResponse {
    pub receipt_id: String,
    pub canister_id: Principal,
    pub subnet_id: Principal,
    pub commit_mode: String,
    pub pre_state_hash: String,
    pub post_state_hash: String,
    pub tombstone_hash: String,
    pub deletion_event_hash: String,
    pub certified_commitment: String,
    pub manifest_hash: String,
    pub module_hash: String,
    pub timestamp: u64,
    pub nonce: u64,
}

// Export Candid interface
ic_cdk::export_candid!();
