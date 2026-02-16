// ============================================================
// DaffyDefs — Per-User Profile Canister
// ============================================================
//
// One canister per user. Created by the Profile Factory.
// Stores PII: email, birthdate, gender, display_name.
//
// Memory layout (frozen — do not reorder or reuse):
//   MemoryId(0) = schema version (StableCell<u64>)
//   MemoryId(1) = profile data (StableCell<StoredProfile>)
//
// Access control:
//   get_display_name()  — public (any caller)
//   get_profile()       — owner only
//   upsert_profile()    — owner only
//   delete_profile()    — owner only
//
// Schema version lifecycle:
//   init:         write v1
//   post_upgrade: 0 → treat as v1 and write; v1 → ok; else → trap

use candid::{CandidType, Principal};
use ic_stable_structures::memory_manager::{MemoryId, MemoryManager, VirtualMemory};
use ic_stable_structures::storable::Bound;
use ic_stable_structures::{DefaultMemoryImpl, StableCell, Storable};
use serde::{Deserialize, Serialize};
use shared::{log_error, log_event, DaffyError, SCHEMA_VERSION_V1};
use std::borrow::Cow;
use std::cell::RefCell;

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
    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(candid::encode_one(self).expect("Failed to encode profile"))
    }
    fn from_bytes(bytes: Cow<[u8]>) -> Self {
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
// Lifecycle hooks
// ============================================================

/// Called when the canister is first created.
/// The factory passes the owner principal as the init argument.
#[ic_cdk::init]
fn init(owner: Principal) {
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

    log_event!("profile_canister init for owner {}", owner);
}

/// Called on canister upgrade. Checks schema version.
#[ic_cdk::post_upgrade]
fn post_upgrade() {
    let version = SCHEMA_VERSION.with(|v| *v.borrow().get());
    match version {
        0 => {
            // Uninitialised — treat as v1 (e.g., canister from before versioning)
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
    format!("profile_canister v0.1.0 (schema v{})", schema)
}

// ============================================================
// Update methods
// ============================================================

/// OWNER ONLY — create or update profile fields.
#[ic_cdk::update]
fn upsert_profile(input: ProfileInput) -> Result<ProfileInfo, DaffyError> {
    let owner = require_owner()?;
    validate_display_name(&input.display_name)?;

    PROFILE.with(|p| {
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
    })
}

/// OWNER ONLY — tombstone all profile fields.
/// The canister remains alive but get_display_name() returns None.
/// Full canister deletion is handled by the Factory.
#[ic_cdk::update]
fn delete_profile() -> Result<(), DaffyError> {
    let owner = require_owner()?;

    PROFILE.with(|p| {
        let current = p.borrow().get().clone();
        if current.state == ProfileState::Deleted {
            return Err(DaffyError::ProfileDeleted {
                message: "Profile is already deleted".into(),
            });
        }

        let tombstoned = StoredProfile {
            owner: current.owner,
            state: ProfileState::Deleted,
            email: String::new(),
            birthdate: String::new(),
            gender: String::new(),
            display_name: String::new(),
        };

        p.borrow_mut()
            .set(tombstoned)
            .expect("Failed to write tombstoned profile");

        log_event!("delete_profile by {}", owner);
        Ok(())
    })
}

// Export Candid interface
ic_cdk::export_candid!();
