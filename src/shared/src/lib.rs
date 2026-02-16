use candid::{CandidType, Principal};
use ic_stable_structures::storable::Bound;
use ic_stable_structures::Storable;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::cmp::Ordering;

// ============================================================
// DaffyError — shared error type across all canisters
// ============================================================

#[derive(Debug, Clone, CandidType, Serialize, Deserialize)]
pub enum DaffyError {
    NotAuthorized { message: String },
    InvalidWord { message: String },
    RateLimitExceeded { message: String },
    ProfileNotFound { message: String },
    ProfileDeleted { message: String },
    AlreadyExists { message: String },
    CanisterCallFailed { message: String },
    InvalidInput { message: String },
}

impl std::fmt::Display for DaffyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DaffyError::NotAuthorized { message } => write!(f, "Not authorized: {}", message),
            DaffyError::InvalidWord { message } => write!(f, "Invalid word: {}", message),
            DaffyError::RateLimitExceeded { message } => {
                write!(f, "Rate limit exceeded: {}", message)
            }
            DaffyError::ProfileNotFound { message } => {
                write!(f, "Profile not found: {}", message)
            }
            DaffyError::ProfileDeleted { message } => write!(f, "Profile deleted: {}", message),
            DaffyError::AlreadyExists { message } => write!(f, "Already exists: {}", message),
            DaffyError::CanisterCallFailed { message } => {
                write!(f, "Canister call failed: {}", message)
            }
            DaffyError::InvalidInput { message } => write!(f, "Invalid input: {}", message),
        }
    }
}

// ============================================================
// StorablePrincipal — fixed-size serialization for use as
// StableBTreeMap keys. 30 bytes: 1-byte length + 29-byte data.
// ============================================================

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StorablePrincipal(pub Principal);

impl StorablePrincipal {
    pub fn new(p: Principal) -> Self {
        Self(p)
    }

    pub fn principal(&self) -> &Principal {
        &self.0
    }
}

impl Storable for StorablePrincipal {
    fn to_bytes(&self) -> Cow<[u8]> {
        let slice = self.0.as_slice();
        let mut buf = [0u8; 30];
        buf[0] = slice.len() as u8;
        buf[1..1 + slice.len()].copy_from_slice(slice);
        Cow::Owned(buf.to_vec())
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        let len = bytes[0] as usize;
        Self(Principal::from_slice(&bytes[1..1 + len]))
    }

    const BOUND: Bound = Bound::Bounded {
        max_size: 30,
        is_fixed_size: true,
    };
}

impl Ord for StorablePrincipal {
    fn cmp(&self, other: &Self) -> Ordering {
        self.to_bytes().cmp(&other.to_bytes())
    }
}

impl PartialOrd for StorablePrincipal {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

// ============================================================
// Schema version helpers
// ============================================================

pub const SCHEMA_VERSION_V1: u64 = 1;

/// Log an event to canister logs (visible via `dfx canister logs`)
#[macro_export]
macro_rules! log_event {
    ($($arg:tt)*) => {
        ic_cdk::println!("EVENT: {}", format!($($arg)*));
    };
}

/// Log an error to canister logs
#[macro_export]
macro_rules! log_error {
    ($($arg:tt)*) => {
        ic_cdk::println!("ERROR: {}", format!($($arg)*));
    };
}
