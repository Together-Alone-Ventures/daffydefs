use candid::CandidType;
use serde::{Deserialize, Serialize};

/// Structured error type shared across all DaffyDefs canisters.
/// Frontend can pattern-match on these variants for appropriate UX.
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
            DaffyError::RateLimitExceeded { message } => write!(f, "Rate limit exceeded: {}", message),
            DaffyError::ProfileNotFound { message } => write!(f, "Profile not found: {}", message),
            DaffyError::ProfileDeleted { message } => write!(f, "Profile deleted: {}", message),
            DaffyError::AlreadyExists { message } => write!(f, "Already exists: {}", message),
            DaffyError::CanisterCallFailed { message } => write!(f, "Canister call failed: {}", message),
            DaffyError::InvalidInput { message } => write!(f, "Invalid input: {}", message),
        }
    }
}
