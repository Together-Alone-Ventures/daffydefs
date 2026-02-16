// ============================================================
// DaffyDefs — Bulletin Board Canister
// ============================================================
//
// Shared canister storing challenges, comments, and likes.
// Makes NO inter-canister calls. Display name resolution is
// handled client-side by the PWA.
//
// Memory layout (frozen — do not reorder or reuse):
//   MemoryId(0) = metadata: schema version + ID counters (StableCell)
//   MemoryId(1) = challenges (StableBTreeMap, keyed by u64::MAX - challenge_id)
//   MemoryId(2) = comments (StableBTreeMap, keyed by comment_id)
//   MemoryId(3) = comments-by-challenge index (StableBTreeMap)
//   MemoryId(4) = like counts (StableBTreeMap)
//   MemoryId(5) = like edges (StableBTreeMap)
//   MemoryId(6) = rate limit buckets (StableBTreeMap)
//
// Schema version lifecycle:
//   init:         write v1
//   post_upgrade: 0 → v1; v1 → ok; else → trap

use candid::{CandidType, Principal};
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

/// Max challenges a user can create per day
const MAX_CHALLENGES_PER_DAY: u32 = 5;

/// Max comments a user can add per day
const MAX_COMMENTS_PER_DAY: u32 = 20;

/// Default page size for pagination
const DEFAULT_PAGE_SIZE: u32 = 20;

/// Max page size
const MAX_PAGE_SIZE: u32 = 50;

/// Nanos per day (for rate limit day-bucket keys)
const NANOS_PER_DAY: u64 = 86_400_000_000_000;

// ============================================================
// Stored types
// ============================================================

/// Metadata stored in MemoryId(0)
#[derive(Debug, Clone, CandidType, Serialize, Deserialize)]
struct Metadata {
    schema_version: u64,
    next_challenge_id: u64,
    next_comment_id: u64,
}

impl Default for Metadata {
    fn default() -> Self {
        Self {
            schema_version: 0,
            next_challenge_id: 1,
            next_comment_id: 1,
        }
    }
}

impl Storable for Metadata {
    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(candid::encode_one(self).expect("Failed to encode metadata"))
    }
    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        candid::decode_one(&bytes).expect("Failed to decode metadata")
    }
    const BOUND: Bound = Bound::Bounded {
        max_size: 128,
        is_fixed_size: false,
    };
}

/// Challenge stored in MemoryId(1)
#[derive(Debug, Clone, CandidType, Serialize, Deserialize)]
struct StoredChallenge {
    id: u64,
    word: String,
    author: Principal,
    created_at: u64,
}

impl Storable for StoredChallenge {
    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(candid::encode_one(self).expect("Failed to encode challenge"))
    }
    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        candid::decode_one(&bytes).expect("Failed to decode challenge")
    }
    const BOUND: Bound = Bound::Bounded {
        max_size: 256,
        is_fixed_size: false,
    };
}

/// Comment stored in MemoryId(2)
#[derive(Debug, Clone, CandidType, Serialize, Deserialize)]
struct StoredComment {
    id: u64,
    challenge_id: u64,
    author: Principal,
    text: String,
    created_at: u64,
}

impl Storable for StoredComment {
    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(candid::encode_one(self).expect("Failed to encode comment"))
    }
    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        candid::decode_one(&bytes).expect("Failed to decode comment")
    }
    const BOUND: Bound = Bound::Bounded {
        max_size: 1024,
        is_fixed_size: false,
    };
}

// ============================================================
// Composite key types
// ============================================================

/// Key for comments-by-challenge index: (challenge_id, rev_comment_id)
/// 16 bytes, fixed size. Both stored as big-endian for correct ordering.
#[derive(Clone, Debug, PartialEq, Eq)]
struct ChallengeCommentKey {
    challenge_id: u64,
    rev_comment_id: u64,
}

impl ChallengeCommentKey {
    fn new(challenge_id: u64, comment_id: u64) -> Self {
        Self {
            challenge_id,
            rev_comment_id: u64::MAX - comment_id,
        }
    }

    /// Start of range for a given challenge (smallest possible rev_comment_id = newest)
    fn range_start(challenge_id: u64) -> Self {
        Self {
            challenge_id,
            rev_comment_id: 0, // u64::MAX - u64::MAX = 0, i.e. newest possible
        }
    }

    /// End of range for a given challenge (largest possible rev_comment_id = oldest)
    fn range_end(challenge_id: u64) -> Self {
        Self {
            challenge_id,
            rev_comment_id: u64::MAX,
        }
    }
}

impl Storable for ChallengeCommentKey {
    fn to_bytes(&self) -> Cow<[u8]> {
        let mut buf = [0u8; 16];
        buf[..8].copy_from_slice(&self.challenge_id.to_be_bytes());
        buf[8..].copy_from_slice(&self.rev_comment_id.to_be_bytes());
        Cow::Owned(buf.to_vec())
    }
    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        Self {
            challenge_id: u64::from_be_bytes(bytes[..8].try_into().unwrap()),
            rev_comment_id: u64::from_be_bytes(bytes[8..16].try_into().unwrap()),
        }
    }
    const BOUND: Bound = Bound::Bounded {
        max_size: 16,
        is_fixed_size: true,
    };
}

impl Ord for ChallengeCommentKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.to_bytes().cmp(&other.to_bytes())
    }
}

impl PartialOrd for ChallengeCommentKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// Key for like edges: (comment_id, principal)
/// 38 bytes, fixed size.
#[derive(Clone, Debug, PartialEq, Eq)]
struct LikeEdgeKey {
    comment_id: u64,
    principal: StorablePrincipal,
}

impl LikeEdgeKey {
    fn new(comment_id: u64, principal: Principal) -> Self {
        Self {
            comment_id,
            principal: StorablePrincipal::new(principal),
        }
    }
}

impl Storable for LikeEdgeKey {
    fn to_bytes(&self) -> Cow<[u8]> {
        let mut buf = Vec::with_capacity(38);
        buf.extend_from_slice(&self.comment_id.to_be_bytes());
        buf.extend_from_slice(&self.principal.to_bytes());
        Cow::Owned(buf)
    }
    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        Self {
            comment_id: u64::from_be_bytes(bytes[..8].try_into().unwrap()),
            principal: StorablePrincipal::from_bytes(Cow::Borrowed(&bytes[8..38])),
        }
    }
    const BOUND: Bound = Bound::Bounded {
        max_size: 38,
        is_fixed_size: true,
    };
}

impl Ord for LikeEdgeKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.to_bytes().cmp(&other.to_bytes())
    }
}

impl PartialOrd for LikeEdgeKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// Key for rate limit buckets: (principal, day_number)
/// 34 bytes, fixed size.
#[derive(Clone, Debug, PartialEq, Eq)]
struct DayRateLimitKey {
    principal: StorablePrincipal,
    day: u32,
}

impl DayRateLimitKey {
    fn new(principal: Principal, day: u32) -> Self {
        Self {
            principal: StorablePrincipal::new(principal),
            day,
        }
    }
}

impl Storable for DayRateLimitKey {
    fn to_bytes(&self) -> Cow<[u8]> {
        let mut buf = Vec::with_capacity(34);
        buf.extend_from_slice(&self.principal.to_bytes());
        buf.extend_from_slice(&self.day.to_be_bytes());
        Cow::Owned(buf)
    }
    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        Self {
            principal: StorablePrincipal::from_bytes(Cow::Borrowed(&bytes[..30])),
            day: u32::from_be_bytes(bytes[30..34].try_into().unwrap()),
        }
    }
    const BOUND: Bound = Bound::Bounded {
        max_size: 34,
        is_fixed_size: true,
    };
}

impl Ord for DayRateLimitKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.to_bytes().cmp(&other.to_bytes())
    }
}

impl PartialOrd for DayRateLimitKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

// ============================================================
// Candid-facing return types
// ============================================================

#[derive(Debug, Clone, CandidType, Serialize, Deserialize)]
pub struct ChallengeSummary {
    pub id: u64,
    pub word: String,
    pub author: Principal,
    pub created_at: u64,
    pub comment_count: u64,
}

#[derive(Debug, Clone, CandidType, Serialize, Deserialize)]
pub struct ChallengeDetail {
    pub id: u64,
    pub word: String,
    pub author: Principal,
    pub created_at: u64,
    pub comments: Vec<CommentView>,
}

#[derive(Debug, Clone, CandidType, Serialize, Deserialize)]
pub struct CommentView {
    pub id: u64,
    pub challenge_id: u64,
    pub author: Principal,
    pub text: String,
    pub created_at: u64,
    pub like_count: u64,
    pub liked_by_caller: bool,
}

#[derive(Debug, Clone, CandidType, Serialize, Deserialize)]
pub struct ChallengesPage {
    pub challenges: Vec<ChallengeSummary>,
    pub next_cursor: Option<u64>,
}

#[derive(Debug, Clone, CandidType, Serialize, Deserialize)]
pub struct CommentsPage {
    pub comments: Vec<CommentView>,
    pub next_cursor: Option<u64>,
}

// ============================================================
// Stable memory setup
// ============================================================

type Memory = VirtualMemory<DefaultMemoryImpl>;

thread_local! {
    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> =
        RefCell::new(MemoryManager::init(DefaultMemoryImpl::default()));

    // MemoryId(0): metadata (schema version + counters)
    static META: RefCell<StableCell<Metadata, Memory>> = RefCell::new(
        StableCell::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(0))),
            Metadata::default(),
        ).expect("Failed to init metadata cell")
    );

    // MemoryId(1): challenges, keyed by order_key = u64::MAX - challenge_id
    static CHALLENGES: RefCell<StableBTreeMap<u64, StoredChallenge, Memory>> =
        RefCell::new(StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(1)))
        ));

    // MemoryId(2): comments, keyed by comment_id (for direct lookup)
    static COMMENTS: RefCell<StableBTreeMap<u64, StoredComment, Memory>> =
        RefCell::new(StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(2)))
        ));

    // MemoryId(3): comments-by-challenge index
    static COMMENT_INDEX: RefCell<StableBTreeMap<ChallengeCommentKey, u64, Memory>> =
        RefCell::new(StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(3)))
        ));

    // MemoryId(4): like counts per comment
    static LIKE_COUNTS: RefCell<StableBTreeMap<u64, u64, Memory>> =
        RefCell::new(StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(4)))
        ));

    // MemoryId(5): like edges (existence = liked)
    static LIKE_EDGES: RefCell<StableBTreeMap<LikeEdgeKey, u8, Memory>> =
        RefCell::new(StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(5)))
        ));

    // MemoryId(6): rate limit buckets
    static RATE_LIMITS: RefCell<StableBTreeMap<DayRateLimitKey, u32, Memory>> =
        RefCell::new(StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(6)))
        ));
}

// ============================================================
// Lifecycle hooks
// ============================================================

#[ic_cdk::init]
fn init() {
    META.with(|m| {
        m.borrow_mut()
            .set(Metadata {
                schema_version: SCHEMA_VERSION_V1,
                next_challenge_id: 1,
                next_comment_id: 1,
            })
            .expect("Failed to write initial metadata")
    });
    log_event!("bulletin_board init");
}

#[ic_cdk::post_upgrade]
fn post_upgrade() {
    let meta = META.with(|m| m.borrow().get().clone());
    match meta.schema_version {
        0 => {
            META.with(|m| {
                let mut updated = m.borrow().get().clone();
                updated.schema_version = SCHEMA_VERSION_V1;
                m.borrow_mut()
                    .set(updated)
                    .expect("Failed to update schema version")
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

fn current_day() -> u32 {
    (ic_cdk::api::time() / NANOS_PER_DAY) as u32
}

fn check_rate_limit(caller: Principal, action: &str, limit: u32) -> Result<(), DaffyError> {
    let day = current_day();
    let key = DayRateLimitKey::new(caller, day);

    RATE_LIMITS.with(|rl| {
        let mut map = rl.borrow_mut();
        let count = map.get(&key).unwrap_or(0);

        if count >= limit {
            log_error!("{} rate limit exceeded for {}", action, caller);
            return Err(DaffyError::RateLimitExceeded {
                message: format!("Max {} {} per day", limit, action),
            });
        }

        map.insert(key.clone(), count + 1);

        // Lazy cleanup: remove entries from 2+ days ago
        let stale_day = day.saturating_sub(2);
        let stale_key = DayRateLimitKey::new(caller, stale_day);
        map.remove(&stale_key);

        Ok(())
    })
}

fn validate_word(word: &str) -> Result<(), DaffyError> {
    if word.len() < 3 || word.len() > 20 {
        return Err(DaffyError::InvalidWord {
            message: "Word must be 3–20 characters".into(),
        });
    }
    if !word.chars().all(|c| c.is_ascii_alphabetic()) {
        return Err(DaffyError::InvalidWord {
            message: "Word must contain only alphabetic characters (A-Z, a-z)".into(),
        });
    }
    Ok(())
}

fn next_challenge_id() -> u64 {
    META.with(|m| {
        let mut meta = m.borrow().get().clone();
        let id = meta.next_challenge_id;
        meta.next_challenge_id += 1;
        m.borrow_mut().set(meta).expect("Failed to update metadata");
        id
    })
}

fn next_comment_id() -> u64 {
    META.with(|m| {
        let mut meta = m.borrow().get().clone();
        let id = meta.next_comment_id;
        meta.next_comment_id += 1;
        m.borrow_mut().set(meta).expect("Failed to update metadata");
        id
    })
}

fn get_like_count(comment_id: u64) -> u64 {
    LIKE_COUNTS.with(|lc| lc.borrow().get(&comment_id).unwrap_or(0))
}

fn is_liked_by(comment_id: u64, principal: Principal) -> bool {
    let key = LikeEdgeKey::new(comment_id, principal);
    LIKE_EDGES.with(|le| le.borrow().contains_key(&key))
}

fn count_comments_for_challenge(challenge_id: u64) -> u64 {
    let start = ChallengeCommentKey::range_start(challenge_id);
    let end = ChallengeCommentKey::range_end(challenge_id);
    COMMENT_INDEX.with(|ci| {
        ci.borrow()
            .range(start..=end)
            .count() as u64
    })
}

fn build_comment_view(comment: &StoredComment, caller: Principal) -> CommentView {
    CommentView {
        id: comment.id,
        challenge_id: comment.challenge_id,
        author: comment.author,
        text: comment.text.clone(),
        created_at: comment.created_at,
        like_count: get_like_count(comment.id),
        liked_by_caller: is_liked_by(comment.id, caller),
    }
}

// ============================================================
// Query methods
// ============================================================

/// List challenges, newest first. Cursor-based pagination.
/// cursor = the last seen order_key from a previous page.
#[ic_cdk::query]
fn list_challenges(cursor: Option<u64>, limit: Option<u32>) -> ChallengesPage {
    let caller = ic_cdk::caller(); // may be anonymous for unauthenticated browsing
    let page_size = limit.unwrap_or(DEFAULT_PAGE_SIZE).min(MAX_PAGE_SIZE) as usize;

    CHALLENGES.with(|ch| {
        let map = ch.borrow();
        let iter: Box<dyn Iterator<Item = (u64, StoredChallenge)>> = match cursor {
            Some(c) => {
                // Start after the cursor (exclusive)
                // order_key is u64::MAX - id, so "after cursor" means keys > cursor
                Box::new(
                    map.range((c + 1)..)
                        .take(page_size + 1),
                )
            }
            None => {
                // Start from the beginning (newest first)
                Box::new(map.iter().take(page_size + 1))
            }
        };

        let items: Vec<(u64, StoredChallenge)> = iter.collect();
        let has_more = items.len() > page_size;
        let page_items = &items[..items.len().min(page_size)];

        let challenges: Vec<ChallengeSummary> = page_items
            .iter()
            .map(|(_, ch)| ChallengeSummary {
                id: ch.id,
                word: ch.word.clone(),
                author: ch.author,
                created_at: ch.created_at,
                comment_count: count_comments_for_challenge(ch.id),
            })
            .collect();

        let next_cursor = if has_more {
            page_items.last().map(|(key, _)| *key)
        } else {
            None
        };

        ChallengesPage {
            challenges,
            next_cursor,
        }
    })
}

/// Get a single challenge by ID, with its comments.
#[ic_cdk::query]
fn get_challenge(id: u64) -> Result<ChallengeDetail, DaffyError> {
    let caller = ic_cdk::caller();
    let order_key = u64::MAX - id;

    let challenge = CHALLENGES.with(|ch| ch.borrow().get(&order_key)).ok_or_else(|| {
        DaffyError::InvalidInput {
            message: "Challenge not found".into(),
        }
    })?;

    // Get all comments for this challenge (newest first)
    let start = ChallengeCommentKey::range_start(id);
    let end = ChallengeCommentKey::range_end(id);

    let comments: Vec<CommentView> = COMMENT_INDEX.with(|ci| {
        ci.borrow()
            .range(start..=end)
            .filter_map(|(_, comment_id)| {
                COMMENTS.with(|cm| {
                    cm.borrow()
                        .get(&comment_id)
                        .map(|c| build_comment_view(&c, caller))
                })
            })
            .collect()
    });

    Ok(ChallengeDetail {
        id: challenge.id,
        word: challenge.word,
        author: challenge.author,
        created_at: challenge.created_at,
        comments,
    })
}

/// List comments for a challenge, newest first. Cursor-based pagination.
/// cursor = the last seen rev_comment_id from a previous page.
#[ic_cdk::query]
fn list_comments(
    challenge_id: u64,
    cursor: Option<u64>,
    limit: Option<u32>,
) -> CommentsPage {
    let caller = ic_cdk::caller();
    let page_size = limit.unwrap_or(DEFAULT_PAGE_SIZE).min(MAX_PAGE_SIZE) as usize;

    COMMENT_INDEX.with(|ci| {
        let map = ci.borrow();

        let start = match cursor {
            Some(c) => ChallengeCommentKey {
                challenge_id,
                rev_comment_id: c + 1, // exclusive: start after cursor
            },
            None => ChallengeCommentKey::range_start(challenge_id),
        };
        let end = ChallengeCommentKey::range_end(challenge_id);

        let items: Vec<(ChallengeCommentKey, u64)> =
            map.range(start..=end).take(page_size + 1).collect();

        let has_more = items.len() > page_size;
        let page_items = &items[..items.len().min(page_size)];

        let comments: Vec<CommentView> = page_items
            .iter()
            .filter_map(|(_, comment_id)| {
                COMMENTS.with(|cm| {
                    cm.borrow()
                        .get(comment_id)
                        .map(|c| build_comment_view(&c, caller))
                })
            })
            .collect();

        let next_cursor = if has_more {
            page_items.last().map(|(key, _)| key.rev_comment_id)
        } else {
            None
        };

        CommentsPage {
            comments,
            next_cursor,
        }
    })
}

/// Returns canister version info.
#[ic_cdk::query]
fn version() -> String {
    let meta = META.with(|m| m.borrow().get().clone());
    format!(
        "bulletin_board v0.1.0 (schema v{}, challenges: {}, comments: {})",
        meta.schema_version,
        meta.next_challenge_id - 1,
        meta.next_comment_id - 1
    )
}

// ============================================================
// Update methods
// ============================================================

/// Create a new challenge. Word must be alphabetic, 3–20 chars.
#[ic_cdk::update]
fn create_challenge(word: String) -> Result<u64, DaffyError> {
    let caller = require_authenticated()?;
    validate_word(&word)?;
    check_rate_limit(caller, "challenges", MAX_CHALLENGES_PER_DAY)?;

    let id = next_challenge_id();
    let order_key = u64::MAX - id;
    let now = ic_cdk::api::time();

    let challenge = StoredChallenge {
        id,
        word: word.clone(),
        author: caller,
        created_at: now,
    };

    CHALLENGES.with(|ch| {
        ch.borrow_mut().insert(order_key, challenge);
    });

    log_event!("create_challenge id={} word='{}' by {}", id, word, caller);
    Ok(id)
}

/// Add a comment to a challenge. Cannot comment on your own challenge.
#[ic_cdk::update]
fn add_comment(challenge_id: u64, text: String) -> Result<u64, DaffyError> {
    let caller = require_authenticated()?;
    check_rate_limit(caller, "comments", MAX_COMMENTS_PER_DAY)?;

    // Validate text
    let text = text.trim().to_string();
    if text.is_empty() {
        return Err(DaffyError::InvalidInput {
            message: "Comment text cannot be empty".into(),
        });
    }
    if text.len() > 500 {
        return Err(DaffyError::InvalidInput {
            message: "Comment text must be 500 characters or fewer".into(),
        });
    }

    // Check challenge exists and caller is not the author
    let challenge_order_key = u64::MAX - challenge_id;
    let challenge =
        CHALLENGES
            .with(|ch| ch.borrow().get(&challenge_order_key))
            .ok_or_else(|| DaffyError::InvalidInput {
                message: "Challenge not found".into(),
            })?;

    if challenge.author == caller {
        return Err(DaffyError::NotAuthorized {
            message: "Cannot comment on your own challenge".into(),
        });
    }

    let id = next_comment_id();
    let now = ic_cdk::api::time();

    let comment = StoredComment {
        id,
        challenge_id,
        author: caller,
        text: text.clone(),
        created_at: now,
    };

    // Store comment
    COMMENTS.with(|cm| {
        cm.borrow_mut().insert(id, comment);
    });

    // Update index
    let index_key = ChallengeCommentKey::new(challenge_id, id);
    COMMENT_INDEX.with(|ci| {
        ci.borrow_mut().insert(index_key, id);
    });

    log_event!(
        "add_comment id={} on challenge={} by {}",
        id,
        challenge_id,
        caller
    );
    Ok(id)
}

/// Toggle like on a comment. If already liked, unlikes. If not liked, likes.
/// Returns the new like count.
#[ic_cdk::update]
fn toggle_like(comment_id: u64) -> Result<u64, DaffyError> {
    let caller = require_authenticated()?;

    // Verify comment exists
    let _comment =
        COMMENTS
            .with(|cm| cm.borrow().get(&comment_id))
            .ok_or_else(|| DaffyError::InvalidInput {
                message: "Comment not found".into(),
            })?;

    let edge_key = LikeEdgeKey::new(comment_id, caller);
    let already_liked = LIKE_EDGES.with(|le| le.borrow().contains_key(&edge_key));

    if already_liked {
        // Unlike
        LIKE_EDGES.with(|le| {
            le.borrow_mut().remove(&edge_key);
        });
        let new_count = LIKE_COUNTS.with(|lc| {
            let mut map = lc.borrow_mut();
            let count = map.get(&comment_id).unwrap_or(0);
            let new_count = count.saturating_sub(1);
            if new_count == 0 {
                map.remove(&comment_id);
            } else {
                map.insert(comment_id, new_count);
            }
            new_count
        });
        log_event!("unlike comment={} by {}", comment_id, caller);
        Ok(new_count)
    } else {
        // Like
        LIKE_EDGES.with(|le| {
            le.borrow_mut().insert(edge_key, 1);
        });
        let new_count = LIKE_COUNTS.with(|lc| {
            let mut map = lc.borrow_mut();
            let count = map.get(&comment_id).unwrap_or(0);
            let new_count = count + 1;
            map.insert(comment_id, new_count);
            new_count
        });
        log_event!("like comment={} by {}", comment_id, caller);
        Ok(new_count)
    }
}

// Export Candid interface
ic_cdk::export_candid!();
