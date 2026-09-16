//! # Hashing Primitives & Domain Separation
//!
//! SHA-256 wrapper, domain separation tags, and byte concatenation helpers.
//!
//! ## Naming Convention Table
//!
//! ### Active — used by `mktd02-v5`
//!
//! | Name                       | Kind           | Purpose                                       | Used in          |
//! |----------------------------|----------------|-----------------------------------------------|------------------|
//! | MKTD_TOMBSTONE_V1          | Constant seed  | Seed for TOMBSTONE_CONSTANT (bytes written)   | tombstone.rs     |
//! | MKTD02_TOMBSTONE_HASH_V1   | Domain tag     | Tag for tombstone_hash in receipt             | engine.rs        |
//! | MKTD02_EVENT_V2            | Domain tag     | Tag for v5 deletion_event_hash (binds receipt_id) | receipt.rs   |
//! | MKTD02_RECEIPT_V3          | Domain tag     | Tag for v3 receipt_id derivation (v3 onwards) | receipt.rs       |
//! | MKTD02_SALT_V1             | Domain tag     | Tag for per-canister salt derivation          | state.rs         |
//! | MKTD02_GENESIS_V1          | Domain tag     | Tag for v5 genesis certified_data (verifier)  | receipt.rs       |
//!
//! ### Active — other lines
//!
//! Never produce a `mktd02-v5` value. Kept active because recomputing an
//! already-issued receipt of an earlier line requires them.
//!
//! | Name                       | Kind           | Purpose                                       | Used in          |
//! |----------------------------|----------------|-----------------------------------------------|------------------|
//! | MKTD02_EVENT_V1            | Domain tag     | Tag for deletion_event_hash on v2-v4          | receipt.rs       |
//! | MKTD02_RECEIPT_V1          | Domain tag     | Tag for v2 receipt_id derivation              | receipt.rs       |
//! | MKTD02_MANIFEST_V1         | Domain tag     | Tag for manifest_hash; the value left the receipt at v0.2.0 | manifest.rs |
//!
//! **Key distinction:** The tombstone constant is a *value written to storage*;
//! domain tags are *prefixes for hash computations*. They must never be confused.
//!
//! ## Retired Tags
//!
//! Retired tags are never deleted: they stay listed here and in
//! [`RETIRED_TAGS`]. A retired tag is a [`RetiredTag`], not a [`DomainTag`],
//! so it cannot be passed to [`hash_with_tag`] (compile error), and
//! `hash_with_tag` debug-asserts that its tag is not retired (test failure).
//! Verifying receipts issued under a retired construction goes through
//! [`RetiredTag::hash_historical`], the only sanctioned way to hash under a
//! retired tag.
//!
//! | Name                       | Retired        | Ruling | Formerly                                  |
//! |----------------------------|----------------|--------|-------------------------------------------|
//! | MKTD02_CERTIFIED_V1        | 2026-09-11     | SR-06  | certified_commitment (mktd02-v2..v4)      |

use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// Constant seed (used to derive a stored value, NOT a hash prefix)
// ---------------------------------------------------------------------------

/// Seed string for the tombstone constant. The actual constant is
/// SHA-256(TOMBSTONE_SEED) -- see tombstone module.
pub const TOMBSTONE_SEED: &[u8] = b"MKTD_TOMBSTONE_V1";

// ---------------------------------------------------------------------------
// Domain separation tags (used as prefixes in hash computations)
// ---------------------------------------------------------------------------

/// A domain separation tag. Wraps a static byte slice to enforce
/// tag-first ordering in hash computations via [`hash_with_tag`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DomainTag(pub &'static [u8]);

/// Domain tag for tombstone_hash field in the deletion receipt.
pub const TAG_TOMBSTONE_HASH: DomainTag = DomainTag(b"MKTD02_TOMBSTONE_HASH_V1");

/// Domain tag for `deletion_event_hash` on the historical lines
/// (`mktd02-v2`, `mktd02-v3`, `mktd02-v4`) — **active, "other lines" group**,
/// alongside [`TAG_RECEIPT`].
///
/// Active, never retired: recomputing the event hash of an already-issued
/// v2–v4 receipt requires it. It must never produce a `mktd02-v5` value —
/// v5 binds `receipt_id` into the preimage and uses [`TAG_EVENT_V2`]
/// (ruling A-1(a), 12 Sep 2026).
pub const TAG_EVENT: DomainTag = DomainTag(b"MKTD02_EVENT_V1");

/// Domain tag for `deletion_event_hash` on `mktd02-v5` — active, v5-used
/// (ruling A-1(a), 12 Sep 2026).
///
/// The v5 preimage binds `receipt_id`, making it a different construction
/// from the v2–v4 one; a different construction takes a different tag, so the
/// two can never collide over identical operands.
pub const TAG_EVENT_V2: DomainTag = DomainTag(b"MKTD02_EVENT_V2");

/// Domain tag for receipt_id derivation.
pub const TAG_RECEIPT: DomainTag = DomainTag(b"MKTD02_RECEIPT_V1");

/// Domain tag for v3 receipt_id derivation with explicit length delimiting.
pub const TAG_RECEIPT_V3: DomainTag = DomainTag(b"MKTD02_RECEIPT_V3");

/// Domain tag for per-canister salt derivation.
pub const TAG_SALT: DomainTag = DomainTag(b"MKTD02_SALT_V1");

/// Domain tag for manifest_hash computation.
pub const TAG_MANIFEST: DomainTag = DomainTag(b"MKTD02_MANIFEST_V1");

/// Domain tag for the mktd02-v5 genesis `certified_data` value
/// (verifier-side only).
pub const TAG_GENESIS: DomainTag = DomainTag(b"MKTD02_GENESIS_V1");

// ---------------------------------------------------------------------------
// Retired domain tags (kept as a record; unusable as hash prefixes)
// ---------------------------------------------------------------------------

/// A domain separation tag retired by ruling.
///
/// Deliberately **not** a [`DomainTag`], so it cannot be passed to
/// [`hash_with_tag`]. Kept, never deleted, so the registry records what the
/// bytes were and when and why they were retired.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetiredTag {
    /// The exact tag bytes as formerly used in hash preimages.
    pub bytes: &'static [u8],
    /// Retirement date (ISO 8601).
    pub retired_on: &'static str,
    /// Ruling that retired the tag.
    pub ruling: &'static str,
}

impl RetiredTag {
    /// `SHA-256(tag || part_0 || part_1 || ...)` under this retired tag — the
    /// same tag-first discipline as [`hash_with_tag`].
    ///
    /// For verifying receipts issued under a retired construction. This is the
    /// **only** sanctioned way to hash under a retired tag; never use it to
    /// produce new values.
    pub fn hash_historical(&self, parts: &[&[u8]]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.bytes);
        for part in parts {
            hasher.update(part);
        }
        hasher.finalize().into()
    }
}

/// **RETIRED** 2026-09-11 by ruling SR-06. Formerly the domain tag for
/// `certified_commitment` (mktd02-v2..v4); mktd02-v5 has no such field.
///
/// Any use as a hashing tag fails to compile:
///
/// ```compile_fail,E0308
/// use zombie_core::hashing::{hash_with_tag, TAG_CERTIFIED};
/// hash_with_tag(TAG_CERTIFIED, &[b"x"]);
/// ```
pub const TAG_CERTIFIED: RetiredTag = RetiredTag {
    bytes: b"MKTD02_CERTIFIED_V1",
    retired_on: "2026-09-11",
    ruling: "SR-06",
};

/// The registry's retired list. Append only; never remove an entry.
pub const RETIRED_TAGS: &[RetiredTag] = &[TAG_CERTIFIED];

// ---------------------------------------------------------------------------
// SHA-256 wrapper
// ---------------------------------------------------------------------------

/// Compute SHA-256 of a single byte slice.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Compute a domain-separated hash: `SHA-256(tag || part_0 || part_1 || ...)`.
///
/// The [`DomainTag`] newtype enforces that the tag is always the first
/// element in the hash preimage, preventing accidental misordering.
///
/// Debug builds (and so every test run) assert that `tag` is not in
/// [`RETIRED_TAGS`], so a retired tag rebuilt as an ad-hoc `DomainTag`
/// fails any test that reaches it. Release builds are unaffected.
pub fn hash_with_tag(tag: DomainTag, parts: &[&[u8]]) -> [u8; 32] {
    debug_assert!(
        !RETIRED_TAGS.iter().any(|r| r.bytes == tag.0),
        "hash_with_tag: retired domain tag {}",
        String::from_utf8_lossy(tag.0)
    );
    let mut hasher = Sha256::new();
    hasher.update(tag.0);
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

/// Compute SHA-256 of multiple byte slices concatenated in order
///
/// **Prefer [`hash_with_tag`] for domain-separated hashes.** This
/// function is for cases without a domain tag (e.g., salt || state_bytes).
pub fn sha256_concat(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

/// A zero-filled 32-byte hash.
///
/// v2–v4: initial `deletion_event_hash` before any deletion.
/// v5: a named rejection (`invalid-event-hash:zero`); the pre-deletion
/// `certified_data` is `genesis_certified_data`.
pub const ZERO_HASH: [u8; 32] = [0u8; 32];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_deterministic() {
        let a = sha256(b"hello");
        let b = sha256(b"hello");
        assert_eq!(a, b);
    }

    #[test]
    fn sha256_different_inputs_differ() {
        let a = sha256(b"hello");
        let b = sha256(b"world");
        assert_ne!(a, b);
    }

    #[test]
    fn sha256_known_vector() {
        let empty = sha256(b"");
        assert_eq!(
            hex::encode(empty),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn hash_with_tag_matches_concat() {
        let via_tag = hash_with_tag(TAG_EVENT, &[b"data"]);
        let via_concat = sha256_concat(&[TAG_EVENT.0, b"data"]);
        assert_eq!(via_tag, via_concat);
    }

    #[test]
    fn hash_with_tag_order_matters() {
        let ab = hash_with_tag(TAG_EVENT, &[b"a", b"b"]);
        let ba = hash_with_tag(TAG_EVENT, &[b"b", b"a"]);
        assert_ne!(ab, ba);
    }

    #[test]
    fn domain_tags_are_distinct() {
        let tags: &[DomainTag] = &[
            TAG_TOMBSTONE_HASH,
            TAG_EVENT,
            TAG_EVENT_V2,
            TAG_RECEIPT,
            TAG_RECEIPT_V3,
            TAG_SALT,
            TAG_MANIFEST,
            TAG_GENESIS,
        ];
        for (i, a) in tags.iter().enumerate() {
            for (j, b) in tags.iter().enumerate() {
                if i != j {
                    assert_ne!(a.0, b.0, "tags at index {} and {} collide", i, j);
                }
            }
        }
    }

    #[test]
    fn tombstone_seed_differs_from_all_tags() {
        let tags: &[DomainTag] = &[
            TAG_TOMBSTONE_HASH,
            TAG_EVENT,
            TAG_EVENT_V2,
            TAG_RECEIPT,
            TAG_RECEIPT_V3,
            TAG_SALT,
            TAG_MANIFEST,
            TAG_GENESIS,
        ];
        for tag in tags {
            assert_ne!(TOMBSTONE_SEED, tag.0);
        }
    }

    #[test]
    fn zero_hash_is_zero() {
        assert_eq!(ZERO_HASH, [0u8; 32]);
    }

    // --- 3.1 tag registry: retirement (SR-06) and MKTD02_GENESIS_V1 -------

    #[test]
    fn retired_tag_certified_is_registered() {
        assert!(RETIRED_TAGS.contains(&TAG_CERTIFIED));
        assert_eq!(TAG_CERTIFIED.bytes, b"MKTD02_CERTIFIED_V1");
        assert_eq!(TAG_CERTIFIED.retired_on, "2026-09-11");
        assert_eq!(TAG_CERTIFIED.ruling, "SR-06");
    }

    #[test]
    fn no_active_tag_is_retired() {
        let active: &[DomainTag] = &[
            TAG_TOMBSTONE_HASH,
            TAG_EVENT,
            TAG_EVENT_V2,
            TAG_RECEIPT,
            TAG_RECEIPT_V3,
            TAG_SALT,
            TAG_MANIFEST,
            TAG_GENESIS,
        ];
        for tag in active {
            for retired in RETIRED_TAGS {
                assert_ne!(tag.0, retired.bytes, "active tag reuses retired bytes");
            }
        }
    }

    /// A retired tag rebuilt as an ad-hoc `DomainTag` must fail under test.
    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "retired domain tag MKTD02_CERTIFIED_V1")]
    fn hash_with_tag_rejects_rebuilt_retired_tag() {
        hash_with_tag(DomainTag(TAG_CERTIFIED.bytes), &[b"x"]);
    }

    /// 1b.1: hash_historical is tag-first, parts in order (hash_with_tag discipline).
    #[test]
    fn hash_historical_follows_hash_with_tag_discipline() {
        assert_eq!(
            TAG_CERTIFIED.hash_historical(&[b"a", b"b"]),
            sha256_concat(&[b"MKTD02_CERTIFIED_V1", b"a", b"b"])
        );
        assert_ne!(
            TAG_CERTIFIED.hash_historical(&[b"a", b"b"]),
            TAG_CERTIFIED.hash_historical(&[b"b", b"a"])
        );
    }

    #[test]
    fn tag_genesis_is_exact_ascii_without_terminator() {
        assert_eq!(TAG_GENESIS.0, b"MKTD02_GENESIS_V1");
        assert_eq!(TAG_GENESIS.0.len(), 17);
        assert!(TAG_GENESIS.0.iter().all(|b| b.is_ascii_graphic()));
        assert!(!TAG_GENESIS.0.contains(&0u8));
    }

    /// Same hash_with_tag discipline as every tag: tag bytes first, then parts.
    #[test]
    fn tag_genesis_follows_hash_with_tag_discipline() {
        let parts: &[&[u8]] = &[&[1, 2, 3, 4]];
        assert_eq!(
            hash_with_tag(TAG_GENESIS, parts),
            sha256_concat(&[b"MKTD02_GENESIS_V1", &[1, 2, 3, 4]])
        );
    }

    /// T3a-3: `MKTD02_EVENT_V2` is exact ASCII with no terminator and collides
    /// with no other tag — active, retired, or the tombstone seed.
    #[test]
    fn t3a3_tag_event_v2_is_exact_ascii_and_distinct_from_every_other_tag() {
        assert_eq!(TAG_EVENT_V2.0, b"MKTD02_EVENT_V2");
        assert_eq!(TAG_EVENT_V2.0.len(), 15);
        assert!(TAG_EVENT_V2.0.iter().all(|b| b.is_ascii_graphic()));
        assert!(!TAG_EVENT_V2.0.contains(&0u8));

        let others: &[DomainTag] = &[
            TAG_TOMBSTONE_HASH,
            TAG_EVENT,
            TAG_RECEIPT,
            TAG_RECEIPT_V3,
            TAG_SALT,
            TAG_MANIFEST,
            TAG_GENESIS,
        ];
        for tag in others {
            assert_ne!(
                TAG_EVENT_V2.0, tag.0,
                "v5 event tag collides with an active tag"
            );
        }
        for retired in RETIRED_TAGS {
            assert_ne!(
                TAG_EVENT_V2.0, retired.bytes,
                "v5 event tag reuses retired bytes"
            );
        }
        assert_ne!(TAG_EVENT_V2.0, TOMBSTONE_SEED);
    }

    /// T3a-3: the new tag follows the same tag-first discipline as every other.
    #[test]
    fn t3a3_tag_event_v2_follows_hash_with_tag_discipline() {
        assert_eq!(
            hash_with_tag(TAG_EVENT_V2, &[b"a", b"b"]),
            sha256_concat(&[b"MKTD02_EVENT_V2", b"a", b"b"])
        );
    }
    // ---------------------------------------------------------------
    // Golden vectors — lock down exact hash outputs.
    // Computed independently via Python hashlib. Any change here
    // means the protocol has changed and all existing CVDRs break.
    // ---------------------------------------------------------------

    #[test]
    fn golden_tombstone_seed() {
        let tombstone = sha256(TOMBSTONE_SEED);
        assert_eq!(
            hex::encode(tombstone),
            "485a0cf91d7feb0f97f428df6328feca93788456a5b614b1bcedf6c4dc0e8d2a",
            "tombstone constant changed — this breaks all existing tombstones"
        );
    }

    #[test]
    fn golden_tag_tombstone_hash() {
        assert_eq!(
            hex::encode(hash_with_tag(TAG_TOMBSTONE_HASH, &[b"test"])),
            "1d458fe278607fd548c30148ffd8eb9fba8c132cc9b1ec5039b7c973ef3bd322"
        );
    }

    #[test]
    fn golden_tag_event() {
        assert_eq!(
            hex::encode(hash_with_tag(TAG_EVENT, &[b"test"])),
            "6393c15cb2820d70e84c82c0928fccf15792cb3f79bb0783a78eb050260a977f"
        );
    }

    #[test]
    fn golden_tag_receipt() {
        assert_eq!(
            hex::encode(hash_with_tag(TAG_RECEIPT, &[b"test"])),
            "b5acde122055eed7a27d1af0e0d6cf510b8afa1532c4383193587e3c57001b15"
        );
    }

    #[test]
    fn golden_tag_receipt_v3() {
        assert_eq!(
            hex::encode(hash_with_tag(TAG_RECEIPT_V3, &[b"test"])),
            "80cace4a6dd613ebab643c887df83b0240a801a607512cd5445031a32b30dd86"
        );
    }

    #[test]
    fn golden_tag_salt() {
        assert_eq!(
            hex::encode(hash_with_tag(TAG_SALT, &[b"test"])),
            "59c364395836b540971fcc4021eaf977deaf174d6eb87b2da68b30e46df66b4a"
        );
    }

    #[test]
    fn golden_tag_manifest() {
        assert_eq!(
            hex::encode(hash_with_tag(TAG_MANIFEST, &[b"test"])),
            "158e49fbae2d7356adccead6973a51722c587a935fdbda455592a1dbb8bc31f2"
        );
    }
    /// Golden vector for v0.2.0 deletion_event_hash formula.
    /// Inputs: pre_state=[1;32], post_state=[2;32], timestamp=1_000_000,
    /// module_hash=[3;32], nonce=1. Note: NO manifest_hash in preimage.
    /// Computed independently via Python hashlib.
    #[test]
    fn golden_deletion_event_hash_v2() {
        let pre_state = [1u8; 32];
        let post_state = [2u8; 32];
        let timestamp = 1_000_000u64.to_be_bytes();
        let module_hash = [3u8; 32];
        let nonce = 1u64.to_be_bytes();

        let result = hash_with_tag(
            TAG_EVENT,
            &[&pre_state, &post_state, &timestamp, &module_hash, &nonce],
        );

        assert_eq!(
            hex::encode(result),
            "9078d9a080606b46298bd9d66d3dd4a75389b04f7531b53a3a0e7c8f25955023",
            "v0.2.0 deletion_event_hash formula changed — manifest_hash must NOT be in preimage"
        );
    }

    /// v4-HISTORICAL — retired pins (SR-06, 11 Sep 2026).
    ///
    /// Locks constructions mktd02-v5 no longer produces, so issued v2–v4
    /// receipts stay explainable. Do not edit, regenerate, or extend. Retired
    /// tags hash via `RetiredTag::hash_historical` (`hash_with_tag` refuses them).
    mod v4_historical {
        use super::super::*;

        #[test]
        fn golden_tag_certified() {
            assert_eq!(
                hex::encode(TAG_CERTIFIED.hash_historical(&[b"test"])),
                "b2a533ef0b75007545bda617076df5a8694db1e3f6ae0c3050b45b81d0cfcf5c"
            );
        }
    }
}
