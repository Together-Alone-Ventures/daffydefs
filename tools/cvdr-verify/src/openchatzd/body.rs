//! RECEIPT_BODY_V1 parser + leaf recompute + TARGETS_COMMITMENT_V1.
//!
//! Layouts are FROZEN and CD-verified; recomputed here exactly as pinned in
//! OpenChatZD's `CVDR_BUILD_SPEC_V1.md` §2 (that file is authoritative). This is
//! an INDEPENDENT re-implementation from the spec — not a port of OpenChatZD's
//! encoder — so a byte-level disagreement is a real cross-repo layout drift.
//!
//! `RECEIPT_BODY_V1` (spec §2, versioned fixed-width tag-concatenation, NOT CBOR):
//! ```text
//! RECEIPT_BODY_TAG(26)                         b"OPENCHATZD_RECEIPT_BODY_V1"
//!   ‖ receipt_id(32)
//!   ‖ nonce(32)
//!   ‖ index_canister_id   (len(u8) ‖ raw principal bytes)
//!   ‖ user_canister_id    (len(u8) ‖ raw principal bytes)
//!   ‖ record_id(32)
//!   ‖ deletion_seq(u64 BE, 8)
//!   ‖ h_user_pre(32)
//!   ‖ h_index(32)
//!   ‖ commitment(32)
//!   ‖ uninstall_completed_at(u64 BE ns, 8)
//!   ‖ receipt_committed_at(u64 BE ns, 8)      // window anchor (hash-bound)
//!   ‖ targets_count(u32 BE, 4)
//!   ‖ targets_commitment(32)
//! ```
//! `leaf = SHA256(RECEIPT_LEAF_TAG ‖ receipt_body)` == the frozen package
//! `receipt_hash` and the value revealed at the witness leaf.

use anyhow::{anyhow, bail, Result};
use candid::Principal;
use zombie_core::hashing::sha256_concat;

/// b"OPENCHATZD_RECEIPT_BODY_V1" (26 bytes) — RECEIPT_BODY_V1 preimage tag (spec §2).
pub const RECEIPT_BODY_TAG: &[u8] = b"OPENCHATZD_RECEIPT_BODY_V1";
/// b"OPENCHATZD_RECEIPT_LEAF_V1" — receipt-tree leaf tag (spec §2).
pub const RECEIPT_LEAF_TAG: &[u8] = b"OPENCHATZD_RECEIPT_LEAF_V1";
/// b"OPENCHATZD_TARGETS_COMMITMENT_V1" — TARGETS_COMMITMENT_V1 tag (spec §2).
pub const TARGETS_COMMITMENT_TAG: &[u8] = b"OPENCHATZD_TARGETS_COMMITMENT_V1";
/// b"OPENCHATZD_CVDR_H_INDEX_V1" — H_INDEX_V1 preimage tag (spec §2).
///
/// CD-anchoring is TRANSITIVE, not direct: no CD anchor names this tag. It is
/// implied by the leaf anchor `7aeb124f…`, which digests the 300-byte unit-vector
/// body whose `h_index` field is built with this tag (`fixtures.rs`). Byte
/// agreement on the leaf therefore pins this preimage. `CVDR_BUILD_SPEC_V1.md` §2
/// remains authoritative; a direct CD anchor for `h_index` would strengthen this.
pub const H_INDEX_TAG: &[u8] = b"OPENCHATZD_CVDR_H_INDEX_V1";
/// Byte-string label for the receipt-tree path `["receipts", receipt_id]` (spec §2).
pub const RECEIPTS_LABEL: &[u8] = b"receipts";

/// Parsed RECEIPT_BODY_V1 fields. Every field is exposed in the verifier report.
#[derive(Debug, Clone)]
pub struct ReceiptBody {
    pub receipt_id: [u8; 32],
    pub nonce: [u8; 32],
    pub index_canister_id: Principal,
    pub user_canister_id: Principal,
    pub record_id: [u8; 32],
    pub deletion_seq: u64,
    pub h_user_pre: [u8; 32],
    pub h_index: [u8; 32],
    pub commitment: [u8; 32],
    pub uninstall_completed_at_ns: u64,
    pub receipt_committed_at_ns: u64,
    pub targets_count: u32,
    pub targets_commitment: [u8; 32],
}

/// Little cursor over the fixed-width body; fails closed on any short read.
struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn take(&mut self, n: usize, what: &str) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or_else(|| anyhow!("length overflow reading {}", what))?;
        if end > self.buf.len() {
            bail!(
                "RECEIPT_BODY_V1 truncated: need {} bytes for {} at offset {}, have {}",
                n,
                what,
                self.pos,
                self.buf.len().saturating_sub(self.pos)
            );
        }
        let out = &self.buf[self.pos..end];
        self.pos = end;
        Ok(out)
    }

    fn take_array<const N: usize>(&mut self, what: &str) -> Result<[u8; N]> {
        let s = self.take(N, what)?;
        let mut arr = [0u8; N];
        arr.copy_from_slice(s);
        Ok(arr)
    }

    fn take_u8(&mut self, what: &str) -> Result<u8> {
        Ok(self.take(1, what)?[0])
    }

    /// `len(u8) ‖ raw principal bytes` — the frozen self-delimiting principal
    /// encoding (spec §2 G adjacency ruling; unifies with TARGETS_COMMITMENT_V1).
    fn take_principal(&mut self, what: &str) -> Result<Principal> {
        let len = self.take_u8(&format!("{} length prefix", what))? as usize;
        if len > 29 {
            bail!(
                "{}: principal length prefix {} exceeds 29 (IC principals are <=29 bytes)",
                what,
                len
            );
        }
        let bytes = self.take(len, &format!("{} bytes", what))?;
        Ok(Principal::from_slice(bytes))
    }
}

impl ReceiptBody {
    /// Parse the fixed-width tag-concatenation. Rejects a wrong/absent tag, any
    /// truncation, and trailing bytes (the body must be exactly consumed).
    pub fn parse(body: &[u8]) -> Result<Self> {
        let mut c = Cursor::new(body);

        let tag = c.take(RECEIPT_BODY_TAG.len(), "RECEIPT_BODY_TAG")?;
        if tag != RECEIPT_BODY_TAG {
            bail!(
                "RECEIPT_BODY_TAG mismatch: expected {:?}, found {:?}",
                String::from_utf8_lossy(RECEIPT_BODY_TAG),
                String::from_utf8_lossy(tag)
            );
        }

        let receipt_id = c.take_array::<32>("receipt_id")?;
        let nonce = c.take_array::<32>("nonce")?;
        let index_canister_id = c.take_principal("index_canister_id")?;
        let user_canister_id = c.take_principal("user_canister_id")?;
        let record_id = c.take_array::<32>("record_id")?;
        let deletion_seq = u64::from_be_bytes(c.take_array::<8>("deletion_seq")?);
        let h_user_pre = c.take_array::<32>("h_user_pre")?;
        let h_index = c.take_array::<32>("h_index")?;
        let commitment = c.take_array::<32>("commitment")?;
        let uninstall_completed_at_ns = u64::from_be_bytes(c.take_array::<8>("uninstall_completed_at")?);
        let receipt_committed_at_ns = u64::from_be_bytes(c.take_array::<8>("receipt_committed_at")?);
        let targets_count = u32::from_be_bytes(c.take_array::<4>("targets_count")?);
        let targets_commitment = c.take_array::<32>("targets_commitment")?;

        if c.pos != body.len() {
            bail!(
                "RECEIPT_BODY_V1 has {} trailing byte(s) after targets_commitment (parsed {} of {})",
                body.len() - c.pos,
                c.pos,
                body.len()
            );
        }

        Ok(Self {
            receipt_id,
            nonce,
            index_canister_id,
            user_canister_id,
            record_id,
            deletion_seq,
            h_user_pre,
            h_index,
            commitment,
            uninstall_completed_at_ns,
            receipt_committed_at_ns,
            targets_count,
            targets_commitment,
        })
    }
}

/// `leaf = SHA256(RECEIPT_LEAF_TAG ‖ receipt_body)` (spec §2).
pub fn receipt_leaf(receipt_body: &[u8]) -> [u8; 32] {
    sha256_concat(&[RECEIPT_LEAF_TAG, receipt_body])
}

/// `h_index = SHA256(H_INDEX_TAG ‖ index_principal ‖ executor_module_hash)` (spec §2).
///
/// The body's `h_index` is hash-bound, so recomputing it from a caller-supplied
/// `executor_module_hash` decides — OFFLINE — whether the receipt commits to that
/// exact module. This is the only comparison that binds a module hash to the
/// receipt; a live `module_hash` read from the chain says what the canister runs
/// *now*, which is a different claim (see `--corroborate-h-index`).
pub fn h_index_for(index_canister_id: Principal, executor_module_hash: &[u8; 32]) -> [u8; 32] {
    sha256_concat(&[H_INDEX_TAG, index_canister_id.as_slice(), executor_module_hash])
}

/// `TARGETS_COMMITMENT_V1` (spec §2, FROZEN): sort targets ascending by raw
/// principal bytes, `serialized = concat(len(u8) ‖ principal_bytes)`,
/// `commitment = SHA256(TARGETS_COMMITMENT_TAG ‖ salt ‖ serialized)`.
///
/// `enforce_sorted`: when true (reveal-package mode), the input MUST already be
/// strictly ascending — a non-sorted or duplicate list is rejected rather than
/// silently reordered, since a valid reveal package hands the user the *sorted*
/// list and any deviation signals a malformed/tampered package. When false the
/// caller has vetted ordering.
pub fn targets_commitment(
    salt: &[u8; 32],
    targets: &[Principal],
    enforce_sorted: bool,
) -> Result<[u8; 32]> {
    if enforce_sorted {
        for w in targets.windows(2) {
            if w[0].as_slice() >= w[1].as_slice() {
                bail!(
                    "reveal target list is not strictly ascending by raw principal bytes \
                     (offending pair: {} then {}); a valid reveal package is pre-sorted and \
                     duplicate-free",
                    w[0],
                    w[1]
                );
            }
        }
    }

    let mut sorted: Vec<&Principal> = targets.iter().collect();
    sorted.sort_by(|a, b| a.as_slice().cmp(b.as_slice()));

    let mut serialized: Vec<u8> = Vec::new();
    for t in sorted {
        let bytes = t.as_slice();
        // Principals are <= 29 bytes, so the u8 length prefix always fits.
        serialized.push(bytes.len() as u8);
        serialized.extend_from_slice(bytes);
    }
    Ok(sha256_concat(&[TARGETS_COMMITMENT_TAG, salt, &serialized]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn receipt_body_tag_is_26_bytes() {
        // The whole 300-byte-with-10-byte-principals invariant depends on this.
        assert_eq!(RECEIPT_BODY_TAG.len(), 26);
    }

    #[test]
    fn rejects_wrong_tag() {
        let mut body = vec![0u8; 300];
        body[..26].copy_from_slice(b"OPENCHATZD_RECEIPT_XXXX_V1");
        let err = ReceiptBody::parse(&body).unwrap_err().to_string();
        assert!(err.contains("RECEIPT_BODY_TAG mismatch"), "{err}");
    }

    #[test]
    fn rejects_truncation() {
        let mut body = Vec::new();
        body.extend_from_slice(RECEIPT_BODY_TAG);
        body.extend_from_slice(&[0u8; 10]);
        let err = ReceiptBody::parse(&body).unwrap_err().to_string();
        assert!(err.contains("truncated"), "{err}");
    }

    #[test]
    fn targets_commitment_rejects_unsorted_when_enforced() {
        let a = Principal::from_slice(&[3u8; 10]);
        let b = Principal::from_slice(&[1u8; 10]);
        let salt = [9u8; 32];
        let err = targets_commitment(&salt, &[a, b], true).unwrap_err().to_string();
        assert!(err.contains("not strictly ascending"), "{err}");
        // same set, pre-sorted, is accepted and order-independent vs unsorted recompute
        let sorted_ok = targets_commitment(&salt, &[b, a], false).unwrap();
        let enforced_ok = targets_commitment(&salt, &[b, a], true).unwrap();
        assert_eq!(sorted_ok, enforced_ok);
    }
}
