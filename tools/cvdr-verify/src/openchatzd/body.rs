//! RECEIPT_BODY_V2 / RECEIPT_BODY_V1 parser + leaf recompute + TARGETS_COMMITMENT_V1.
//!
//! Layouts are FROZEN; recomputed here from the OpenChatZD normative formulas
//! (suite-v5 rulings R-1/R-2/R-4/R-5; `CVDR_BUILD_SPEC` §2). This is an INDEPENDENT
//! re-implementation — not a port of OpenChatZD's encoder — so a byte-level
//! disagreement is a real cross-repo layout drift.
//!
//! The body is dispatched on its leading tag, exact match only:
//! - `RECEIPT_BODY_V2` (LIVE — suite v5, R-4): `RECEIPT_BODY_V1 − {h_index, commitment}`;
//!   `record_id` is the non-identifying salted derivation (R-1).
//! - `RECEIPT_BODY_V1` (HISTORICAL — decoded for pre-v5 packages only).
//!
//! Any other tag is malformed.
//!
//! `RECEIPT_BODY_V2` (fixed-width tag-concatenation, NOT CBOR):
//! ```text
//! RECEIPT_BODY_TAG_V2(26)                      b"OPENCHATZD_RECEIPT_BODY_V2"
//!   ‖ receipt_id(32)
//!   ‖ nonce(32)
//!   ‖ index_canister_id   (len(u8) ‖ raw principal bytes)
//!   ‖ user_canister_id    (len(u8) ‖ raw principal bytes)
//!   ‖ record_id(32)
//!   ‖ deletion_seq(u64 BE, 8)
//!   ‖ h_user_pre(32)                            // Index-recorded observation (R-2 addendum)
//!   ‖ uninstall_completed_at(u64 BE ns, 8)     // V3A not-before anchor (hash-bound)
//!   ‖ receipt_committed_at(u64 BE ns, 8)       // window anchor (hash-bound)
//!   ‖ targets_count(u32 BE, 4)
//!   ‖ targets_commitment(32)
//! ```
//! `RECEIPT_BODY_V1` (historical) additionally carries `h_index(32) ‖ commitment(32)`
//! between `h_user_pre` and `uninstall_completed_at`:
//! ```text
//! RECEIPT_BODY_TAG_V1(26)                      b"OPENCHATZD_RECEIPT_BODY_V1"
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

/// b"OPENCHATZD_RECEIPT_BODY_V2" (26 bytes) — the LIVE body tag (suite v5, R-4).
pub const RECEIPT_BODY_TAG_V2: &[u8] = b"OPENCHATZD_RECEIPT_BODY_V2";
/// b"OPENCHATZD_RECEIPT_BODY_V1" (26 bytes) — HISTORICAL body tag (pre-v5 packages only).
pub const RECEIPT_BODY_TAG_V1: &[u8] = b"OPENCHATZD_RECEIPT_BODY_V1";

/// Which body layout a receipt carries. Decided by exact tag match, never by length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyVersion {
    /// Historical: pre-v5 OpenChatZD receipts (deployer `h_index` + displayed `commitment`).
    V1,
    /// Live: suite v5 (R-4).
    V2,
}

impl BodyVersion {
    pub fn tag(self) -> &'static [u8] {
        match self {
            BodyVersion::V1 => RECEIPT_BODY_TAG_V1,
            BodyVersion::V2 => RECEIPT_BODY_TAG_V2,
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            BodyVersion::V1 => "RECEIPT_BODY_V1",
            BodyVersion::V2 => "RECEIPT_BODY_V2",
        }
    }
}
/// b"OPENCHATZD_RECEIPT_LEAF_V1" — receipt-tree leaf tag (spec §2).
pub const RECEIPT_LEAF_TAG: &[u8] = b"OPENCHATZD_RECEIPT_LEAF_V1";
/// b"OPENCHATZD_TARGETS_COMMITMENT_V1" — TARGETS_COMMITMENT_V1 tag (spec §2).
pub const TARGETS_COMMITMENT_TAG: &[u8] = b"OPENCHATZD_TARGETS_COMMITMENT_V1";
/// b"OPENCHATZD_CVDR_H_INDEX_V1" — HISTORICAL H_INDEX_V1 preimage tag (RECEIPT_BODY_V1 only;
/// retired by suite-v5 ruling R-2 — never reused, never a live trust input).
pub const H_INDEX_TAG: &[u8] = b"OPENCHATZD_CVDR_H_INDEX_V1";
/// Byte-string label for the receipt-tree path `["receipts", receipt_id]` (spec §2).
pub const RECEIPTS_LABEL: &[u8] = b"receipts";

/// Parsed receipt body (V2 live / V1 historical). Every field is exposed in the verifier report.
#[derive(Debug, Clone)]
pub struct ReceiptBody {
    pub version: BodyVersion,
    pub receipt_id: [u8; 32],
    pub nonce: [u8; 32],
    pub index_canister_id: Principal,
    pub user_canister_id: Principal,
    /// V2: non-identifying `SHA256(RECORD_ID_TAG_V2 ‖ record_salt ‖ principal)` (R-1) — displayed,
    /// bound through `receipt_id` and the leaf; recomputable only with the user's RevealWire salt.
    pub record_id: [u8; 32],
    pub deletion_seq: u64,
    /// Index-recorded observation of the target's pre-uninstall module hash — integrity-bound by
    /// the certified receipt relation, NOT independently attested (R-2 addendum).
    pub h_user_pre: [u8; 32],
    /// Historical (V1 only): deployer-derived executor hash. `None` on V2.
    pub h_index: Option<[u8; 32]>,
    /// Historical (V1 only): displayed commitment. `None` on V2.
    pub commitment: Option<[u8; 32]>,
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
                "receipt body truncated: need {} bytes for {} at offset {}, have {}",
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

/// b"OPENCHATZD_CVDR_RECEIPT_V1" — receipt_id derivation tag (spec §2).
pub const RECEIPT_ID_TAG: &[u8] = b"OPENCHATZD_CVDR_RECEIPT_V1";

/// Recompute `receipt_id = SHA256(RECEIPT_ID_TAG ‖ record_id ‖ deletion_seq_be ‖ nonce)`.
pub fn receipt_id_for(record_id: &[u8; 32], deletion_seq: u64, nonce: &[u8; 32]) -> [u8; 32] {
    sha256_concat(&[
        RECEIPT_ID_TAG,
        record_id.as_slice(),
        &deletion_seq.to_be_bytes(),
        nonce.as_slice(),
    ])
}

impl ReceiptBody {
    /// Parse the fixed-width tag-concatenation, dispatching on the EXACT leading tag
    /// (`RECEIPT_BODY_V2` live, `RECEIPT_BODY_V1` historical). Rejects any other tag, any
    /// truncation, and trailing bytes (the body must be exactly consumed).
    pub fn parse(body: &[u8]) -> Result<Self> {
        let mut c = Cursor::new(body);

        let tag = c.take(RECEIPT_BODY_TAG_V2.len(), "RECEIPT_BODY_TAG")?;
        let version = if tag == BodyVersion::V2.tag() {
            BodyVersion::V2
        } else if tag == BodyVersion::V1.tag() {
            BodyVersion::V1
        } else {
            bail!(
                "RECEIPT_BODY_TAG mismatch: expected {:?} (live) or {:?} (historical), found {:?}",
                String::from_utf8_lossy(BodyVersion::V2.tag()),
                String::from_utf8_lossy(BodyVersion::V1.tag()),
                String::from_utf8_lossy(tag)
            );
        };

        let receipt_id = c.take_array::<32>("receipt_id")?;
        let nonce = c.take_array::<32>("nonce")?;
        let index_canister_id = c.take_principal("index_canister_id")?;
        let user_canister_id = c.take_principal("user_canister_id")?;
        let record_id = c.take_array::<32>("record_id")?;
        let deletion_seq = u64::from_be_bytes(c.take_array::<8>("deletion_seq")?);
        let h_user_pre = c.take_array::<32>("h_user_pre")?;
        let (h_index, commitment) = match version {
            BodyVersion::V1 => (
                Some(c.take_array::<32>("h_index")?),
                Some(c.take_array::<32>("commitment")?),
            ),
            BodyVersion::V2 => (None, None),
        };
        let uninstall_completed_at_ns =
            u64::from_be_bytes(c.take_array::<8>("uninstall_completed_at")?);
        let receipt_committed_at_ns =
            u64::from_be_bytes(c.take_array::<8>("receipt_committed_at")?);
        let targets_count = u32::from_be_bytes(c.take_array::<4>("targets_count")?);
        let targets_commitment = c.take_array::<32>("targets_commitment")?;

        if c.pos != body.len() {
            bail!(
                "{} has {} trailing byte(s) after targets_commitment (parsed {} of {})",
                version.label(),
                body.len() - c.pos,
                c.pos,
                body.len()
            );
        }

        Ok(Self {
            version,
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

/// HISTORICAL (RECEIPT_BODY_V1 only): `h_index = SHA256(H_INDEX_TAG ‖ index_principal ‖
/// executor_module_hash)`. Under suite v5 (R-2) no deployer-supplied module hash enters a receipt;
/// a V2 body has no `h_index` and this is never evaluated for it.
pub fn h_index_for(index_canister_id: Principal, executor_module_hash: &[u8; 32]) -> [u8; 32] {
    sha256_concat(&[
        H_INDEX_TAG,
        index_canister_id.as_slice(),
        executor_module_hash,
    ])
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
        assert_eq!(RECEIPT_BODY_TAG_V1.len(), 26);
        assert_eq!(RECEIPT_BODY_TAG_V2.len(), 26);
        assert_ne!(RECEIPT_BODY_TAG_V1, RECEIPT_BODY_TAG_V2);
    }

    /// Tag dispatch is exact: V2 parses to the 236-byte layout without h_index/commitment, V1 to
    /// the 300-byte layout with them, and a V1-length body under a V2 tag (or any unknown tag) is
    /// malformed — never a prefix match, never a length guess.
    #[test]
    fn tag_dispatch_is_exact_and_fails_closed() {
        let p10 = [0x11u8; 10];
        let mut v2 = Vec::new();
        v2.extend_from_slice(RECEIPT_BODY_TAG_V2);
        v2.extend_from_slice(&[1u8; 32]); // receipt_id
        v2.extend_from_slice(&[2u8; 32]); // nonce
        for _ in 0..2 {
            v2.push(10);
            v2.extend_from_slice(&p10);
        }
        v2.extend_from_slice(&[3u8; 32]); // record_id
        v2.extend_from_slice(&7u64.to_be_bytes());
        v2.extend_from_slice(&[4u8; 32]); // h_user_pre
        let tail = {
            let mut t = Vec::new();
            t.extend_from_slice(&111u64.to_be_bytes());
            t.extend_from_slice(&222u64.to_be_bytes());
            t.extend_from_slice(&2u32.to_be_bytes());
            t.extend_from_slice(&[5u8; 32]);
            t
        };
        let mut v2_full = v2.clone();
        v2_full.extend_from_slice(&tail);
        assert_eq!(v2_full.len(), 26 + 64 + 22 + 32 + 8 + 32 + 8 + 8 + 4 + 32);
        let b = ReceiptBody::parse(&v2_full).expect("V2 parses");
        assert_eq!(b.version, BodyVersion::V2);
        assert_eq!((b.h_index, b.commitment), (None, None));
        assert_eq!(
            (
                b.uninstall_completed_at_ns,
                b.receipt_committed_at_ns,
                b.targets_count
            ),
            (111, 222, 2)
        );

        // V1 = same fields plus h_index ‖ commitment before the timestamps.
        let mut v1 = v2.clone();
        v1[..26].copy_from_slice(RECEIPT_BODY_TAG_V1);
        v1.extend_from_slice(&[8u8; 32]);
        v1.extend_from_slice(&[9u8; 32]);
        v1.extend_from_slice(&tail);
        let b1 = ReceiptBody::parse(&v1).expect("V1 (historical) parses");
        assert_eq!(b1.version, BodyVersion::V1);
        assert_eq!(
            (b1.h_index, b1.commitment),
            (Some([8u8; 32]), Some([9u8; 32]))
        );

        // V1 layout under the V2 tag: 64 trailing bytes => malformed.
        let mut mixed = v1.clone();
        mixed[..26].copy_from_slice(RECEIPT_BODY_TAG_V2);
        let err = ReceiptBody::parse(&mixed).unwrap_err().to_string();
        assert!(err.contains("trailing"), "{err}");
        // V2 layout under the V1 tag: truncated => malformed.
        let mut mixed2 = v2_full.clone();
        mixed2[..26].copy_from_slice(RECEIPT_BODY_TAG_V1);
        assert!(ReceiptBody::parse(&mixed2)
            .unwrap_err()
            .to_string()
            .contains("truncated"));
        // Unknown / future tag => malformed, named.
        let mut v3 = v2_full.clone();
        v3[..26].copy_from_slice(b"OPENCHATZD_RECEIPT_BODY_V3");
        assert!(ReceiptBody::parse(&v3)
            .unwrap_err()
            .to_string()
            .contains("RECEIPT_BODY_TAG mismatch"));
    }

    #[test]
    fn receipt_id_for_matches_tagged_preimage() {
        let record_id = [0xabu8; 32];
        let nonce = [0xcd; 32];
        let seq = 7u64;
        let expected = sha256_concat(&[RECEIPT_ID_TAG, &record_id, &seq.to_be_bytes(), &nonce]);
        assert_eq!(receipt_id_for(&record_id, seq, &nonce), expected);
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
        body.extend_from_slice(RECEIPT_BODY_TAG_V2);
        body.extend_from_slice(&[0u8; 10]);
        let err = ReceiptBody::parse(&body).unwrap_err().to_string();
        assert!(err.contains("truncated"), "{err}");
    }

    #[test]
    fn targets_commitment_rejects_unsorted_when_enforced() {
        let a = Principal::from_slice(&[3u8; 10]);
        let b = Principal::from_slice(&[1u8; 10]);
        let salt = [9u8; 32];
        let err = targets_commitment(&salt, &[a, b], true)
            .unwrap_err()
            .to_string();
        assert!(err.contains("not strictly ascending"), "{err}");
        // same set, pre-sorted, is accepted and order-independent vs unsorted recompute
        let sorted_ok = targets_commitment(&salt, &[b, a], false).unwrap();
        let enforced_ok = targets_commitment(&salt, &[b, a], true).unwrap();
        assert_eq!(sorted_ok, enforced_ok);
    }
}
