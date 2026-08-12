//! Witness verification (spec §2/§9): decode the stored-verbatim IC `HashTree`
//! CBOR, recompute the certified root, and confirm the leaf sits at the frozen
//! path `["receipts", receipt_id]` with value == `receipt_hash`.
//!
//! `receipt_id` is taken from the PARSED body (hash-bound identity), never a
//! caller argument — a package cannot point its own witness at a different id.

use anyhow::{anyhow, bail, Result};
use ic_agent::hash_tree::{HashTree, LookupResult};

use super::body::RECEIPTS_LABEL;

/// Outcome of decoding + checking the witness.
#[derive(Debug)]
pub struct WitnessOutcome {
    /// Recomputed certified root == `HashTree::digest()`.
    pub root: [u8; 32],
    /// Value found at `["receipts", receipt_id]`.
    pub leaf_value: [u8; 32],
}

/// Decode `witness_bytes` as an IC HashTree and extract (root, leaf@path).
///
/// Does NOT itself compare against `tree_root`/`receipt_hash`; the caller wires
/// those comparisons to §9 rules 1 and 2 so the reject reason is precise. Fails
/// closed if the path is absent/pruned/ambiguous or the leaf is not 32 bytes.
pub fn decode_and_locate(witness_bytes: &[u8], receipt_id: &[u8; 32]) -> Result<WitnessOutcome> {
    let tree: HashTree<Vec<u8>> = serde_cbor::from_slice(witness_bytes)
        .map_err(|e| anyhow!("witness does not decode as an IC HashTree (CBOR): {}", e))?;

    let root = tree.digest();

    let leaf_value = match tree.lookup_path([RECEIPTS_LABEL, receipt_id.as_slice()]) {
        LookupResult::Found(v) => {
            if v.len() != 32 {
                bail!(
                    "witness leaf at [\"receipts\", receipt_id] is {} bytes, expected 32",
                    v.len()
                );
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(v);
            arr
        }
        LookupResult::Absent => bail!(
            "witness proves ABSENCE at [\"receipts\", {}] — leaf not present",
            hex::encode(receipt_id)
        ),
        LookupResult::Unknown => bail!(
            "witness is pruned at [\"receipts\", {}] — leaf not revealed (cannot bind receipt_hash)",
            hex::encode(receipt_id)
        ),
        LookupResult::Error => bail!(
            "witness path [\"receipts\", receipt_id] is malformed for this tree"
        ),
    };

    Ok(WitnessOutcome { root, leaf_value })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_agent::hash_tree::{label, leaf};

    fn single_leaf_witness(receipt_id: &[u8; 32], receipt_hash: &[u8; 32]) -> Vec<u8> {
        let tree = label(RECEIPTS_LABEL, label(receipt_id.to_vec(), leaf(receipt_hash.to_vec())));
        serde_cbor::to_vec(&tree).unwrap()
    }

    #[test]
    fn locates_leaf_and_recomputes_root() {
        let rid = [0x11u8; 32];
        let rhash = [0xAAu8; 32];
        let w = single_leaf_witness(&rid, &rhash);
        let out = decode_and_locate(&w, &rid).unwrap();
        assert_eq!(out.leaf_value, rhash);
        // root must equal the ic-agent digest of the same tree
        let tree: HashTree<Vec<u8>> = serde_cbor::from_slice(&w).unwrap();
        assert_eq!(out.root, tree.digest());
    }

    #[test]
    fn rejects_wrong_receipt_id() {
        let rid = [0x11u8; 32];
        let rhash = [0xAAu8; 32];
        let w = single_leaf_witness(&rid, &rhash);
        let err = decode_and_locate(&w, &[0x22u8; 32]).unwrap_err().to_string();
        assert!(err.contains("ABSENCE") || err.contains("pruned"), "{err}");
    }
}
