//! V1 — internal consistency of the receipt.
//!
//! - **mktd02-v5:** the normative `zombie_core::verify_v1` (receipt_id first,
//!   then the event hash over the checked receipt_id). Its named errors are
//!   surfaced verbatim. The verifier does not compose the v5 steps itself.
//! - **mktd02-v2 … v4 (historical):** the frozen constructions, recomputed with
//!   zombie-core's historical helpers: receipt_id per line (v2 legacy, v3/v4
//!   length-delimited), `deletion_event_hash_v1`, `certified_commitment` under
//!   the retired tag via `TAG_CERTIFIED.hash_historical`, and `tombstone_hash`.

use candid::Principal;
use zombie_core::hashing::{
    hash_with_tag, sha256, TAG_CERTIFIED, TAG_TOMBSTONE_HASH, TOMBSTONE_SEED,
};
use zombie_core::receipt::{compute_receipt_id, compute_receipt_id_v2};
use zombie_core::{deletion_event_hash_v1, verify_v1, AnyDeletionReceipt, DeletionReceiptV4};

use crate::report::{CheckOutcome, ProtocolLine};

/// Named historical V1 failures (the v5 names come from zombie-core).
pub const ERR_V1_HIST_RECEIPT_ID: &str = "v1-historical:receipt-id-mismatch";
pub const ERR_V1_HIST_EVENT_HASH: &str = "v1-historical:event-hash-mismatch";
pub const ERR_V1_HIST_CERTIFIED_COMMITMENT: &str = "v1-historical:certified-commitment-mismatch";
pub const ERR_V1_HIST_TOMBSTONE_HASH: &str = "v1-historical:tombstone-hash-mismatch";

/// Run V1 for any supported line.
pub fn verify(receipt: &AnyDeletionReceipt) -> CheckOutcome {
    match receipt {
        AnyDeletionReceipt::V5(r) => match verify_v1(r) {
            Ok(()) => CheckOutcome::pass(
                "receipt_id and deletion_event_hash recomputed (normative mktd02-v5 V1)",
            ),
            Err(named) => CheckOutcome::fail(named, None),
        },
        AnyDeletionReceipt::V4(r) => verify_historical(r),
    }
}

/// `tombstone_hash` under the v2–v4 construction:
/// `SHA-256(TAG_TOMBSTONE_HASH ‖ canister ‖ SHA-256(TOMBSTONE_SEED) ‖ u64_be(timestamp) ‖ u64_be(deletion_seq))`.
pub fn historical_tombstone_hash(
    canister_id: &Principal,
    timestamp: u64,
    deletion_seq: u64,
) -> [u8; 32] {
    hash_with_tag(
        TAG_TOMBSTONE_HASH,
        &[
            canister_id.as_slice(),
            &sha256(TOMBSTONE_SEED),
            &timestamp.to_be_bytes(),
            &deletion_seq.to_be_bytes(),
        ],
    )
}

/// `certified_commitment` under the retired v2–v4 construction:
/// `SHA-256(MKTD02_CERTIFIED_V1 ‖ post_state_hash ‖ deletion_event_hash)`.
pub fn historical_certified_commitment(
    post_state_hash: &[u8; 32],
    deletion_event_hash: &[u8; 32],
) -> [u8; 32] {
    TAG_CERTIFIED.hash_historical(&[post_state_hash, deletion_event_hash])
}

/// The receipt_id construction for a historical receipt's line.
pub fn historical_receipt_id(receipt: &DeletionReceiptV4) -> [u8; 32] {
    match ProtocolLine::of_v4_label(&receipt.protocol_version) {
        ProtocolLine::V2 => compute_receipt_id_v2(&receipt.canister_id, receipt.deletion_seq),
        // v4 reuses the v3 length-delimited formula (TAG_RECEIPT_V3).
        _ => compute_receipt_id(
            &receipt.canister_id,
            &receipt.record_id,
            receipt.deletion_seq,
        ),
    }
}

/// Historical V1. Every construction is recomputed so the detail lists all
/// mismatches; the named error is the first in the order receipt_id →
/// deletion_event_hash → certified_commitment → tombstone_hash.
pub fn verify_historical(receipt: &DeletionReceiptV4) -> CheckOutcome {
    let expected_id = historical_receipt_id(receipt);
    let expected_event = deletion_event_hash_v1(
        &receipt.pre_state_hash,
        &receipt.post_state_hash,
        receipt.timestamp,
        &receipt.module_hash,
        receipt.deletion_seq,
    );
    let expected_commitment =
        historical_certified_commitment(&receipt.post_state_hash, &expected_event);
    let expected_tombstone = historical_tombstone_hash(
        &receipt.canister_id,
        receipt.timestamp,
        receipt.deletion_seq,
    );

    let comparisons: [(&'static str, &str, [u8; 32], [u8; 32]); 4] = [
        (
            ERR_V1_HIST_RECEIPT_ID,
            "receipt_id",
            expected_id,
            receipt.receipt_id,
        ),
        (
            ERR_V1_HIST_EVENT_HASH,
            "deletion_event_hash",
            expected_event,
            receipt.deletion_event_hash,
        ),
        (
            ERR_V1_HIST_CERTIFIED_COMMITMENT,
            "certified_commitment",
            expected_commitment,
            receipt.certified_commitment,
        ),
        (
            ERR_V1_HIST_TOMBSTONE_HASH,
            "tombstone_hash",
            expected_tombstone,
            receipt.tombstone_hash,
        ),
    ];

    let mismatches: Vec<_> = comparisons
        .iter()
        .filter(|(_, _, expected, actual)| expected != actual)
        .collect();
    match mismatches.first() {
        None => CheckOutcome::pass(
            "receipt_id, deletion_event_hash, certified_commitment and tombstone_hash recomputed (historical constructions)",
        ),
        Some((named, ..)) => {
            let detail = mismatches
                .iter()
                .map(|(_, field, expected, actual)| {
                    format!("{field}: expected {} actual {}", hex::encode(expected), hex::encode(actual))
                })
                .collect::<Vec<_>>()
                .join("; ");
            CheckOutcome::fail(*named, Some(detail))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zombie_core::receipt::ProtocolVersion;

    /// Golden vector: identical inputs to zombie-core's historical
    /// `golden_deletion_event_hash_v2` (pre=[1;32], post=[2;32], module=[3;32],
    /// timestamp=1_000_000, nonce=1, canister=aaaaa-aa). manifest_hash is NOT in
    /// the preimage; any formula regression breaks the pinned values.
    fn golden_v2_receipt() -> DeletionReceiptV4 {
        let canister_id = Principal::from_text("aaaaa-aa").unwrap();
        let (timestamp, deletion_seq) = (1_000_000u64, 1u64);
        let (pre_state_hash, post_state_hash, module_hash) =
            ([0x01u8; 32], [0x02u8; 32], [0x03u8; 32]);
        let deletion_event_hash = deletion_event_hash_v1(
            &pre_state_hash,
            &post_state_hash,
            timestamp,
            &module_hash,
            deletion_seq,
        );
        DeletionReceiptV4 {
            protocol_version: ProtocolVersion::V2.into(),
            receipt_id: compute_receipt_id_v2(&canister_id, deletion_seq),
            canister_id,
            record_id: Vec::new(),
            pre_state_hash,
            post_state_hash,
            tombstone_hash: historical_tombstone_hash(&canister_id, timestamp, deletion_seq),
            deletion_event_hash,
            certified_commitment: historical_certified_commitment(
                &post_state_hash,
                &deletion_event_hash,
            ),
            module_hash,
            timestamp,
            deletion_seq,
            bls_certificate: None,
            trust_root_key_id: String::new(),
            module_hash_certificate: None,
        }
    }

    #[test]
    fn golden_v1_full_verification_v2() {
        let receipt = golden_v2_receipt();
        assert_eq!(
            hex::encode(receipt.deletion_event_hash),
            "9078d9a080606b46298bd9d66d3dd4a75389b04f7531b53a3a0e7c8f25955023",
            "v0.2.x deletion_event_hash changed — manifest_hash must NOT be in preimage"
        );
        assert_eq!(
            hex::encode(receipt.receipt_id),
            "1f213a0f2bf4992071a7f23e72d1942e564a4e871e3decce8ac8ee27d08f534b",
            "receipt_id derivation changed"
        );
        let outcome = verify(&AnyDeletionReceipt::V4(receipt));
        assert!(outcome.is_pass(), "{outcome:?}");
    }

    #[test]
    fn golden_v1_full_verification_v3() {
        let canister_id = Principal::from_text("aaaaa-aa").unwrap();
        let (timestamp, deletion_seq) = (1_000_000u64, 2u64);
        let (pre_state_hash, post_state_hash, module_hash) =
            ([0x11u8; 32], [0x22u8; 32], [0x33u8; 32]);
        let record_id = canister_id.as_slice().to_vec();
        let deletion_event_hash = deletion_event_hash_v1(
            &pre_state_hash,
            &post_state_hash,
            timestamp,
            &module_hash,
            deletion_seq,
        );
        let receipt = DeletionReceiptV4 {
            protocol_version: ProtocolVersion::V3.into(),
            receipt_id: compute_receipt_id(&canister_id, &record_id, deletion_seq),
            canister_id,
            record_id,
            pre_state_hash,
            post_state_hash,
            tombstone_hash: historical_tombstone_hash(&canister_id, timestamp, deletion_seq),
            deletion_event_hash,
            certified_commitment: historical_certified_commitment(
                &post_state_hash,
                &deletion_event_hash,
            ),
            module_hash,
            timestamp,
            deletion_seq,
            bls_certificate: None,
            trust_root_key_id: String::new(),
            module_hash_certificate: None,
        };
        assert!(verify(&AnyDeletionReceipt::V4(receipt)).is_pass());
    }

    #[test]
    fn historical_mismatches_are_named_in_order_and_all_listed() {
        let mut receipt = golden_v2_receipt();
        receipt.certified_commitment = [0xEE; 32];
        receipt.tombstone_hash = [0xCC; 32];
        match verify(&AnyDeletionReceipt::V4(receipt)) {
            CheckOutcome::Fail { error, detail } => {
                assert_eq!(error, ERR_V1_HIST_CERTIFIED_COMMITMENT);
                let detail = detail.unwrap();
                assert!(
                    detail.contains("certified_commitment") && detail.contains("tombstone_hash"),
                    "{detail}"
                );
            }
            other => panic!("expected FAIL, got {other:?}"),
        }

        let mut receipt = golden_v2_receipt();
        receipt.receipt_id = [0u8; 32];
        receipt.deletion_event_hash = [0u8; 32];
        assert_eq!(
            verify(&AnyDeletionReceipt::V4(receipt)).error(),
            Some(ERR_V1_HIST_RECEIPT_ID)
        );
    }
}
