//! V2 — Direct Certification from the receipt's embedded certificate.
//!
//! Offline only. The embedded `bls_certificate` is validated against the
//! explicit trust root (BLS signature, one-level NNS delegation, delegation
//! canister range; freshness-at-verification-time is intentionally skipped for
//! archived evidence), its `certified_data` for the receipt's canister is
//! extracted, and:
//!
//! - **mktd02-v5:** `zombie_core::check_certified_data_not_genesis`
//!   (`no-deletion-certified`), then `certified_data == deletion_event_hash`;
//! - **mktd02-v2 … v4:** `certified_data == certified_commitment`.
//!
//! No live query is made here; live corroboration is a diagnostic
//! (`crate::diagnostics`).

use candid::Principal;
use ic_agent::hash_tree::{LookupResult, SubtreeLookupResult};
use ic_agent::{lookup_value, Certificate};
use zombie_core::{check_certified_data_not_genesis, AnyDeletionReceipt};

use crate::report::{CheckOutcome, TimingFact};
use crate::trust_root::TrustRoot;

const IC_STATE_ROOT_DOMAIN_SEPARATOR: &[u8; 14] = b"\x0Dic-state-root";
const DER_PREFIX: &[u8; 37] = b"\x30\x81\x82\x30\x1d\x06\x0d\x2b\x06\x01\x04\x01\x82\xdc\x7c\x05\x03\x01\x02\x01\x06\x0c\x2b\x06\x01\x04\x01\x82\xdc\x7c\x05\x03\x02\x01\x03\x61\x00";
const BLS_RAW_KEY_LEN: usize = 96;
const V2_TIME_WARN_ENV: &str = "CVDR_V2_CERT_TIME_WARN_SECS";
const DEFAULT_V2_TIME_WARN_SECS: u64 = 300;

/// Named V2 failures (`no-deletion-certified` comes from zombie-core).
pub const ERR_V2_CERTIFICATE_PARSE: &str = "v2:certificate-parse";
pub const ERR_V2_CERTIFICATE_INVALID: &str = "v2:certificate-invalid";
pub const ERR_V2_CERTIFIED_DATA_ABSENT: &str = "v2:certified-data-absent";
pub const ERR_V2_CERTIFIED_DATA_MISMATCH: &str = "v2:certified-data-mismatch";

/// V2 outcome plus its timing sub-result.
#[derive(Debug, Clone, PartialEq)]
pub struct V2Evaluation {
    pub outcome: CheckOutcome,
    pub timing: Option<TimingFact>,
}

/// Run V2 on a decoded receipt against the explicit trust root.
pub fn verify(receipt: &AnyDeletionReceipt, trust_root: &TrustRoot) -> V2Evaluation {
    let (canister_id, bls_certificate, timestamp) = match receipt {
        AnyDeletionReceipt::V5(r) => (r.canister_id, &r.bls_certificate, r.timestamp),
        AnyDeletionReceipt::V4(r) => (r.canister_id, &r.bls_certificate, r.timestamp),
    };
    let Some(cert_bytes) = bls_certificate else {
        return V2Evaluation {
            outcome: CheckOutcome::not_evaluated("pending — Phase B certificate not yet embedded"),
            timing: None,
        };
    };

    let certificate: Certificate = match serde_cbor::from_slice(cert_bytes) {
        Ok(c) => c,
        Err(e) => {
            return V2Evaluation {
                outcome: CheckOutcome::fail(
                    ERR_V2_CERTIFICATE_PARSE,
                    Some(format!("embedded certificate CBOR: {e}")),
                ),
                timing: None,
            }
        }
    };
    let timing = Some(certificate_timing(&certificate, timestamp));
    let outcome = direct_certification(receipt, &certificate, canister_id, trust_root);
    V2Evaluation { outcome, timing }
}

fn direct_certification(
    receipt: &AnyDeletionReceipt,
    certificate: &Certificate,
    canister_id: Principal,
    trust_root: &TrustRoot,
) -> CheckOutcome {
    if let Err(e) =
        verify_archived_certificate_no_freshness(certificate, canister_id, trust_root.der())
    {
        return CheckOutcome::fail(ERR_V2_CERTIFICATE_INVALID, Some(e));
    }
    let certified_data = match certified_data_for_canister(certificate, canister_id) {
        Ok(d) => d,
        Err(e) => return CheckOutcome::fail(ERR_V2_CERTIFIED_DATA_ABSENT, Some(e)),
    };
    let (expected, field) = match receipt {
        AnyDeletionReceipt::V5(r) => {
            if let Err(named) = check_certified_data_not_genesis(&r.canister_id, &certified_data) {
                return CheckOutcome::fail(
                    named,
                    Some(format!("certified_data {}", hex::encode(certified_data))),
                );
            }
            (r.deletion_event_hash, "deletion_event_hash")
        }
        AnyDeletionReceipt::V4(r) => (r.certified_commitment, "certified_commitment"),
    };
    if certified_data != expected {
        return CheckOutcome::fail(
            ERR_V2_CERTIFIED_DATA_MISMATCH,
            Some(format!(
                "certificate certified_data {} != receipt {field} {}",
                hex::encode(certified_data),
                hex::encode(expected)
            )),
        );
    }
    CheckOutcome::pass(format!(
        "embedded certificate chains to trust root {} and the subnet-certified certified_data of canister {} equals the receipt's {field}",
        trust_root.id(),
        canister_id
    ))
}

/// `certified_data` at `/canister/<canister_id>/certified_data`, exactly 32 bytes.
/// Performs no signature validation; callers validate the certificate first.
pub fn certified_data_for_canister(
    certificate: &Certificate,
    canister_id: Principal,
) -> Result<[u8; 32], String> {
    let data = lookup_value(
        certificate,
        [
            b"canister".as_ref(),
            canister_id.as_slice(),
            b"certified_data".as_ref(),
        ],
    )
    .map_err(|e| format!("certified_data not found in certificate tree: {e:?}"))?;
    data.try_into()
        .map_err(|_| format!("certified_data is {} bytes, expected 32", data.len()))
}

// ---------------------------------------------------------------------------
// Archived-evidence certificate validation (shared with V3A and OpenChatZD)
// ---------------------------------------------------------------------------

fn verify_archived_certificate_no_freshness(
    cert: &Certificate,
    effective_canister_id: Principal,
    trust_root_der: &[u8],
) -> Result<(), String> {
    let signer_der = match &cert.delegation {
        None => trust_root_der.to_vec(),
        Some(delegation) => {
            let delegated_cert: Certificate =
                serde_cbor::from_slice(delegation.certificate.as_ref())
                    .map_err(|e| format!("Failed to parse delegation certificate CBOR: {}", e))?;

            if delegated_cert.delegation.is_some() {
                return Err(
                    "Delegation certificate contains nested delegation (unsupported)".to_string(),
                );
            }

            // Verify delegation certificate signature against trust root.
            verify_signature_with_der_key(&delegated_cert, trust_root_der)
                .map_err(|e| format!("Delegation certificate signature invalid: {}", e))?;

            // Enforce canister authorization. The IC may present the subnet's
            // canister ranges in EITHER tree layout; accept both, and in both
            // cases still require effective_canister_id to fall within a range
            // proven for the delegating subnet under the same delegation
            // signature (no weakening — see `authorize_canister_ranges`).
            authorize_canister_ranges(
                &delegated_cert,
                delegation.subnet_id.as_ref(),
                &effective_canister_id,
            )?;

            let public_key_path = [
                b"subnet".as_ref(),
                delegation.subnet_id.as_ref(),
                b"public_key".as_ref(),
            ];
            lookup_value(&delegated_cert, public_key_path)
                .map_err(|e| format!("Delegation certificate missing subnet public_key: {}", e))?
                .to_vec()
        }
    };

    verify_signature_with_der_key(cert, &signer_der)
}

fn verify_signature_with_der_key(cert: &Certificate, der_key: &[u8]) -> Result<(), String> {
    let key = extract_der_public_key(der_key)?;

    let root_hash = cert.tree.digest();
    let mut msg = Vec::with_capacity(IC_STATE_ROOT_DOMAIN_SEPARATOR.len() + root_hash.len());
    msg.extend_from_slice(IC_STATE_ROOT_DOMAIN_SEPARATOR);
    msg.extend_from_slice(&root_hash);

    ic_verify_bls_signature::verify_bls_signature(cert.signature.as_ref(), &msg, &key)
        .map_err(|_| "BLS signature check failed".to_string())
}

pub(crate) fn extract_der_public_key(der_key: &[u8]) -> Result<Vec<u8>, String> {
    let expected_len = DER_PREFIX.len() + BLS_RAW_KEY_LEN;
    if der_key.len() != expected_len {
        return Err(format!(
            "DER key length mismatch (expected {}, got {})",
            expected_len,
            der_key.len()
        ));
    }
    if &der_key[..DER_PREFIX.len()] != DER_PREFIX {
        return Err("DER key prefix mismatch".to_string());
    }
    Ok(der_key[DER_PREFIX.len()..].to_vec())
}

fn principal_is_within_ranges(principal: &Principal, ranges: &[(Principal, Principal)]) -> bool {
    ranges
        .iter()
        .any(|(low, high)| principal >= low && principal <= high)
}

/// Enforce that `effective_canister_id` falls within the canister ranges proven
/// for the delegating subnet, accepting EITHER tree layout the IC may present:
///
///   - **Legacy:**  `/subnet/<subnet_id>/canister_ranges` — a single CBOR
///     `Vec<(Principal, Principal)>` blob. This is the only layout the pinned
///     ic-agent 0.39 (and 0.40) `check_delegation` understands.
///   - **Sharded:** `/canister_ranges/<subnet_id>/<shard_key>` — one CBOR
///     `Vec<(Principal, Principal)>` blob per shard leaf. This is the newer IC
///     routing-table layout, not yet handled by the pinned ic-agent, resolved
///     here via the maintained `lookup_subtree`/`list_paths`/`lookup_path`
///     primitives (no hand-rolled tree-digest walking).
///
/// Authorization semantics are identical across layouts: authorize iff there is
/// **any authenticated ranges leaf under the target subnet whose signed range
/// contains the target canister**. A pruned shard carries no leaf and therefore
/// cannot authorize. The function rejects when (a) neither layout exists, (b) a
/// present leaf fails to CBOR-decode, (c) a present authenticated leaf is not an
/// exact three-level shard leaf (`/canister_ranges/<subnet_id>/<shard_key>` —
/// deeper descendant paths are rejected, never authorized), or (d) no signed
/// range contains the target. This widens *where* the proof is read, never
/// *whether* the canister must be proven in range.
fn authorize_canister_ranges(
    delegated_cert: &Certificate,
    subnet_id: &[u8],
    effective_canister_id: &Principal,
) -> Result<(), String> {
    // Legacy single-blob layout: /subnet/<subnet_id>/canister_ranges
    if let Ok(blob) = lookup_value(
        delegated_cert,
        [b"subnet".as_ref(), subnet_id, b"canister_ranges".as_ref()],
    ) {
        let ranges: Vec<(Principal, Principal)> = serde_cbor::from_slice(blob)
            .map_err(|e| format!("Invalid canister_ranges payload (legacy layout): {}", e))?;
        return if principal_is_within_ranges(effective_canister_id, &ranges) {
            Ok(())
        } else {
            Err("Certificate delegation is not authorized for this canister (legacy canister_ranges layout)".to_string())
        };
    }

    // New sharded layout: /canister_ranges/<subnet_id>/<shard_key> leaves.
    // Enumerate the authenticated (present, non-pruned) ranges leaves directly
    // under the target subnet and CBOR-decode EVERY present leaf. Authorize iff
    // some decoded signed range contains the target — but only after confirming
    // that NO present leaf failed to decode (G §2.4 (b)) and that every present
    // leaf is an exact three-level shard leaf (G §2.4 — no deeper descendant may
    // authorize). We deliberately do NOT return early on a match, so a later
    // malformed sibling cannot be skipped.
    if let SubtreeLookupResult::Found(subtree) = delegated_cert
        .tree
        .lookup_subtree([b"canister_ranges".as_ref(), subnet_id])
    {
        // `list_paths()` returns paths RELATIVE to the subtree root (the
        // <subnet_id> node — verified against ic-certification 3.1.0
        // `HashTreeNode::list_paths`, which seeds an empty prefix), so a direct
        // `<shard_key>` leaf has depth 1. If a real cert ever surfaced a
        // different convention, the live V1–V4 run regresses V2 to FAIL with the
        // "expected direct shard leaf" message below — the fix would be to set
        // this constant to the observed depth, never to drop the check.
        const SHARDED_LEAF_DEPTH: usize = 1;

        let mut present_shard = false;
        let mut authorized = false;
        for path in subtree.list_paths() {
            present_shard = true;
            // Fail closed: enforce exact three-level shard depth FIRST, then
            // require the path to resolve to a Found leaf — any non-Found result
            // (Absent / Unknown / Error) rejects rather than being silently
            // skipped (G ratified form).
            if path.len() != SHARDED_LEAF_DEPTH {
                return Err(format!(
                    "Invalid sharded canister_ranges layout: expected direct shard leaf at depth {} under /canister_ranges/<subnet_id>, found authenticated leaf at depth {}",
                    SHARDED_LEAF_DEPTH,
                    path.len()
                ));
            }
            let leaf = match subtree.lookup_path(&path) {
                LookupResult::Found(leaf) => leaf,
                other => {
                    return Err(format!(
                        "Sharded canister_ranges path enumerated by list_paths did not resolve to a Found leaf (lookup result: {:?})",
                        other
                    ));
                }
            };
            // Decode every present leaf; a failure here rejects regardless of
            // whether an earlier leaf already matched.
            let ranges: Vec<(Principal, Principal)> = serde_cbor::from_slice(leaf)
                .map_err(|e| format!("Invalid canister_ranges payload (sharded layout): {}", e))?;
            if principal_is_within_ranges(effective_canister_id, &ranges) {
                authorized = true;
            }
        }
        if present_shard {
            return if authorized {
                Ok(())
            } else {
                Err("Certificate delegation is not authorized for this canister (sharded canister_ranges layout)".to_string())
            };
        }
    }

    Err("Delegation certificate missing canister_ranges in both legacy (/subnet/<id>/canister_ranges) and sharded (/canister_ranges/<id>/<shard>) tree layouts".to_string())
}

/// V2 timing sub-result: certificate `/time` against the receipt timestamp.
/// Informational only (warning past `CVDR_V2_CERT_TIME_WARN_SECS`, default 300 s).
fn certificate_timing(cert: &Certificate, receipt_timestamp_ns: u64) -> TimingFact {
    match lookup_certificate_time_ns(cert) {
        Ok(cert_time_ns) => {
            let delta_ns = cert_time_ns as i128 - receipt_timestamp_ns as i128;
            let warn_secs = std::env::var(V2_TIME_WARN_ENV)
                .ok()
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(DEFAULT_V2_TIME_WARN_SECS);
            TimingFact::V2CertificateTime {
                certificate_time_ns: cert_time_ns,
                receipt_timestamp_ns,
                delta_secs: delta_ns as f64 / 1_000_000_000f64,
                warn_threshold_secs: warn_secs,
                exceeds_warning_threshold: delta_ns.unsigned_abs()
                    > warn_secs as u128 * 1_000_000_000u128,
            }
        }
        Err(e) => TimingFact::V2CertificateTimeUnavailable {
            detail: format!("could not decode certificate time field: {e}"),
        },
    }
}

fn lookup_certificate_time_ns(cert: &Certificate) -> Result<u64, String> {
    let encoded = lookup_value(cert, [b"time".as_ref()])
        .map_err(|e| format!("time path lookup failed: {}", e))?;
    decode_unsigned_leb128_u64(encoded)
}

fn decode_unsigned_leb128_u64(bytes: &[u8]) -> Result<u64, String> {
    let mut result: u64 = 0;
    let mut shift = 0u32;
    for (idx, byte) in bytes.iter().copied().enumerate() {
        let chunk = (byte & 0x7f) as u64;
        if shift >= 64 && chunk != 0 {
            return Err(format!("ULEB128 overflow at byte {}", idx));
        }
        result |= chunk << shift;
        if byte & 0x80 == 0 {
            return Ok(result);
        }
        shift = shift.saturating_add(7);
        if shift > 63 {
            return Err("ULEB128 too large for u64".to_string());
        }
    }
    Err("ULEB128 terminated unexpectedly".to_string())
}

// ---------------------------------------------------------------------------
// OpenChatZD frozen-package reuse (spec §6/§7): the committed BLS→NNS→delegation
// →canister-range path, run VERBATIM over `certified_data == tree_root` instead
// of the MKTd02 `certified_commitment`. Same archived-evidence semantics
// (signature authenticity, delegation trust, canister authorization; freshness
// intentionally skipped). Exposed pub so `openchatzd::` reuses it without
// forking the verification logic.
// ---------------------------------------------------------------------------

pub struct CertifiedDataOutcome {
    /// Certificate `/time` in nanoseconds (IC consensus time).
    pub certificate_time_ns: u64,
}

/// Verify an embedded IC certificate and require its `certified_data` for
/// `canister_id` to equal `expected_certified_data` (the OpenChatZD receipt-tree
/// root). Returns the certificate's `/time`. Errors map to §9 rejects at the call
/// site: signature/delegation/range failure → §9.4; certified_data mismatch →
/// §9.3 (the caller has already required witness_root == tree_root, §9.2).
pub fn verify_certificate_over_certified_data(
    cert_bytes: &[u8],
    canister_id: Principal,
    expected_certified_data: &[u8; 32],
    trust_root_der: &[u8],
) -> Result<CertifiedDataOutcome, String> {
    let certificate: Certificate = serde_cbor::from_slice(cert_bytes)
        .map_err(|e| format!("Failed to parse certificate CBOR: {}", e))?;

    // Committed archived-evidence path: BLS signature → NNS delegation → the
    // delegation's canister range must cover `canister_id` (§9.4).
    verify_archived_certificate_no_freshness(&certificate, canister_id, trust_root_der)?;

    // certified_data under /canister/<canister_id>/certified_data. Absence here
    // (e.g. the certificate does not speak for `canister_id` at all) is a §9.4
    // authorization failure surfaced as a lookup miss.
    let data = lookup_value(
        &certificate,
        [
            b"canister".as_ref(),
            canister_id.as_slice(),
            b"certified_data".as_ref(),
        ],
    )
    .map_err(|e| {
        format!(
            "certified_data not found for canister in certificate tree: {:?}",
            e
        )
    })?;
    if data.len() != 32 {
        return Err(format!(
            "certified_data is {} bytes, expected 32",
            data.len()
        ));
    }
    let actual: [u8; 32] = data.try_into().unwrap();
    if &actual != expected_certified_data {
        // §9.3: certificate certified_data != witness root (== tree_root).
        return Err(format!(
            "certified_data mismatch:\n  certificate:  {}\n  witness root: {}",
            hex::encode(actual),
            hex::encode(expected_certified_data)
        ));
    }

    let certificate_time_ns = lookup_certificate_time_ns(&certificate)?;
    Ok(CertifiedDataOutcome {
        certificate_time_ns,
    })
}

// ---------------------------------------------------------------------------
// V3A / OpenChatZD INDEX: archived certificate over /canister/<id>/module_hash
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct ModuleHashOutcome {
    /// Certificate `/time` in nanoseconds (IC consensus time).
    pub certificate_time_ns: u64,
    /// The subnet-certified module hash at /canister/<id>/module_hash.
    pub certified_module_hash: [u8; 32],
}

/// Verify an embedded IC certificate and extract the subnet-certified module
/// hash at **exactly** `/canister/<canister_id>/module_hash`. Same archived-
/// evidence machinery as [`verify_certificate_over_certified_data`] (BLS
/// signature → NNS delegation → the delegation's canister range must cover
/// `canister_id`), so both certificates in a V3A check validate against the
/// same trust root.
///
/// `lookup_value` is path-agnostic: the exact path is asserted here, so a
/// certificate over any other path (e.g. a certified_data-only certificate)
/// yields a lookup miss and errors — it can never be accepted as a module-hash
/// attestation. OpenChatZD INDEX evidence reuses this path; `h_index` compare
/// stays in the OpenChatZD verifier (folded under H_INDEX_TAG).
pub fn verify_certificate_over_module_hash(
    cert_bytes: &[u8],
    canister_id: Principal,
    trust_root_der: &[u8],
) -> Result<ModuleHashOutcome, String> {
    let certificate: Certificate = serde_cbor::from_slice(cert_bytes)
        .map_err(|e| format!("Failed to parse module-hash certificate CBOR: {}", e))?;

    verify_archived_certificate_no_freshness(&certificate, canister_id, trust_root_der)?;

    let data = lookup_value(
        &certificate,
        [
            b"canister".as_ref(),
            canister_id.as_slice(),
            b"module_hash".as_ref(),
        ],
    )
    .map_err(|e| {
        format!(
            "module_hash not found for canister in certificate tree: {:?}",
            e
        )
    })?;
    if data.len() != 32 {
        return Err(format!("module_hash is {} bytes, expected 32", data.len()));
    }
    let certified_module_hash: [u8; 32] = data.try_into().unwrap();

    let certificate_time_ns = lookup_certificate_time_ns(&certificate)?;
    Ok(ModuleHashOutcome {
        certificate_time_ns,
        certified_module_hash,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_agent::hash_tree::{fork, label, leaf, HashTree};

    const SUBNET_ID: &[u8] = &[0xfe, 0x32, 0x0f, 0x2f, 0xbb];
    // A different subnet — ranges signed under it must NOT authorize a lookup
    // performed against SUBNET_ID (the delegating subnet).
    const OTHER_SUBNET_ID: &[u8] = &[0xab, 0xcd, 0xef, 0x01, 0x23];
    // Range [00000000013000000101 .. 00000000013fffff0101] — the live shard.
    const RANGE_LOW: &[u8] = &[0, 0, 0, 0, 1, 0x30, 0, 0, 1, 1];
    const RANGE_HIGH: &[u8] = &[0, 0, 0, 0, 1, 0x3f, 0xff, 0xff, 1, 1];
    const IN_RANGE: &[u8] = &[0, 0, 0, 0, 1, 0x30, 0x90, 0x42, 1, 1]; // fg23v-... shard member
    const OUT_OF_RANGE: &[u8] = &[0, 0, 0, 0, 1, 0x40, 0, 0, 1, 1];

    fn ranges_cbor() -> Vec<u8> {
        let ranges: Vec<(Principal, Principal)> = vec![(
            Principal::from_slice(RANGE_LOW),
            Principal::from_slice(RANGE_HIGH),
        )];
        serde_cbor::to_vec(&ranges).unwrap()
    }

    fn cert_with_tree(tree: HashTree<Vec<u8>>) -> Certificate {
        Certificate {
            tree,
            signature: Vec::new(),
            delegation: None,
        }
    }

    /// Legacy layout: /subnet/<subnet_id>/canister_ranges -> single CBOR blob.
    fn legacy_cert() -> Certificate {
        cert_with_tree(label(
            "subnet",
            label(SUBNET_ID, label("canister_ranges", leaf(ranges_cbor()))),
        ))
    }

    /// Sharded layout: /canister_ranges/<subnet_id>/<shard_key> -> CBOR blob.
    fn sharded_cert() -> Certificate {
        cert_with_tree(label(
            "canister_ranges",
            label(SUBNET_ID, label(RANGE_LOW, leaf(ranges_cbor()))),
        ))
    }

    /// Sharded layout, but the shard leaf is not valid CBOR.
    fn sharded_cert_malformed_leaf() -> Certificate {
        cert_with_tree(label(
            "canister_ranges",
            label(SUBNET_ID, label(RANGE_LOW, leaf(vec![0xff, 0xff, 0xff]))),
        ))
    }

    /// Sharded layout whose ranges are signed under a DIFFERENT subnet than the
    /// one the delegation names — the lookup against SUBNET_ID must miss it.
    fn sharded_cert_wrong_subnet() -> Certificate {
        cert_with_tree(label(
            "canister_ranges",
            label(OTHER_SUBNET_ID, label(RANGE_LOW, leaf(ranges_cbor()))),
        ))
    }

    /// Sharded layout with TWO direct (depth-1) shard leaves: the first valid and
    /// containing the target, the second malformed CBOR. The fork children must
    /// be in sorted label order, so RANGE_LOW (valid) precedes RANGE_HIGH
    /// (malformed). Decode-all must reject for the malformed sibling rather than
    /// passing early on the first containing leaf.
    fn sharded_cert_valid_then_malformed() -> Certificate {
        cert_with_tree(label(
            "canister_ranges",
            label(
                SUBNET_ID,
                fork(
                    label(RANGE_LOW, leaf(ranges_cbor())),
                    label(RANGE_HIGH, leaf(vec![0xff, 0xff, 0xff])),
                ),
            ),
        ))
    }

    /// Sharded layout with a DEEPER descendant leaf at
    /// /canister_ranges/<subnet_id>/<shard_key>/extra (relative depth 2). The
    /// leaf is valid CBOR and contains the target, but the depth violation must
    /// reject before any authorization.
    fn sharded_cert_deeper_path() -> Certificate {
        cert_with_tree(label(
            "canister_ranges",
            label(
                SUBNET_ID,
                label(RANGE_LOW, label("extra", leaf(ranges_cbor()))),
            ),
        ))
    }

    #[test]
    fn legacy_layout_authorizes_in_range() {
        authorize_canister_ranges(&legacy_cert(), SUBNET_ID, &Principal::from_slice(IN_RANGE))
            .expect("in-range canister must be authorized via legacy layout");
    }

    #[test]
    fn sharded_layout_authorizes_in_range() {
        authorize_canister_ranges(&sharded_cert(), SUBNET_ID, &Principal::from_slice(IN_RANGE))
            .expect("in-range canister must be authorized via sharded layout");
    }

    #[test]
    fn sharded_layout_rejects_out_of_range() {
        let err = authorize_canister_ranges(
            &sharded_cert(),
            SUBNET_ID,
            &Principal::from_slice(OUT_OF_RANGE),
        )
        .unwrap_err();
        assert!(err.contains("not authorized"), "unexpected error: {err}");
    }

    #[test]
    fn legacy_layout_rejects_out_of_range() {
        let err = authorize_canister_ranges(
            &legacy_cert(),
            SUBNET_ID,
            &Principal::from_slice(OUT_OF_RANGE),
        )
        .unwrap_err();
        assert!(err.contains("not authorized"), "unexpected error: {err}");
    }

    #[test]
    fn rejects_when_ranges_absent_from_both_layouts() {
        let cert = cert_with_tree(label("time", leaf(vec![1, 2, 3])));
        let err = authorize_canister_ranges(&cert, SUBNET_ID, &Principal::from_slice(IN_RANGE))
            .unwrap_err();
        assert!(
            err.contains("missing canister_ranges in both"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn sharded_layout_rejects_malformed_cbor_leaf() {
        // A present (authenticated) shard leaf that fails to CBOR-decode must
        // reject, not silently skip — per G ruling §2.4 condition (b).
        let err = authorize_canister_ranges(
            &sharded_cert_malformed_leaf(),
            SUBNET_ID,
            &Principal::from_slice(IN_RANGE),
        )
        .unwrap_err();
        assert!(
            err.contains("Invalid canister_ranges payload (sharded layout)"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn rejects_when_ranges_signed_under_wrong_subnet() {
        // Ranges proven for OTHER_SUBNET_ID must not authorize a canister whose
        // delegation names SUBNET_ID — even though the canister is within those
        // ranges. The lookup is scoped to the delegating subnet's path.
        let err = authorize_canister_ranges(
            &sharded_cert_wrong_subnet(),
            SUBNET_ID,
            &Principal::from_slice(IN_RANGE),
        )
        .unwrap_err();
        assert!(
            err.contains("missing canister_ranges in both"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn sharded_layout_rejects_when_a_later_leaf_is_malformed() {
        // A valid containing leaf must NOT short-circuit past a later malformed
        // present leaf — decode-all rejects (CD Finding 1). The IN_RANGE target
        // lies within the first (valid) leaf, so an early-return implementation
        // would wrongly PASS; this must fail on the malformed sibling instead.
        let err = authorize_canister_ranges(
            &sharded_cert_valid_then_malformed(),
            SUBNET_ID,
            &Principal::from_slice(IN_RANGE),
        )
        .unwrap_err();
        assert!(
            err.contains("Invalid canister_ranges payload (sharded layout)"),
            "must reject for the malformed sibling's decode failure, got: {err}"
        );
    }

    #[test]
    fn sharded_layout_rejects_deeper_descendant_path() {
        // A leaf one level too deep (/.../<shard_key>/extra) must reject for the
        // depth violation specifically (CD Finding 2), even though its CBOR is
        // valid and contains the target.
        let err = authorize_canister_ranges(
            &sharded_cert_deeper_path(),
            SUBNET_ID,
            &Principal::from_slice(IN_RANGE),
        )
        .unwrap_err();
        assert!(
            err.contains("expected direct shard leaf"),
            "must reject for the depth violation, got: {err}"
        );
    }
}

/// The v5 V2 path over a REAL mainnet certificate. No real v5 receipt exists
/// yet, so the v4 reference CVDR's bls certificate is placed into v5-shaped
/// receipts. This exercises direct certification against `deletion_event_hash`;
/// it is not a v5 receipt and is not used as one.
#[cfg(test)]
mod v5_path_tests {
    use super::*;
    use zombie_core::{DeletionReceiptV4, DeletionReceiptV5};

    fn reference_v4() -> DeletionReceiptV4 {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/v4/v4_finalized_mainnet.json");
        match crate::intake::read_receipt_file(path.to_str().unwrap()).unwrap() {
            AnyDeletionReceipt::V4(r) => r,
            other => panic!("expected the v4 reference, got {other:?}"),
        }
    }

    /// A v5-shaped receipt carrying the v4 reference's real certificate, with
    /// `deletion_event_hash` set to `certified_data_value`.
    fn transplanted(certified_data_value: [u8; 32], with_certificate: bool) -> AnyDeletionReceipt {
        let r = reference_v4();
        AnyDeletionReceipt::V5(DeletionReceiptV5 {
            protocol_version: "mktd02-v5".into(),
            receipt_id: r.receipt_id,
            canister_id: r.canister_id,
            record_id: r.record_id,
            pre_state_hash: r.pre_state_hash,
            post_state_hash: r.post_state_hash,
            tombstone_hash: r.tombstone_hash,
            deletion_event_hash: certified_data_value,
            module_hash: r.module_hash,
            timestamp: r.timestamp,
            deletion_seq: r.deletion_seq,
            bls_certificate: if with_certificate {
                r.bls_certificate
            } else {
                None
            },
            trust_root_key_id: r.trust_root_key_id,
            module_hash_certificate: if with_certificate {
                r.module_hash_certificate
            } else {
                None
            },
        })
    }

    fn mainnet() -> TrustRoot {
        TrustRoot::built_in("mainnet").unwrap()
    }

    #[test]
    fn v5_direct_certification_binds_deletion_event_hash() {
        // The real certificate certifies the v4 receipt's certified_commitment.
        let certified = reference_v4().certified_commitment;
        let eval = verify(&transplanted(certified, true), &mainnet());
        match &eval.outcome {
            CheckOutcome::Pass { established } => {
                assert!(established.contains("deletion_event_hash"), "{established}")
            }
            other => panic!("expected PASS, got {other:?}"),
        }
        assert!(matches!(
            eval.timing,
            Some(TimingFact::V2CertificateTime { .. })
        ));
    }

    #[test]
    fn v5_certified_data_mismatch_is_named() {
        let eval = verify(&transplanted([0x11; 32], true), &mainnet());
        assert_eq!(eval.outcome.error(), Some(ERR_V2_CERTIFIED_DATA_MISMATCH));
    }

    #[test]
    fn v5_pending_is_not_evaluated() {
        let eval = verify(&transplanted([0x11; 32], false), &mainnet());
        assert!(matches!(eval.outcome, CheckOutcome::NotEvaluated { .. }));
        assert_eq!(eval.timing, None);
    }

    #[test]
    fn v5_synthetic_certificate_bytes_fail_parse_by_name() {
        let AnyDeletionReceipt::V5(mut r) = transplanted([0x11; 32], true) else {
            unreachable!()
        };
        r.bls_certificate = Some(vec![0xaa, 0xbb, 0xcc]);
        let eval = verify(&AnyDeletionReceipt::V5(r), &mainnet());
        assert_eq!(eval.outcome.error(), Some(ERR_V2_CERTIFICATE_PARSE));
    }

    /// The genesis check is the one V2 runs: zombie-core's named error for a
    /// certified_data equal to the canister's genesis value.
    #[test]
    fn v5_genesis_certified_data_is_refused_by_the_check_v2_runs() {
        let canister = reference_v4().canister_id;
        let genesis = zombie_core::genesis_certified_data(&canister);
        assert_eq!(
            check_certified_data_not_genesis(&canister, &genesis),
            Err(zombie_core::ERR_NO_DELETION_CERTIFIED)
        );
    }
}
