//! Live diagnostics. Every query here reads the canister as it is now, so none
//! of them enters validity; they are reported in a separate block.

use candid::{CandidType, Decode, Encode, Principal};
use ic_agent::{Agent, Certificate};
use serde::Deserialize;
use zombie_core::AnyDeletionReceipt;

use crate::report::DiagnosticFact;
use crate::v2_certificate::certified_data_for_canister;
use crate::v4_tombstone;

#[derive(Debug, CandidType, Deserialize)]
struct StateHashCertified {
    certificate: Option<serde_bytes::ByteBuf>,
    #[allow(dead_code)]
    hash: serde_bytes::ByteBuf,
}

/// Run every live diagnostic for the receipt's canister.
pub async fn run(agent: &Agent, receipt: &AnyDeletionReceipt) -> Vec<DiagnosticFact> {
    let (canister_id, module_hash, post_state_hash, certified_expected, field) = match receipt {
        AnyDeletionReceipt::V5(r) => (
            r.canister_id,
            r.module_hash,
            r.post_state_hash,
            r.deletion_event_hash,
            "deletion_event_hash",
        ),
        AnyDeletionReceipt::V4(r) => (
            r.canister_id,
            r.module_hash,
            r.post_state_hash,
            r.certified_commitment,
            "certified_commitment",
        ),
    };
    vec![
        live_certified_data(agent, canister_id, certified_expected, field).await,
        live_module_hash(agent, canister_id, module_hash).await,
        v4_tombstone::diagnose(agent, canister_id, post_state_hash).await,
    ]
}

/// The canister's current certified_data (certified query, agent-verified with
/// normal freshness) against the receipt's certified value.
async fn live_certified_data(
    agent: &Agent,
    canister_id: Principal,
    expected: [u8; 32],
    field: &str,
) -> DiagnosticFact {
    const NAME: &str = "live-certified-data";
    let fact = |status, detail: String| DiagnosticFact {
        name: NAME,
        status,
        detail,
    };
    let arg = match Encode!() {
        Ok(a) => a,
        Err(e) => return fact("unavailable", format!("failed to encode query args: {e}")),
    };
    let response = match agent
        .query(&canister_id, "mktd_get_state_hash")
        .with_arg(arg)
        .call()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            return fact(
                "unavailable",
                format!("query mktd_get_state_hash failed: {e}"),
            )
        }
    };
    let cert_bytes = match Decode!(&response, StateHashCertified) {
        Ok(StateHashCertified {
            certificate: Some(c),
            ..
        }) => c.into_vec(),
        Ok(_) => {
            return fact(
                "unavailable",
                "query response carries no certificate".to_string(),
            )
        }
        Err(e) => {
            return fact(
                "unavailable",
                format!("failed to decode state hash response: {e}"),
            )
        }
    };
    let certificate: Certificate = match serde_cbor::from_slice(&cert_bytes) {
        Ok(c) => c,
        Err(e) => {
            return fact(
                "unavailable",
                format!("failed to parse live certificate CBOR: {e}"),
            )
        }
    };
    if let Err(e) = agent.verify(&certificate, canister_id) {
        return fact(
            "inconsistent",
            format!("live certificate verification failed: {e}"),
        );
    }
    match certified_data_for_canister(&certificate, canister_id) {
        Err(e) => fact("unavailable", e),
        Ok(actual) if actual == expected => {
            fact("consistent", format!("current certified_data equals the receipt's {field}"))
        }
        Ok(actual) => fact(
            "informational",
            format!(
                "current certified_data {} differs from the receipt's {field} {} (canister state has moved on since the receipt)",
                hex::encode(actual),
                hex::encode(expected)
            ),
        ),
    }
}

/// The canister's current module hash against the receipt's.
async fn live_module_hash(
    agent: &Agent,
    canister_id: Principal,
    receipt_hash: [u8; 32],
) -> DiagnosticFact {
    const NAME: &str = "live-module-hash";
    let fact = |status, detail: String| DiagnosticFact {
        name: NAME,
        status,
        detail,
    };
    if receipt_hash == [0u8; 32] {
        return fact(
            "inconsistent",
            "receipt module_hash is all zeros (development build)".to_string(),
        );
    }
    let live = match agent
        .read_state_canister_info(canister_id, "module_hash")
        .await
    {
        Ok(bytes) => bytes,
        Err(e) => return fact("unavailable", format!("read_state module_hash failed: {e}")),
    };
    if live.as_slice() == receipt_hash.as_slice() {
        fact(
            "consistent",
            "current module hash equals the receipt's module_hash".to_string(),
        )
    } else {
        fact(
            "informational",
            format!(
                "current module hash {} differs from the receipt's {} (canister upgraded since deletion; the receipt is unaffected)",
                hex::encode(&live),
                hex::encode(receipt_hash)
            ),
        )
    }
}
