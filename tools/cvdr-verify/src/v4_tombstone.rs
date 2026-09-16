//! Diagnostic: live tombstone persistence. Point-in-time only; never part of
//! validity.

use anyhow::Result;
use candid::{CandidType, Decode, Encode, Principal};
use ic_agent::Agent;
use serde::Deserialize;

use crate::report::DiagnosticFact;

#[derive(Debug, CandidType, Deserialize)]
pub struct TombstoneStatus {
    pub is_tombstoned: bool,
    pub tombstoned_at: Option<u64>,
}

#[derive(Debug, CandidType, Deserialize)]
pub struct StateHashResponse {
    pub certificate: Option<serde_bytes::ByteBuf>,
    pub hash: serde_bytes::ByteBuf,
}

const NAME: &str = "live-tombstone-persistence";

pub async fn diagnose(
    agent: &Agent,
    canister_id: Principal,
    post_state_hash: [u8; 32],
) -> DiagnosticFact {
    let fact = |status, detail: String| DiagnosticFact {
        name: NAME,
        status,
        detail,
    };
    let tombstone = match query_tombstone_status(agent, canister_id).await {
        Ok(t) => t,
        Err(e) => return fact("unavailable", format!("tombstone status query failed: {e}")),
    };
    if !tombstone.is_tombstoned {
        return fact(
            "inconsistent",
            "canister reports it is not tombstoned".to_string(),
        );
    }
    match query_state_hash(agent, canister_id).await {
        Err(e) => fact("unavailable", format!("state hash query failed: {e}")),
        Ok(current) if current == post_state_hash => fact(
            "consistent",
            "tombstone intact; current state hash equals receipt post_state_hash".to_string(),
        ),
        Ok(current) => fact(
            "inconsistent",
            format!(
                "state hash diverged (possible resurrection): receipt {} current {}",
                hex::encode(post_state_hash),
                hex::encode(current)
            ),
        ),
    }
}

async fn query_tombstone_status(agent: &Agent, canister_id: Principal) -> Result<TombstoneStatus> {
    let response = agent
        .query(&canister_id, "mktd_get_tombstone_status")
        .with_arg(Encode!()?)
        .call()
        .await
        .map_err(|e| anyhow::anyhow!("query mktd_get_tombstone_status failed: {}", e))?;
    Decode!(&response, TombstoneStatus)
        .map_err(|e| anyhow::anyhow!("failed to decode tombstone status: {}", e))
}

async fn query_state_hash(agent: &Agent, canister_id: Principal) -> Result<[u8; 32]> {
    let response = agent
        .query(&canister_id, "mktd_get_state_hash")
        .with_arg(Encode!()?)
        .call()
        .await
        .map_err(|e| anyhow::anyhow!("query mktd_get_state_hash failed: {}", e))?;

    let bytes: Vec<u8> = if let Ok(resp) = Decode!(&response, StateHashResponse) {
        resp.hash.into_vec()
    } else if let Ok(blob) = Decode!(&response, serde_bytes::ByteBuf) {
        blob.into_vec()
    } else if let Ok(text) = Decode!(&response, String) {
        hex::decode(&text).map_err(|e| anyhow::anyhow!("state hash hex decode failed: {}", e))?
    } else {
        return Err(anyhow::anyhow!("could not decode state hash response"));
    };
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("state hash is not 32 bytes"))
}
