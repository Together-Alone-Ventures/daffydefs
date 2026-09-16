//! Fetch a mainnet `read_state` certificate for `/canister/<id>/module_hash`.
//!
//! ```text
//! cargo run -p mktd02-verify --example fetch_module_hash_cert -- \
//!   nq4qv-wqaaa-aaaaf-bhdgq-cai /tmp/mh_cert.bin
//! ```

use candid::Principal;
use serde::Serialize;
use std::env;
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Serialize)]
#[serde(tag = "request_type", rename_all = "snake_case")]
enum EnvelopeContent {
    ReadState {
        ingress_expiry: u64,
        sender: Principal,
        paths: Vec<Vec<serde_bytes::ByteBuf>>,
    },
}

#[derive(Serialize)]
struct Envelope {
    content: EnvelopeContent,
}

#[derive(serde::Deserialize)]
struct ReadStateResponse {
    #[serde(with = "serde_bytes")]
    certificate: Vec<u8>,
}

fn encode_anonymous_module_hash_read_state(canister_id: Principal, ingress_expiry: u64) -> Vec<u8> {
    let path_module = vec![
        serde_bytes::ByteBuf::from(b"canister".as_slice()),
        serde_bytes::ByteBuf::from(canister_id.as_slice()),
        serde_bytes::ByteBuf::from(b"module_hash".as_slice()),
    ];
    let path_time = vec![serde_bytes::ByteBuf::from(b"time".as_slice())];
    let envelope = Envelope {
        content: EnvelopeContent::ReadState {
            ingress_expiry,
            sender: Principal::anonymous(),
            paths: vec![path_module, path_time],
        },
    };
    let mut serializer = serde_cbor::Serializer::new(Vec::new());
    serializer.self_describe().expect("self-describe");
    envelope.serialize(&mut serializer).expect("serialize");
    serializer.into_inner()
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut args = env::args().skip(1);
    let canister_text = args
        .next()
        .unwrap_or_else(|| "nq4qv-wqaaa-aaaaf-bhdgq-cai".to_string());
    let out_path = args
        .next()
        .unwrap_or_else(|| "module_hash_certificate.bin".to_string());
    let canister = Principal::from_text(&canister_text)?;
    let now_ns = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos() as u64;
    let ingress_expiry = now_ns.saturating_add(5 * 60 * 1_000_000_000);
    let body = encode_anonymous_module_hash_read_state(canister, ingress_expiry);
    let url = format!("https://icp-api.io/api/v2/canister/{canister}/read_state");
    let client = reqwest::Client::new();
    let resp = client
        .post(&url)
        .header("Content-Type", "application/cbor")
        .body(body)
        .send()
        .await?;
    let status = resp.status();
    let bytes = resp.bytes().await?;
    if !status.is_success() {
        anyhow::bail!("HTTP {status}: {}", String::from_utf8_lossy(&bytes));
    }
    let parsed: ReadStateResponse = serde_cbor::from_slice(&bytes)?;
    if parsed.certificate.is_empty() {
        anyhow::bail!("empty certificate in response");
    }
    fs::write(&out_path, &parsed.certificate)?;
    println!(
        "wrote {} bytes to {out_path} (canister {canister_text})",
        parsed.certificate.len()
    );
    println!(
        "sha256={}",
        hex::encode(zombie_core::hashing::sha256(&parsed.certificate))
    );
    Ok(())
}
