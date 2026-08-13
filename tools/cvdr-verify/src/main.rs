mod fetch;
mod openchatzd;
mod v1_transition;
mod v2_certificate;
mod v3_module;
mod v4_tombstone;

use anyhow::Result;
use clap::Parser;
use ic_agent::Agent;
use candid::Principal;

const V4_NOT_EVALUATED: &str = "V4 — code provenance: NOT EVALUATED (see published verification procedure)";

#[derive(Parser)]
#[command(name = "mktd02-verify")]
#[command(version)]
#[command(about = "Automated V1–V3 verification for MKTd02 CVDRs; V4 (code provenance) established by the published verification procedure")]
struct Cli {
    /// Canister principal that holds the receipt (network-fetch mode)
    #[arg(long)]
    canister: Option<String>,

    /// Hex-encoded receipt ID (network-fetch mode)
    #[arg(long)]
    receipt_id: Option<String>,

    /// Local receipt JSON file (DaffyDefs export shape)
    #[arg(long)]
    receipt_file: Option<String>,

    /// IC network URL
    #[arg(long, default_value = "https://ic0.app")]
    network: String,

    /// Optional: published WASM hash (hex) for V3 three-way comparison
    #[arg(long)]
    wasm_hash: Option<String>,

    // --- OpenChatZD frozen-package mode (spec §2/§4/§5/§9) -------------------
    /// Verify an OpenChatZD frozen CVDR package (portable JSON). Switches into
    /// the offline package-verification path; mutually exclusive with the
    /// MKTd02 --canister/--receipt-id/--receipt-file inputs.
    #[arg(long)]
    package: Option<String>,

    /// Optional reveal package {version, salt, sorted target list} to re-derive
    /// TARGETS_COMMITMENT_V1 against the body (§2).
    #[arg(long)]
    reveal: Option<String>,

    /// Allowed finalization window in hours (spec §5; default 24).
    #[arg(long, default_value_t = openchatzd::DEFAULT_WINDOW_HOURS)]
    window_hours: u64,

    /// Trust-root key id for the certificate path (default: build active key).
    #[arg(long)]
    trust_root_key_id: Option<String>,

    /// TEST-ONLY: allow a frozen package's own `root_key_hex` to be used as the certificate trust
    /// anchor (e.g. a PocketIC end-to-end fixture, whose NNS root is not a built-in key). Off by
    /// default — a fixture must never silently supply its own trust anchor. Use is announced loudly.
    #[arg(long, default_value_t = false)]
    allow_fixture_root_key: bool,

    /// Expected executor module hash (64 hex chars). GATING and OFFLINE: the receipt's
    /// hash-bound `h_index` is recomputed from this hash and must match, else REJECT.
    #[arg(long)]
    expect_module_hash: Option<String>,

    /// Read the index canister's live module_hash via read_state (needs --network
    /// reachable). On its own this only DISPLAYS the live hash and verifies nothing.
    /// With --expect-module-hash it GATES: live hash must equal the expected one.
    #[arg(long, default_value_t = false)]
    corroborate_h_index: bool,
}

/// Decode a 32-byte hash from 64 hex chars, naming the flag in every error.
fn decode_hash32(flag: &str, hex_text: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(hex_text.trim())
        .map_err(|e| anyhow::anyhow!("{} must be valid hex: {}", flag, e))?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("{} must be 64 hex chars (32 bytes)", flag))
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let expect_module_hash_arg: Option<[u8; 32]> = match &cli.expect_module_hash {
        Some(h) => Some(decode_hash32("--expect-module-hash", h)?),
        None => None,
    };

    // OpenChatZD frozen-package mode: distinct offline path, mutually exclusive
    // with the MKTd02 receipt inputs.
    if let Some(package_path) = &cli.package {
        if cli.canister.is_some() || cli.receipt_id.is_some() || cli.receipt_file.is_some() {
            return Err(anyhow::anyhow!(
                "--package is mutually exclusive with --canister/--receipt-id/--receipt-file"
            ));
        }
        let agent = Agent::builder().with_url(&cli.network).build()?;
        if cli.corroborate_h_index
            && cli.network != "https://ic0.app"
            && cli.network != "https://icp0.io"
        {
            agent.fetch_root_key().await?;
        }
        let cfg = openchatzd::Config {
            package_path: package_path.clone(),
            reveal_path: cli.reveal.clone(),
            window_hours: cli.window_hours,
            trust_root_key_id: cli.trust_root_key_id.clone(),
            allow_fixture_root_key: cli.allow_fixture_root_key,
            corroborate_h_index: cli.corroborate_h_index,
            expect_module_hash: expect_module_hash_arg,
        };
        let code = openchatzd::run(&agent, cfg).await?;
        std::process::exit(code);
    }

    // Both flags are OpenChatZD-package-mode only. Erroring beats silently ignoring a
    // gating flag — a no-op --expect-module-hash would read as "the hash was checked".
    if expect_module_hash_arg.is_some() || cli.corroborate_h_index {
        return Err(anyhow::anyhow!(
            "--expect-module-hash / --corroborate-h-index apply only to --package mode"
        ));
    }

    let using_file_mode = cli.receipt_file.is_some();
    if using_file_mode {
        if cli.canister.is_some() || cli.receipt_id.is_some() {
            return Err(anyhow::anyhow!(
                "--receipt-file is mutually exclusive with --canister/--receipt-id"
            ));
        }
    } else if cli.canister.is_none() || cli.receipt_id.is_none() {
        return Err(anyhow::anyhow!(
            "network-fetch mode requires both --canister and --receipt-id"
        ));
    }

    let published_hash: Option<[u8; 32]> = match &cli.wasm_hash {
        Some(h) => Some(decode_hash32("--wasm-hash", h)?),
        None => None,
    };

    // Build agent
    let agent = Agent::builder()
        .with_url(&cli.network)
        .build()?;

    // Keep eager root-key fetch for network-fetch mode. In --receipt-file mode,
    // run receipt-contained checks first and let live-dependent checks fail explicitly.
    if cli.receipt_file.is_none() && cli.network != "https://ic0.app" && cli.network != "https://icp0.io" {
        agent.fetch_root_key().await?;
    }

    let (canister_id, receipt, receipt_id_display, source_display) = if let Some(path) = &cli.receipt_file {
        let receipt = fetch::load_receipt_from_file(path)?;
        let canister_id = receipt.canister_id;
        let receipt_id_display = hex::encode(receipt.receipt_id);
        (canister_id, receipt, receipt_id_display, format!("file:{}", path))
    } else {
        let canister_text = cli.canister.as_ref().expect("validated above");
        let receipt_id_text = cli.receipt_id.as_ref().expect("validated above");
        let canister_id = Principal::from_text(canister_text)
            .map_err(|e| anyhow::anyhow!("Invalid canister ID: {}", e))?;
        let receipt = fetch::fetch_receipt(&agent, canister_id, receipt_id_text).await?;
        (
            canister_id,
            receipt,
            receipt_id_text.clone(),
            "network-fetch".to_string(),
        )
    };

    println!("====================================================================================");
    println!(" CVDR-Verify: MKTd02 CVDR Verification — V1–V3 automated; V4 by published procedure");
    println!(" Canister : {}", canister_id);
    println!(" Receipt  : {}", receipt_id_display);
    println!(" Source   : {}", source_display);
    println!(" Network  : {}", cli.network);
    println!("====================================================================================");
    println!();

    println!("Receipt load...");
    println!("  protocol_version : {}", receipt.protocol_version);
    println!("  deletion_seq     : {}", receipt.deletion_seq);
    match receipt.protocol_version.as_str() {
        "mktd02-v2" => {
            println!("  receipt line     : v2 (legacy nonce semantics on-wire)");
        }
        "mktd02-v3" | "mktd02-v4" => {
            println!(
                "  record_id        : {} bytes ({})",
                receipt.record_id.len(),
                hex::encode(&receipt.record_id)
            );
            if receipt.protocol_version == "mktd02-v4" {
                println!(
                    "  module_hash_cert : {}",
                    match &receipt.module_hash_certificate {
                        Some(c) => format!("{} bytes (present)", c.len()),
                        None => "absent (pending / non-attested)".to_string(),
                    }
                );
            }
        }
        _ => {
            println!(
                "  record_id        : {} bytes ({})",
                receipt.record_id.len(),
                hex::encode(&receipt.record_id)
            );
            println!("  receipt line     : unknown protocol_version");
        }
    }
    println!("  Receipt loaded successfully.");
    println!();

    // Step 2: V1 — Hash recomputation
    println!("[1/3] V1: State transition verification...");
    let v1 = v1_transition::verify(&receipt, canister_id);
    println!("  {}", v1.summary());
    println!();

    // Step 3: V2 — Certificate path
    println!("[2/3] V2: Certificate verification path...");
    let v2 = v2_certificate::verify(&agent, canister_id, &receipt).await;
    println!("  {}", v2.summary());
    for note in &v2.notes {
        println!("    {}", note);
    }
    println!();

    println!("[3/3] V3 — attested code identity...");
    let v3a = v3_module::verify_v3a(&receipt);
    println!("  {}", v3a.summary());
    println!();

    println!("{V4_NOT_EVALUATED}");
    println!();

    println!("INFO — live module corroboration (non-gating)...");
    let v3 = v3_module::verify(&agent, canister_id, &receipt, published_hash).await;
    println!("  {}", v3.summary());
    println!();

    println!("INFO — tombstone persistence (diagnostic, non-gating)...");
    let v4 = v4_tombstone::verify(&agent, canister_id, &receipt).await;
    println!("  {}", v4.summary());
    println!();

    // Summary
    println!("====================================================================================");
    println!(" CVDR Verification Summary");
    println!("====================================================================================");
    println!(" {:<16} : {}", "V1 (hashes)",    v1.summary());
    println!(" {:<16} : {}", "V2 (cert path)", v2.summary());
    println!(" {:<16} : {}", "V3 (attested)", v3a.summary());
    println!(" {:<16} : {}", "V4 (provenance)",
        "NOT EVALUATED — established by the published verification procedure");
    println!(" {:<16} : {}", "INFO (live)", v3.summary());
    println!(" {:<16} : {}", "INFO (tombstone)", v4.summary());
    println!("====================================================================================");

    // Exit gate: V1, V2, and V3 attested code identity. V3 gates ONLY on a present-but-invalid
    // certificate (`Failed`) — a genuine integrity red flag; absent/pending/
    // deployer-declared and DELAY_EXCEEDED are non-attested/downgrade, not process
    // failures (pending export is permitted, labelled non-attested).
    std::process::exit(exit_code(v1.passed(), v2.passed(), v3a.passed()));
}

fn exit_code(v1: bool, v2: bool, v3: bool) -> i32 { if v1 && v2 && v3 { 0 } else { 1 } }

#[cfg(test)]
mod cli_output_tests {
    use super::{exit_code, V4_NOT_EVALUATED};
    use crate::v3_module::{V3Classification, V3Result};
    use crate::v4_tombstone::V4Result;

    #[test]
    fn tombstone_failure_is_informational_and_non_gating() {
        let result = V4Result { tombstone_ok: false, state_hash_ok: false, detail: "not tombstoned".into() };
        assert_eq!(exit_code(true, true, true), 0);
        assert!(result.summary().contains("INFO — tombstone persistence (diagnostic, non-gating): FAIL"));
    }

    #[test]
    fn live_mismatch_without_provenance_is_informational_and_non_gating() {
        let result = V3Result { classification: V3Classification::MismatchExpected };
        assert_eq!(exit_code(true, true, true), 0);
        assert!(result.summary().contains("INFO — live module corroboration (non-gating): MISMATCH-EXPECTED"));
    }

    #[test]
    fn v4_is_not_evaluated_and_has_no_verdict() {
        assert_eq!(V4_NOT_EVALUATED, "V4 — code provenance: NOT EVALUATED (see published verification procedure)");
        assert!(!V4_NOT_EVALUATED.contains("PASS") && !V4_NOT_EVALUATED.contains("FAIL"));
    }

    #[test]
    fn v1_v2_and_v3_failures_still_gate() {
        assert_eq!(exit_code(false, true, true), 1);
        assert_eq!(exit_code(true, false, true), 1);
        assert_eq!(exit_code(true, true, false), 1);
        assert_eq!(exit_code(true, true, true), 0);
    }
}
