mod openchatzd;

// The OpenChatZD package path reuses the shared certificate machinery as
// `crate::v2_certificate`.
use mktd02_verify::v2_certificate;

use anyhow::Result;
use candid::Principal;
use clap::Parser;
use ic_agent::Agent;
use mktd02_verify::intake::{self, IntakeError};
use mktd02_verify::report::{VerificationFacts, EXIT_USAGE};
use mktd02_verify::trust_root::TrustRoot;
use mktd02_verify::verify::{verify_receipt, VerifyOptions};
use mktd02_verify::{diagnostics, render};

#[derive(Parser)]
#[command(name = "mktd02-verify")]
#[command(version)]
#[command(
    about = "Reference verifier for MKTd02 deletion receipts (V1, V2, V3A, V3B) and OpenChatZD packages"
)]
struct Cli {
    /// Canister principal that holds the receipt (network-fetch intake)
    #[arg(long)]
    canister: Option<String>,

    /// Hex-encoded receipt ID (network-fetch intake)
    #[arg(long)]
    receipt_id: Option<String>,

    /// Local receipt file: JSON (ratified wire; v2–v4 historical tolerance) or CBOR
    #[arg(long)]
    receipt_file: Option<String>,

    /// IC network URL
    #[arg(long, default_value = "https://ic0.app")]
    network: String,

    /// Optional build provenance: published WASM module hash (hex) compared by V3B
    #[arg(long)]
    wasm_hash: Option<String>,

    /// MKTd02: print the verification facts as JSON instead of the provisional human rendering
    #[arg(long, default_value_t = false)]
    json: bool,

    /// MKTd02 (required, or --trust-root-pem): built-in IC root key to verify certificates against
    #[arg(long, value_name = "BUILT_IN_ID", conflicts_with = "trust_root_pem")]
    trust_root: Option<String>,

    /// MKTd02 (required, or --trust-root): PEM file holding the IC root public key (e.g. PocketIC)
    #[arg(long, value_name = "FILE")]
    trust_root_pem: Option<String>,

    /// MKTd02: also run live queries against the canister; reported separately, never part of validity
    #[arg(long, default_value_t = false)]
    diagnostic_live_check: bool,

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

/// MKTd02 path: a usage error produces no verdict.
fn usage_error(message: impl std::fmt::Display) -> ! {
    eprintln!("error: {message}");
    std::process::exit(EXIT_USAGE);
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
        if cli.trust_root.is_some()
            || cli.trust_root_pem.is_some()
            || cli.diagnostic_live_check
            || cli.json
        {
            return Err(anyhow::anyhow!(
                "--trust-root / --trust-root-pem / --diagnostic-live-check / --json apply only to MKTd02 receipt mode"
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

    run_mktd02(cli, expect_module_hash_arg).await
}

async fn run_mktd02(cli: Cli, expect_module_hash_arg: Option<[u8; 32]>) -> ! {
    // Both flags are OpenChatZD-package-mode only. Erroring beats silently ignoring a
    // gating flag — a no-op --expect-module-hash would read as "the hash was checked".
    if expect_module_hash_arg.is_some() || cli.corroborate_h_index {
        usage_error("--expect-module-hash / --corroborate-h-index apply only to --package mode");
    }
    if cli.trust_root_key_id.is_some() {
        usage_error(
            "--trust-root-key-id applies only to --package mode; MKTd02 receipts use --trust-root or --trust-root-pem",
        );
    }
    // The trust root is always explicit: never taken from the receipt, never defaulted.
    let trust_root = match (&cli.trust_root, &cli.trust_root_pem) {
        (Some(id), None) => TrustRoot::built_in(id),
        (None, Some(path)) => TrustRoot::from_pem_file(path),
        _ => {
            usage_error("a trust root is required: --trust-root mainnet or --trust-root-pem <file>")
        }
    }
    .unwrap_or_else(|e| usage_error(e));
    if cli.receipt_file.is_some() {
        if cli.canister.is_some() || cli.receipt_id.is_some() {
            usage_error("--receipt-file is mutually exclusive with --canister/--receipt-id");
        }
    } else if cli.canister.is_none() || cli.receipt_id.is_none() {
        usage_error("network-fetch mode requires both --canister and --receipt-id");
    }
    let published_module_hash = cli
        .wasm_hash
        .as_deref()
        .map(|h| decode_hash32("--wasm-hash", h).unwrap_or_else(|e| usage_error(e)));

    let agent = Agent::builder()
        .with_url(&cli.network)
        .build()
        .unwrap_or_else(|e| usage_error(e));
    // Queries (receipt fetch, diagnostics) are checked by the agent against the
    // explicit PEM root when one is given; otherwise a non-mainnet network's root
    // key is fetched for them. Receipt verification always uses `trust_root`.
    if cli.trust_root_pem.is_some() {
        agent.set_root_key(trust_root.der().to_vec());
    } else if cli.network != "https://ic0.app" && cli.network != "https://icp0.io" {
        if let Err(e) = agent.fetch_root_key().await {
            eprintln!("note: could not fetch root key from {}: {e}", cli.network);
        }
    }

    let (source, intake_result) = if let Some(path) = &cli.receipt_file {
        (format!("file:{path}"), intake::read_receipt_file(path))
    } else {
        let canister_text = cli.canister.as_deref().expect("validated above");
        let receipt_id = cli.receipt_id.as_deref().expect("validated above");
        let canister_id = Principal::from_text(canister_text)
            .unwrap_or_else(|e| usage_error(format!("invalid canister ID: {e}")));
        (
            format!("network-fetch:{}", cli.network),
            intake::fetch_receipt(&agent, canister_id, receipt_id).await,
        )
    };

    let facts = match intake_result {
        Err(IntakeError::Unavailable(e)) => usage_error(e),
        Err(IntakeError::Rejected(e)) => VerificationFacts::intake_rejected(source, e),
        Ok(receipt) => {
            let options = VerifyOptions {
                trust_root,
                published_module_hash,
            };
            let mut facts = verify_receipt(&receipt, source, &options);
            if cli.diagnostic_live_check {
                facts.diagnostics = Some(diagnostics::run(&agent, &receipt).await);
            }
            facts
        }
    };

    if cli.json {
        println!("{}", render::render_json(&facts));
    } else {
        println!("{}", render::render_human(&facts));
    }
    std::process::exit(facts.validity.validity.exit_code());
}
