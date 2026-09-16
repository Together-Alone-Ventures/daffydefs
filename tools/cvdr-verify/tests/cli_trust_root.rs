//! CLI: the trust root is explicit, the receipt's key id is only compared, and
//! live checks run only when asked for. Offline: no test here reaches a network.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const V4_REFERENCE: &str = "tests/fixtures/v4/v4_finalized_mainnet.json";

fn crate_path(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(rel)
}

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_mktd02-verify"))
        .args(args)
        .output()
        .expect("binary runs")
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn mainnet_pem_file(name: &str) -> PathBuf {
    use base64::Engine;
    let b64 =
        base64::engine::general_purpose::STANDARD.encode(zombie_core::nns_keys::MAINNET_KEY_DER);
    let path = std::env::temp_dir().join(format!("cvdr_verify_{}_{name}.pem", std::process::id()));
    std::fs::write(
        &path,
        format!("-----BEGIN PUBLIC KEY-----\n{b64}\n-----END PUBLIC KEY-----\n"),
    )
    .unwrap();
    path
}

#[test]
fn missing_trust_root_is_a_usage_error() {
    let fixture = crate_path(V4_REFERENCE);
    let out = run(&["--receipt-file", fixture.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("a trust root is required"));
    assert!(stdout(&out).is_empty(), "no verdict on a usage error");
}

#[test]
fn built_in_mainnet_is_recorded_and_diagnostics_are_off_by_default() {
    let fixture = crate_path(V4_REFERENCE);
    let out = run(&[
        "--receipt-file",
        fixture.to_str().unwrap(),
        "--trust-root",
        "mainnet",
    ]);
    let text = stdout(&out);
    assert_eq!(out.status.code(), Some(0), "{text}");
    assert!(text.contains("validity: PASS"));
    assert!(text.contains("protocol_line: mktd02-v4 (historical)"));
    assert!(text.contains("trust_root: mainnet (built-in)"));
    assert!(text.contains("trust_root_mismatch: none"));
    assert!(text.contains("diagnostics: not requested"));
}

#[test]
fn pem_root_is_used_and_receipt_key_id_mismatch_is_a_warning_not_a_fail() {
    let fixture = crate_path(V4_REFERENCE);
    let pem = mainnet_pem_file("mismatch");
    let out = run(&[
        "--receipt-file",
        fixture.to_str().unwrap(),
        "--trust-root-pem",
        pem.to_str().unwrap(),
        "--json",
    ]);
    std::fs::remove_file(&pem).ok();
    let facts: serde_json::Value = serde_json::from_slice(&out.stdout).expect("JSON facts");
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(facts["validity"]["validity"], "PASS");
    assert_eq!(facts["trust_root_used"]["source"], "pem");
    let used = facts["trust_root_used"]["id"].as_str().unwrap();
    assert!(used.starts_with("pem:"), "{used}");
    assert_eq!(facts["trust_root_mismatch"]["receipt_says"], "mainnet");
    assert_eq!(facts["trust_root_mismatch"]["verification_used"], used);
    assert!(facts["diagnostics"].is_null());
}

#[test]
fn a_wrong_explicit_root_fails_v2_and_v3a_by_name() {
    // A structurally valid PEM whose key is not the mainnet root.
    use base64::Engine;
    let mut der = zombie_core::nns_keys::MAINNET_KEY_DER.to_vec();
    let last = der.len() - 1;
    der[last] ^= 0x01;
    let path = std::env::temp_dir().join(format!("cvdr_verify_{}_wrong.pem", std::process::id()));
    std::fs::write(
        &path,
        format!(
            "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
            base64::engine::general_purpose::STANDARD.encode(&der)
        ),
    )
    .unwrap();
    let fixture = crate_path(V4_REFERENCE);
    let out = run(&[
        "--receipt-file",
        fixture.to_str().unwrap(),
        "--trust-root-pem",
        path.to_str().unwrap(),
        "--json",
    ]);
    std::fs::remove_file(&path).ok();
    let facts: serde_json::Value = serde_json::from_slice(&out.stdout).expect("JSON facts");
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(facts["validity"]["validity"], "FAIL");
    assert_eq!(facts["checks"]["v2"]["error"], "v2:certificate-invalid");
    assert_eq!(facts["checks"]["v3a"]["error"], "v3a:bls-certificate");
}

#[test]
fn flags_are_scoped_to_their_mode() {
    let fixture = crate_path(V4_REFERENCE);
    let f = fixture.to_str().unwrap();
    let both = run(&[
        "--receipt-file",
        f,
        "--trust-root",
        "mainnet",
        "--trust-root-pem",
        "x.pem",
    ]);
    assert_eq!(
        both.status.code(),
        Some(2),
        "clap conflict is a usage error"
    );

    let key_id = run(&[
        "--receipt-file",
        f,
        "--trust-root",
        "mainnet",
        "--trust-root-key-id",
        "mainnet",
    ]);
    assert_eq!(key_id.status.code(), Some(2));

    let unknown = run(&["--receipt-file", f, "--trust-root", "test-key"]);
    assert_eq!(unknown.status.code(), Some(2));

    let package = run(&["--package", "p.json", "--trust-root", "mainnet"]);
    assert_ne!(package.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&package.stderr).contains("apply only to MKTd02 receipt mode"));
}
