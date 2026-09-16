//! The DaffyDefs v4 reference CVDR keeps verifying on the historical line.

use mktd02_verify::intake::read_receipt_file;
use mktd02_verify::render::render_human;
use mktd02_verify::report::{ProtocolLine, Validity};
use mktd02_verify::trust_root::TrustRoot;
use mktd02_verify::verify::{verify_receipt, VerifyOptions};
use std::path::Path;
use zombie_core::ReceiptState;

const FIXTURE: &str = "tests/fixtures/v4/v4_finalized_mainnet.json";
/// Durable pin recorded in tests/fixtures/v4/PROVENANCE.md.
const FIXTURE_SHA256: &str = "fad7ef92aaefc18f44e1e78f78f80c9a9444b0240ff9696698a4eced5520cd4b";

fn fixture_path() -> String {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join(FIXTURE)
        .to_string_lossy()
        .into_owned()
}

#[test]
fn fixture_bytes_match_the_provenance_pin() {
    let bytes = std::fs::read(fixture_path()).unwrap();
    assert_eq!(hex::encode(zombie_core::sha256(&bytes)), FIXTURE_SHA256);
}

#[test]
fn v4_reference_verifies_as_historical_pass() {
    let receipt = read_receipt_file(&fixture_path()).expect("reference CVDR decodes");
    let options = VerifyOptions {
        trust_root: TrustRoot::built_in("mainnet").unwrap(),
        published_module_hash: None,
    };
    let facts = verify_receipt(&receipt, format!("file:{FIXTURE}"), &options);

    assert_eq!(facts.validity.validity, Validity::Pass, "{facts:#?}");
    assert_eq!(facts.protocol_line, Some(ProtocolLine::V4));
    assert_eq!(facts.historical, Some(true));
    assert_eq!(facts.receipt_state, Some(ReceiptState::FinalizedCandidate));
    assert!(facts.checks.v1.is_pass() && facts.checks.v2.is_pass() && facts.checks.v3a.is_pass());
    assert_eq!(facts.attestation_class, "subnet-attested");
    assert_eq!(facts.trust_root_mismatch, None);
    assert_eq!(facts.evidence_established.len(), 3);

    let text = render_human(&facts);
    assert!(text.contains("validity: PASS"));
    assert!(text.contains("protocol_line: mktd02-v4 (historical)"));
    for line in text.lines() {
        assert_ne!(line.trim(), "PASS", "bare PASS line");
    }
}
