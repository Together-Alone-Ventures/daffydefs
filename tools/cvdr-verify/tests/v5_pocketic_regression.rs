//! Real v5 V2 regression fixture, not a fully valid v5 CVDR or corpus vector.
//! V3A: FAIL — fixture (the captured module-hash certificate is dummy).

use base64::Engine;
use mktd02_verify::intake::read_receipt_file;
use mktd02_verify::report::{CheckOutcome, ProtocolLine, Validity};
use mktd02_verify::trust_root::TrustRoot;
use mktd02_verify::v2_certificate::{
    self, ERR_V2_CERTIFICATE_INVALID, ERR_V2_CERTIFIED_DATA_MISMATCH,
};
use mktd02_verify::v3_module::ERR_V3A_MODULE_HASH_CERTIFICATE;
use mktd02_verify::verify::{verify_receipt, VerifyOptions};
use std::path::{Path, PathBuf};
use std::process::Command;
use zombie_core::{AnyDeletionReceipt, ReceiptState};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/v5/pocketic-11-p17")
        .join(name)
}

fn receipt() -> AnyDeletionReceipt {
    read_receipt_file(fixture("receipt.cbor").to_str().unwrap()).unwrap()
}

fn root() -> TrustRoot {
    TrustRoot::from_pem_file(fixture("root.pem").to_str().unwrap()).unwrap()
}

#[test]
fn real_v5_v2_passes_and_dummy_module_certificate_alone_fails_v3a() {
    let receipt = receipt();
    assert_eq!(receipt.protocol_version(), "mktd02-v5");
    assert_eq!(receipt.state(), ReceiptState::FinalizedCandidate);
    let AnyDeletionReceipt::V5(r) = &receipt else {
        panic!("v5 intake")
    };
    assert_eq!(r.module_hash_certificate, Some(vec![0x4D; 8]));
    assert_eq!(r.trust_root_key_id, "mainnet");
    let root = root();
    assert_eq!(root.der(), std::fs::read(fixture("root.der")).unwrap());
    let facts = verify_receipt(
        &receipt,
        "PocketIC regression fixture".into(),
        &VerifyOptions {
            trust_root: root.clone(),
            published_module_hash: None,
        },
    );
    assert_eq!(facts.protocol_line, Some(ProtocolLine::V5));
    assert!(facts.checks.v1.is_pass(), "{facts:#?}");
    // Production V2 checks both signatures, delegation/range/path, non-genesis,
    // and certified_data == deletion_event_hash before producing this PASS.
    assert!(facts.checks.v2.is_pass(), "{facts:#?}");
    let cert: ic_agent::Certificate =
        serde_cbor::from_slice(r.bls_certificate.as_ref().unwrap()).unwrap();
    assert!(
        cert.delegation.is_some(),
        "exercise application-subnet delegation"
    );
    let certified = v2_certificate::certified_data_for_canister(&cert, r.canister_id).unwrap();
    assert_ne!(
        certified,
        zombie_core::genesis_certified_data(&r.canister_id)
    );
    assert_eq!(certified, r.deletion_event_hash);
    assert_eq!(
        facts.checks.v3a.error(),
        Some(ERR_V3A_MODULE_HASH_CERTIFICATE)
    );
    match &facts.checks.v3a {
        CheckOutcome::Fail {
            detail: Some(detail),
            ..
        } => assert!(
            detail.starts_with("Failed to parse module-hash certificate CBOR:"),
            "{detail}"
        ),
        other => panic!("V3A: FAIL — fixture: {other:?}"),
    }
    let mismatch = facts.trust_root_mismatch.unwrap();
    assert_eq!(mismatch.receipt_says, "mainnet");
    assert_eq!(mismatch.verification_used, root.id());
    assert_eq!(facts.validity.validity, Validity::Fail);
}

fn cli(pem: &Path) -> serde_json::Value {
    let out = Command::new(env!("CARGO_BIN_EXE_mktd02-verify"))
        .arg("--receipt-file")
        .arg(fixture("receipt.cbor"))
        .arg("--trust-root-pem")
        .arg(pem)
        .arg("--json")
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).unwrap()
}

#[test]
fn cli_captured_pem_passes_v2_with_mismatch_warning_and_overall_fail() {
    let facts = cli(&fixture("root.pem"));
    assert_eq!(facts["checks"]["v1"]["outcome"], "pass");
    assert_eq!(facts["checks"]["v2"]["outcome"], "pass");
    assert_eq!(
        facts["checks"]["v3a"]["error"],
        ERR_V3A_MODULE_HASH_CERTIFICATE
    );
    assert_eq!(facts["validity"]["validity"], "FAIL");
    assert_eq!(facts["trust_root_used"]["source"], "pem");
    assert_eq!(facts["trust_root_used"]["id"], root().id());
    assert_eq!(facts["trust_root_mismatch"]["receipt_says"], "mainnet");
    assert_eq!(
        facts["trust_root_mismatch"]["verification_used"],
        root().id()
    );
}

#[test]
fn different_valid_root_pem_fails_delegation_signature() {
    // The real mainnet key is valid, distinct from the captured PocketIC key.
    let der = zombie_core::nns_keys::MAINNET_KEY_DER;
    assert_ne!(der, root().der());
    let pem = format!(
        "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
        base64::engine::general_purpose::STANDARD.encode(der)
    );
    let path = std::env::temp_dir().join(format!(
        "slice4-pocketic-wrong-root-{}.pem",
        std::process::id()
    ));
    std::fs::write(&path, pem).unwrap();
    let facts = cli(&path);
    std::fs::remove_file(path).unwrap();
    assert_eq!(facts["checks"]["v1"]["outcome"], "pass");
    assert_eq!(facts["checks"]["v2"]["error"], ERR_V2_CERTIFICATE_INVALID);
    assert!(facts["checks"]["v2"]["detail"]
        .as_str()
        .unwrap()
        .contains("Delegation certificate signature invalid: BLS signature check failed"));
}

#[test]
fn mutated_certificate_signature_fails_crypto_without_breaking_cbor() {
    let AnyDeletionReceipt::V5(mut r) = receipt() else {
        unreachable!()
    };
    let mut cert: ic_agent::Certificate =
        serde_cbor::from_slice(r.bls_certificate.as_ref().unwrap()).unwrap();
    cert.signature[0] ^= 1;
    r.bls_certificate = Some(serde_cbor::to_vec(&cert).unwrap());
    let result = v2_certificate::verify(&AnyDeletionReceipt::V5(r), &root());
    assert_eq!(result.outcome.error(), Some(ERR_V2_CERTIFICATE_INVALID));
    assert!(
        matches!(result.outcome, CheckOutcome::Fail { detail: Some(ref d), .. } if d == "BLS signature check failed")
    );
}

#[test]
fn mutated_event_binding_fails_after_certificate_verification() {
    let AnyDeletionReceipt::V5(mut r) = receipt() else {
        unreachable!()
    };
    r.deletion_event_hash[0] ^= 1;
    let result = v2_certificate::verify(&AnyDeletionReceipt::V5(r), &root());
    assert_eq!(result.outcome.error(), Some(ERR_V2_CERTIFIED_DATA_MISMATCH));
}

#[test]
fn mutated_certified_leaf_fails_signature_even_when_event_matches() {
    let AnyDeletionReceipt::V5(mut r) = receipt() else {
        unreachable!()
    };
    let bytes = r.bls_certificate.as_mut().unwrap();
    let positions: Vec<_> = bytes
        .windows(32)
        .enumerate()
        .filter_map(|(i, b)| (b == r.deletion_event_hash).then_some(i))
        .collect();
    assert_eq!(positions.len(), 1, "unique certified event leaf");
    bytes[positions[0]] ^= 1;
    r.deletion_event_hash[0] ^= 1;
    let cert: ic_agent::Certificate = serde_cbor::from_slice(bytes).unwrap();
    assert_eq!(
        v2_certificate::certified_data_for_canister(&cert, r.canister_id).unwrap(),
        r.deletion_event_hash
    );
    let result = v2_certificate::verify(&AnyDeletionReceipt::V5(r), &root());
    assert_eq!(result.outcome.error(), Some(ERR_V2_CERTIFICATE_INVALID));
    assert!(
        matches!(result.outcome, CheckOutcome::Fail { detail: Some(ref d), .. } if d == "BLS signature check failed")
    );
}

#[test]
fn captured_set_and_cvdr_provenance_match_sha256_pins() {
    for (name, expected) in [
        (
            "PROVENANCE.md",
            "258ba50827f1363952000346fd5b2ab577439dc72365ae39388e9efc6c5e4b25",
        ),
        (
            "provenance.txt",
            "7dbb6b5f892b150f76e9ea50b8f29b4df70171adf0e3246d0b0a02f7d1cafe5c",
        ),
        (
            "receipt.cbor",
            "91dbce51e0401856721eaa46cb8fa46ad4ecc8d2d098de89b2560fd4f259f741",
        ),
        (
            "root.der",
            "e8a47c78b3a7075cc6f0e1e66f9f1b5ba3da8e470f07723eb8cd2b61c6e4bcf2",
        ),
        (
            "root.pem",
            "d7110b5b34a37dad591caf572f131ec89539e1898283462696913325964a2c26",
        ),
    ] {
        assert_eq!(
            hex::encode(zombie_core::sha256(&std::fs::read(fixture(name)).unwrap())),
            expected,
            "{name}"
        );
    }
}
