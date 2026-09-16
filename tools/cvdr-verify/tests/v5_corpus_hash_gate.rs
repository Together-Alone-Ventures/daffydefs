//! The corpus loader's hash gate, exercised on its own (the vectors are driven
//! through the verifier by `tests/v5_corpus_acceptance.rs`): the loader reads the
//! countersigned bytes at the rev this crate pins and refuses anything else.

mod support;

use support::corpus::{check_sha256, load_signed_corpus, load_signed_corpus_at, V5_CORPUS_REV};

#[test]
fn manifest_at_the_v5_rev_is_countersigned_over_the_expected_corpus() {
    let corpus = load_signed_corpus();
    assert_eq!(corpus.rev, V5_CORPUS_REV);
    assert_eq!(corpus.manifest["status"], "countersigned");
    assert_eq!(corpus.manifest["protocol_version"], "mktd02-v5");
    // The spec's pin: countersignature over corpus commit 40ba6db.
    assert!(corpus.manifest["countersignature"]["corpus_commit_sha"]
        .as_str()
        .unwrap()
        .starts_with("40ba6db"));
}

#[test]
fn every_countersigned_file_is_hash_checked_and_every_manifest_id_has_a_file() {
    let corpus = load_signed_corpus();
    let ids = corpus.manifest_ids();
    assert_eq!(
        ids.len(),
        29,
        "12 positive + 13 negative/compatibility + 4 historical"
    );
    assert_eq!(
        corpus.files.len(),
        ids.len(),
        "one countersigned file per manifest id"
    );
    for id in &ids {
        let rel = match id.strip_prefix("v4h-") {
            Some(name) => format!("docs/test-vectors/v4-historical/{name}.json"),
            None => format!("docs/test-vectors/v5/{id}.json"),
        };
        let v = corpus.json(&rel);
        assert_eq!(&v["id"], id.as_str(), "{rel}");
    }
}

#[test]
fn hash_gate_refuses_a_tampered_copy() {
    let corpus = load_signed_corpus();
    let rel = "docs/test-vectors/v5/gv5-007.json";
    let signed = corpus.manifest["countersignature"]["vector_file_sha256"][rel]
        .as_str()
        .unwrap();
    let mut copy = corpus.files[rel].clone();
    assert_eq!(check_sha256(&copy, signed), Ok(()));
    let last = copy.len() - 2;
    copy[last] ^= 0x01;
    assert!(
        check_sha256(&copy, signed).is_err(),
        "a one-bit change must be refused"
    );
}

#[test]
fn a_rev_without_the_countersigned_corpus_is_refused() {
    // zombie-core 0.4.1 (27d508f, the v0.7.0 pin) predates the v5 corpus.
    let err = load_signed_corpus_at("27d508f0df9c6a1f86c11b2bf197e3f091cb858f")
        .err()
        .expect("zombie-core 0.4.1 carries no countersigned v5 corpus");
    assert!(err.contains("manifest"), "{err}");
    assert!(load_signed_corpus_at("0000000000000000000000000000000000000000").is_err());
}
