//! serde_cbor (unmaintained, today's certificate parser) vs ciborium, on every
//! real IC certificate the verifier holds, delegation certificates included.
//!
//! Findings this test pins (evidence for the dependency ruling; serde_cbor is
//! NOT removed):
//! 1. **Data model:** both parsers read every real certificate to the same CBOR
//!    value tree (tags stripped: serde_cbor is built without its `tags`
//!    feature and skips them, ciborium keeps them).
//! 2. **Typed decode blocker:** ciborium cannot decode `ic_agent::Certificate`
//!    (ic-certification's types deserialize borrowed byte arrays, which
//!    ciborium's reader does not provide). A drop-in swap is not possible with
//!    ic-agent 0.39. If this assertion starts failing, the blocker is gone and
//!    the swap should be re-evaluated.
//! 3. serde_cbor also stays in the graph regardless: ic-agent 0.39.3 and
//!    ic-transport-types 0.39.3 depend on it directly.

use ic_agent::Certificate;
use serde_json::Value;
use std::path::Path;

fn crate_file(rel: &str) -> Vec<u8> {
    std::fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join(rel))
        .unwrap_or_else(|e| panic!("{rel}: {e}"))
}

fn json_hex(rel: &str, key: &str) -> Vec<u8> {
    let v: Value = serde_json::from_slice(&crate_file(rel)).unwrap();
    hex::decode(v[key].as_str().unwrap_or_else(|| panic!("{rel}: {key}"))).unwrap()
}

/// Every real certificate available offline, labelled.
fn real_certificates() -> Vec<(String, Vec<u8>)> {
    let reference = "tests/fixtures/v4/v4_finalized_mainnet.json";
    let module_hash = "tests/fixtures/v4/v4_module_hash_cert.json";
    let a1 = "fixtures/a1_mainnet_cvdr.json";
    vec![
        (
            format!("{reference}: bls_certificate"),
            json_hex(reference, "bls_certificate"),
        ),
        (
            format!("{reference}: module_hash_certificate"),
            json_hex(reference, "module_hash_certificate"),
        ),
        (
            module_hash.into(),
            json_hex(module_hash, "certificate_bytes"),
        ),
        (a1.into(), json_hex(a1, "certificate_bytes")),
        (
            "testdata/A1_certificate.bin".into(),
            crate_file("testdata/A1_certificate.bin"),
        ),
        (
            "testdata/mainnet_module_hash_certificate.bin".into(),
            crate_file("testdata/mainnet_module_hash_certificate.bin"),
        ),
    ]
}

/// A parser-neutral CBOR value: tags stripped, map entries in a canonical order.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum Cbor {
    Null,
    Bool(bool),
    Int(i128),
    FloatBits(u64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Cbor>),
    Map(Vec<(Cbor, Cbor)>),
}

fn from_serde_cbor(v: serde_cbor::Value) -> Cbor {
    use serde_cbor::Value as V;
    match v {
        V::Null => Cbor::Null,
        V::Bool(b) => Cbor::Bool(b),
        V::Integer(i) => Cbor::Int(i),
        V::Float(f) => Cbor::FloatBits(f.to_bits()),
        V::Bytes(b) => Cbor::Bytes(b),
        V::Text(t) => Cbor::Text(t),
        V::Array(a) => Cbor::Array(a.into_iter().map(from_serde_cbor).collect()),
        V::Map(m) => {
            let mut entries: Vec<_> = m
                .into_iter()
                .map(|(k, v)| (from_serde_cbor(k), from_serde_cbor(v)))
                .collect();
            entries.sort();
            Cbor::Map(entries)
        }
        V::Tag(_, inner) => from_serde_cbor(*inner),
        other => panic!("unexpected serde_cbor value {other:?}"),
    }
}

fn from_ciborium(v: ciborium::Value) -> Cbor {
    use ciborium::Value as V;
    match v {
        V::Null => Cbor::Null,
        V::Bool(b) => Cbor::Bool(b),
        V::Integer(i) => Cbor::Int(i.into()),
        V::Float(f) => Cbor::FloatBits(f.to_bits()),
        V::Bytes(b) => Cbor::Bytes(b),
        V::Text(t) => Cbor::Text(t),
        V::Array(a) => Cbor::Array(a.into_iter().map(from_ciborium).collect()),
        V::Map(m) => {
            let mut entries: Vec<_> = m
                .into_iter()
                .map(|(k, v)| (from_ciborium(k), from_ciborium(v)))
                .collect();
            entries.sort();
            Cbor::Map(entries)
        }
        V::Tag(_, inner) => from_ciborium(*inner),
        other => panic!("unexpected ciborium value {other:?}"),
    }
}

fn value_trees(label: &str, bytes: &[u8]) -> (Cbor, Cbor) {
    let a = serde_cbor::from_slice::<serde_cbor::Value>(bytes)
        .unwrap_or_else(|e| panic!("{label}: serde_cbor value: {e}"));
    let b = ciborium::from_reader::<ciborium::Value, _>(bytes)
        .unwrap_or_else(|e| panic!("{label}: ciborium value: {e}"));
    (from_serde_cbor(a), from_ciborium(b))
}

#[test]
fn both_parsers_read_real_certificates_to_the_same_value_tree() {
    let mut delegations = 0;
    for (label, bytes) in real_certificates() {
        let (a, b) = value_trees(&label, &bytes);
        assert_eq!(a, b, "{label}: CBOR value trees differ");

        // Today's typed decode (serde_cbor) succeeds; its delegation certificate
        // bytes are compared the same way.
        let cert: Certificate = serde_cbor::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("{label}: serde_cbor Certificate: {e}"));
        if let Some(delegation) = &cert.delegation {
            delegations += 1;
            let nested = delegation.certificate.as_ref();
            let (da, db) = value_trees(&format!("{label}: delegation"), nested);
            assert_eq!(da, db, "{label}: delegation value trees differ");
            serde_cbor::from_slice::<Certificate>(nested)
                .unwrap_or_else(|e| panic!("{label}: delegation serde_cbor Certificate: {e}"));
        }
    }
    assert!(
        delegations > 0,
        "at least one delegated certificate compared"
    );
}

#[test]
fn ciborium_cannot_decode_ic_agent_certificate_type() {
    for (label, bytes) in real_certificates() {
        let err = ciborium::from_reader::<Certificate, _>(bytes.as_slice())
            .expect_err("tripwire: ciborium now decodes ic_agent::Certificate; re-evaluate the serde_cbor swap")
            .to_string();
        assert!(err.contains("borrowed byte array"), "{label}: {err}");
    }
}

#[test]
fn both_parsers_refuse_non_certificate_bytes() {
    // Short synthetic placeholders like the corpus's "aabbcc"/"ddee", an empty
    // input, and a truncated real certificate.
    let mut truncated = real_certificates().remove(0).1;
    truncated.truncate(truncated.len() / 2);
    for bytes in [vec![0xaa, 0xbb, 0xcc], vec![0xdd, 0xee], vec![], truncated] {
        assert!(
            serde_cbor::from_slice::<Certificate>(&bytes).is_err(),
            "serde_cbor accepted {} bytes",
            bytes.len()
        );
        assert!(
            ciborium::from_reader::<ciborium::Value, _>(bytes.as_slice())
                .map(from_ciborium)
                .ok()
                .and_then(|v| match v {
                    Cbor::Map(_) => Some(()),
                    _ => None,
                })
                .is_none(),
            "ciborium read {} bytes as a CBOR map",
            bytes.len()
        );
    }
}
