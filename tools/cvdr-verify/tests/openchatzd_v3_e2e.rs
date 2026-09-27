//! OpenChatZD PortablePackageV3 end to end through the real CLI, over the genuine PocketIC fixture
//! (`tests/fixtures/v5-openchatzd/pocketic-v3/`, see its PROVENANCE.md). Offline.
//!
//! Pins the step-5 rules: the trust-root selector is not evidence (no flag / no root => FAIL, the
//! verdict names the reason and announces a non-production root when one is used); V3A PASS needs an
//! authenticated certificate AND a matching displayed `index_module_hash`; unknown keys are malformed.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const DIR: &str = "tests/fixtures/v5-openchatzd/pocketic-v3";

fn crate_path(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(rel)
}

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_mktd02-verify"))
        .args(args)
        .output()
        .expect("binary runs")
}

fn text(o: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

fn package() -> String {
    crate_path(&format!("{DIR}/package.json"))
        .to_str()
        .unwrap()
        .to_string()
}

fn root_hex() -> String {
    std::fs::read_to_string(crate_path(&format!("{DIR}/root_key.hex")))
        .unwrap()
        .trim()
        .to_string()
}

fn write_variant(name: &str, mutate: impl FnOnce(&mut serde_json::Value)) -> String {
    let mut v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(package()).unwrap()).unwrap();
    mutate(&mut v);
    let path = std::env::temp_dir().join(format!("oczd_v3_{}_{name}.json", std::process::id()));
    std::fs::write(&path, serde_json::to_vec(&v).unwrap()).unwrap();
    path.to_str().unwrap().to_string()
}

#[test]
fn genuine_v3_package_passes_only_with_explicit_non_production_root() {
    let pkg = package();
    let root = root_hex();

    // No flag: the non-production selector cannot be honoured => FAIL, reason named.
    let refused = run(&["--package", &pkg]);
    assert_eq!(refused.status.code(), Some(1), "{}", text(&refused));
    let t = text(&refused);
    assert!(
        t.contains("validity: FAIL (trust-root:") && t.contains("--allow-fixture-root-key"),
        "{t}"
    );

    // Flag but no root material: still FAIL.
    let no_root = run(&["--package", &pkg, "--allow-fixture-root-key"]);
    assert_eq!(no_root.status.code(), Some(1));
    assert!(text(&no_root).contains("no non-production root to select"));

    // Flag + out-of-band root: PASS, V3A_PASS, non-production root announced.
    let ok = run(&[
        "--package",
        &pkg,
        "--allow-fixture-root-key",
        "--fixture-root-key-hex",
        &root,
    ]);
    let t = text(&ok);
    assert_eq!(ok.status.code(), Some(0), "{t}");
    assert!(t.contains("validity: PASS"), "{t}");
    assert!(t.contains("outcome : V3A_PASS"), "{t}");
    assert!(t.contains("PortablePackageV3 with RECEIPT_BODY_V2"), "{t}");
    assert!(
        t.contains("NON-PRODUCTION root") && t.contains("TEST VERDICT ONLY"),
        "{t}"
    );
    assert!(t.contains(
        "subnet-attested installed module identity during the finalization/certification window"
    ));

    // Root material without the flag is refused before anything is verified.
    let unflagged_root = run(&["--package", &pkg, "--fixture-root-key-hex", &root]);
    assert_ne!(unflagged_root.status.code(), Some(0));
    assert!(text(&unflagged_root).contains("requires --allow-fixture-root-key"));

    // CLI selector conflicting with the package selector: FAIL.
    let conflict = run(&[
        "--package",
        &pkg,
        "--allow-fixture-root-key",
        "--fixture-root-key-hex",
        &root,
        "--trust-root-key-id",
        "mainnet",
    ]);
    assert_eq!(conflict.status.code(), Some(1));
    assert!(text(&conflict).contains("selector conflict"));
}

#[test]
fn tampered_displayed_module_hash_fails_named_and_unknown_key_is_malformed() {
    let root = root_hex();
    let tampered = write_variant("tampered", |v| {
        v["index_code_identity_evidence"]["index_module_hash"] =
            serde_json::Value::String("00".repeat(32));
    });
    let out = run(&[
        "--package",
        &tampered,
        "--allow-fixture-root-key",
        "--fixture-root-key-hex",
        &root,
    ]);
    let t = text(&out);
    assert_eq!(out.status.code(), Some(1), "{t}");
    assert!(t.contains("outcome : INDEX_HASH_MISMATCH"), "{t}");
    assert!(t.contains("validity: FAIL"), "{t}");

    let extra = write_variant("extra", |v| {
        v["extra"] = serde_json::Value::from(1);
    });
    let out = run(&[
        "--package",
        &extra,
        "--allow-fixture-root-key",
        "--fixture-root-key-hex",
        &root,
    ]);
    assert_ne!(out.status.code(), Some(0));
    assert!(text(&out).contains("unknown key `extra`"));

    let bad_version = write_variant("v4", |v| {
        v["version"] = serde_json::Value::from(4);
    });
    let out = run(&[
        "--package",
        &bad_version,
        "--allow-fixture-root-key",
        "--fixture-root-key-hex",
        &root,
    ]);
    assert_ne!(out.status.code(), Some(0));
    assert!(text(&out).contains("must be exactly 3"));

    let bad_selector = write_variant("selector", |v| {
        v["trust_root_key_id"] = serde_json::Value::String("mainnet-ish".into());
    });
    let out = run(&[
        "--package",
        &bad_selector,
        "--allow-fixture-root-key",
        "--fixture-root-key-hex",
        &root,
    ]);
    assert_ne!(out.status.code(), Some(0));
    assert!(text(&out).contains("not a known trust-root selector"));
}

/// G (frozen): PENDING / PERMANENTLY_UNAVAILABLE are as-of-verification-time classifications. The
/// report must print the evaluation time and its source whenever it emits one, with the fixed
/// statement; the same package is PENDING at hour 3 and PERMANENTLY_UNAVAILABLE at hour 25, both
/// INCOMPLETE / exit 4; a PASS prints no such line. The README carries the same statement.
#[test]
fn absent_evidence_classification_prints_evaluation_time_and_as_of_note() {
    let root = root_hex();
    // FrozenWire-only variant of the genuine package (no evidence), with the fixture root inline.
    let v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(package()).unwrap()).unwrap();
    let mut frozen: serde_json::Value =
        serde_json::from_slice(&hex::decode(v["frozen"].as_str().unwrap()).unwrap()).unwrap();
    frozen["root_key_hex"] = serde_json::Value::String(root.clone());
    let body = hex::decode(frozen["receipt_body"].as_str().unwrap()).unwrap();
    // uninstall_completed_at sits after tag(26)+receipt_id(32)+nonce(32)+2 principals+record_id(32)+seq(8)+h_user_pre(32)
    let mut at = 26 + 64;
    at += 1 + body[at] as usize;
    at += 1 + body[at] as usize;
    at += 32 + 8 + 32;
    let uninstall = u64::from_be_bytes(body[at..at + 8].try_into().unwrap());
    let path = std::env::temp_dir().join(format!("oczd_frozen_only_{}.json", std::process::id()));
    std::fs::write(&path, serde_json::to_vec(&frozen).unwrap()).unwrap();
    let pkg = path.to_str().unwrap();
    let base = [
        "--package",
        pkg,
        "--allow-fixture-root-key",
        "--trust-root-key-id",
        "non-production-test-root",
    ];

    let hour3 = (uninstall + 3 * 3_600_000_000_000).to_string();
    let hour25 = (uninstall + 25 * 3_600_000_000_000).to_string();
    let pending = run(&[&base[..], &["--now-ns", &hour3]].concat());
    let gone = run(&[&base[..], &["--now-ns", &hour25]].concat());
    let (tp, tg) = (text(&pending), text(&gone));
    assert_eq!(pending.status.code(), Some(4), "{tp}");
    assert_eq!(gone.status.code(), Some(4), "{tg}");
    assert!(
        tp.contains("outcome : V3A_PENDING_IN_PROTECTED_WINDOW"),
        "{tp}"
    );
    assert!(tg.contains("outcome : V3A_PERMANENTLY_UNAVAILABLE"), "{tg}");
    for (t, now) in [(&tp, &hour3), (&tg, &hour25)] {
        assert!(t.contains("validity: INCOMPLETE"), "{t}");
        assert!(
            t.contains(&format!(
                "evaluated at          : {now} ns (source: --now-ns)"
            )),
            "{t}"
        );
        assert!(
            t.contains("as-of-verification-time classification, NOT a cryptographic verdict"),
            "{t}"
        );
        assert!(
            t.contains(
                "PENDING_IN_PROTECTED_WINDOW at hour 3 and V3A_PERMANENTLY_UNAVAILABLE at hour 25"
            ),
            "{t}"
        );
        assert!(t.contains("both are validity: INCOMPLETE (exit 4)"), "{t}");
    }
    // system clock: source named; the fixture's 2021 PocketIC time is long past => PERMANENTLY_UNAVAILABLE
    let sys = run(&base);
    let ts = text(&sys);
    assert_eq!(sys.status.code(), Some(4), "{ts}");
    assert!(ts.contains("(source: system clock)"), "{ts}");
    assert!(ts.contains("outcome : V3A_PERMANENTLY_UNAVAILABLE"), "{ts}");
    // a PASS prints no evaluation-time line
    let pass = run(&[
        "--package",
        &package(),
        "--allow-fixture-root-key",
        "--fixture-root-key-hex",
        &root,
    ]);
    let tpass = text(&pass);
    assert_eq!(pass.status.code(), Some(0), "{tpass}");
    assert!(
        !tpass.contains("evaluated at") && !tpass.contains("as-of-verification-time"),
        "{tpass}"
    );
    // README pins the same statement
    let readme = std::fs::read_to_string(crate_path("README.md")).unwrap();
    assert!(
        readme.contains("as-of-verification-time\nclassifications, not cryptographic verdicts")
            || readme
                .contains("as-of-verification-time classifications, not cryptographic verdicts")
    );
    assert!(readme.contains("PENDING at hour 3 and PERMANENTLY_UNAVAILABLE at hour 25"));
    assert!(readme.contains("(source: --now-ns | system clock)"));
}
