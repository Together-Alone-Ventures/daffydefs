//! The crate README documents the command that is actually built and the
//! MKTd02 result shape, and keeps its claims in the attested-identity register.

use std::path::Path;

fn readme() -> String {
    std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("README.md")).unwrap()
}

#[test]
fn documented_commands_use_the_built_binary_name() {
    let binary = Path::new(env!("CARGO_BIN_EXE_mktd02-verify"))
        .file_stem()
        .unwrap()
        .to_string_lossy()
        .into_owned();
    let text = readme();
    let mut in_code = false;
    let mut commands = 0;
    for line in text.lines() {
        if line.trim_start().starts_with("```") {
            in_code = !in_code;
            continue;
        }
        let mut tokens = line.split_whitespace();
        let (first, second) = (tokens.next(), tokens.next());
        // A command line: a program name followed directly by a flag.
        if let (true, Some(command), Some(flag)) = (in_code, first, second) {
            if !flag.starts_with("--") {
                continue;
            }
            assert_eq!(command, binary, "documented command: {line}");
            commands += 1;
        }
    }
    assert!(commands >= 3, "README documents commands");
}

#[test]
fn readme_documents_provisional_output_incomplete_and_the_claim_register() {
    let text = readme();
    for required in [
        "PROVISIONAL",
        "validity: PASS",
        "validity: INCOMPLETE",
        "validity: FAIL",
        "--trust-root mainnet",
        "--trust-root-pem",
        "--diagnostic-live-check",
        "attests the\n  identity of the deployed module at certification time",
    ] {
        assert!(text.contains(required), "README lacks {required:?}");
    }
    for retired in [
        "torn down by the named code",
        "code provenance confirmed",
        "cvdr-verify ",
    ] {
        assert!(!text.contains(retired), "README still says {retired:?}");
    }
    for internal in ["Slice ", "Gate 2", "Amendment 1"] {
        assert!(
            !text.contains(internal),
            "README uses internal name {internal:?}"
        );
    }
}
