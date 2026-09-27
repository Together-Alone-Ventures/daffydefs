//! OpenChatZD package verification (offline, end-to-end) — suite v5 (Brief B1 step 5).
//!
//! Inputs: a `PortablePackageV3` (live), or — historical decoders only — a `PortablePackageV2`
//! or a bare FrozenWire. The package **version and the body tag are dispatched together**: a
//! V3 package must carry `RECEIPT_BODY_V2`, a V2 package `RECEIPT_BODY_V1`; a bare FrozenWire
//! takes either body; any other pairing is structurally malformed (validity FAIL).
//!
//! Checks and grade (suite vocabulary — `validity: PASS | INCOMPLETE | FAIL`):
//! - **V1** — exact version/tag dispatch; body parse; `receipt_id` recomputed from the displayed
//!   fields (R-5); leaf == `receipt_hash`; optional RevealWire: `targets_commitment` and (v2) the
//!   non-identifying `record_id` (R-1) recomputed.
//! - **V2** — certificate BLS→NNS→delegation→range under the SELECTED trust root, `certified_data`
//!   == witness root, witness leaf == `receipt_hash`, `certificate_time` == cert `/time`.
//! - **V3A** — [`index_attestation`]: exactly PASS / PENDING-IN-PROTECTED-WINDOW /
//!   PERMANENTLY-UNAVAILABLE, or a named failure.
//! - `validity: PASS` = V1 ∧ V2 ∧ V3A PASS; `INCOMPLETE` = V1 ∧ V2 pass and V3A pending or
//!   permanently unavailable (never a pass, never a fail — reason names which); `FAIL` otherwise.
//! - The finalization-window tier and the timing axis are reported, NON-GATING. Live reads
//!   (`--corroborate-h-index`) are diagnostics and never touch validity.
//!
//! `trust_root_key_id` is a SELECTOR of a verifier-configured root, never evidence (G rule 1).

pub mod body;
pub mod index_attestation;
pub mod package;
pub mod witness;

#[cfg(test)]
mod fixtures;

use anyhow::Result;
use candid::Principal;
use ic_agent::Agent;
use zombie_core::hashing::sha256_concat;
use zombie_core::nns_keys;

use crate::v2_certificate::verify_certificate_over_certified_data;
use body::{BodyVersion, ReceiptBody};
use index_attestation::{TrustRootUsed, V3aOutcome, V3aResult};
use mktd02_verify::report::{EXIT_FAIL, EXIT_INCOMPLETE, EXIT_PASS};
use package::{
    PackageInput, RevealPackage, PORTABLE_VERSION_V2, PORTABLE_VERSION_V3, TRUST_ROOT_MAINNET,
    TRUST_ROOT_NON_PRODUCTION,
};

/// Default finalization window (§5): 24h. Reported, non-gating.
pub const DEFAULT_WINDOW_HOURS: u64 = 24;
const NS_PER_HOUR: u64 = 3_600_000_000_000;

/// b"OPENCHATZD_RECORD_ID_USER_V2" — the non-identifying record_id tag (R-1).
pub const RECORD_ID_TAG_V2: &[u8] = b"OPENCHATZD_RECORD_ID_USER_V2";

/// `record_id_v2 = SHA256(RECORD_ID_TAG_V2 ‖ record_salt ‖ canonical UserId principal bytes)`.
/// In OpenChatZD the UserId principal is the user canister principal carried in the body.
pub fn record_id_v2(record_salt: &[u8; 32], user_principal: Principal) -> [u8; 32] {
    sha256_concat(&[RECORD_ID_TAG_V2, record_salt, user_principal.as_slice()])
}

/// Named validity reasons (suite style).
pub const REASON_V3A_PENDING: &str = "v3a-pending-in-protected-window";
pub const REASON_V3A_PERMANENTLY_UNAVAILABLE: &str = "v3a-permanently-unavailable";

/// CLI-supplied configuration for an OpenChatZD package verification.
pub struct Config {
    pub package_path: String,
    /// Out-of-band non-production root (DER) for the `non-production-test-root` selector; only
    /// honoured with `allow_fixture_root_key`. Takes precedence over a FrozenWire `root_key_hex`.
    pub fixture_root_key_der: Option<Vec<u8>>,
    pub reveal_path: Option<String>,
    /// Finalization window in hours (reported, non-gating).
    pub window_hours: u64,
    /// Trust-root selector for FrozenWire/V2 inputs (default: the build's active key). For a V3
    /// package the PACKAGE selector governs; a differing CLI value is a conflict (FAIL).
    pub trust_root_key_id: Option<String>,
    /// TEST-ONLY opt-in: honour the `non-production-test-root` selector (and a FrozenWire
    /// `root_key_hex`) as the trust anchor. Announced loudly; the verdict says so.
    pub allow_fixture_root_key: bool,
    /// Live `module_hash` read — DIAGNOSTIC ONLY, never part of validity.
    pub corroborate_h_index: bool,
    /// Operator expectation for the Index module hash (64 hex). GATING when supplied: must equal
    /// the V3A-certified module hash (V2 body) or reproduce `h_index` (historical V1 body).
    pub expect_module_hash: Option<[u8; 32]>,
    /// Verifier clock (ns) used only to split V3A pending from permanently unavailable.
    /// `None` = system time.
    pub now_ns: Option<u64>,
}

/// Where the verifier clock came from — printed whenever it decided the V3A classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NowSource {
    /// `--now-ns` on the command line (test/audit).
    CliNowNs,
    /// The verifier host's system clock.
    SystemClock,
}

impl NowSource {
    pub fn label(self) -> &'static str {
        match self {
            NowSource::CliNowNs => "--now-ns",
            NowSource::SystemClock => "system clock",
        }
    }
}

/// Printed with every PENDING / PERMANENTLY_UNAVAILABLE classification (G, frozen wording).
pub const AS_OF_NOTE: &str = "as-of-verification-time classification, NOT a cryptographic verdict: the same package \
can be V3A_PENDING_IN_PROTECTED_WINDOW at hour 3 and V3A_PERMANENTLY_UNAVAILABLE at hour 25; both are \
validity: INCOMPLETE (exit 4)";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Validity {
    Pass,
    Incomplete,
    Fail,
}

impl Validity {
    pub fn label(self) -> &'static str {
        match self {
            Validity::Pass => "PASS",
            Validity::Incomplete => "INCOMPLETE",
            Validity::Fail => "FAIL",
        }
    }
    pub fn exit_code(self) -> i32 {
        match self {
            Validity::Pass => EXIT_PASS,
            Validity::Incomplete => EXIT_INCOMPLETE,
            Validity::Fail => EXIT_FAIL,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Check {
    Pass(String),
    Fail(String),
    /// Not evaluated because a prerequisite failed (still forces FAIL).
    Skipped(String),
    /// Informational only — never affects validity.
    Info(String),
}

impl Check {
    fn is_fail(&self) -> bool {
        matches!(self, Check::Fail(_) | Check::Skipped(_))
    }
    fn glyph(&self) -> &'static str {
        match self {
            Check::Pass(_) => "PASS",
            Check::Fail(_) => "FAIL",
            Check::Skipped(_) => "SKIP",
            Check::Info(_) => "----",
        }
    }
    fn text(&self) -> &str {
        match self {
            Check::Pass(s) | Check::Fail(s) | Check::Skipped(s) | Check::Info(s) => s,
        }
    }
}

/// Full structured report; `render()` prints it and `validity` drives the exit code.
pub struct Report {
    pub validity: Validity,
    /// Named reason for INCOMPLETE / FAIL.
    pub reason: Option<String>,
    /// Verifier clock used to classify absent evidence (ns) and where it came from.
    pub evaluated_at: (u64, NowSource),
    body: Option<ReceiptBody>,
    package_version: Option<u64>,
    /// Gate B: SHA-256 of the exact nested FrozenWire bytes (portable packages).
    frozen_exact_sha256: Option<[u8; 32]>,
    pub(crate) checks: Vec<(&'static str, Check)>,
    window_note: Option<String>,
    corroboration: Option<Check>,
    pub v3a: Option<V3aResult>,
}

impl Report {
    fn push(&mut self, rule: &'static str, c: Check) {
        self.checks.push((rule, c));
    }

    pub fn render(&self) {
        println!("============================================================");
        println!(" CVDR-Verify: OpenChatZD package (suite v5 — V1 / V2 / V3A)");
        println!("============================================================");
        println!(
            " Package: {}",
            match self.package_version {
                Some(3) => "PortablePackageV3 (live)".to_string(),
                Some(v) => format!("PortablePackageV{v} (HISTORICAL)"),
                None => "FrozenWire only (no index evidence)".to_string(),
            }
        );
        if let Some(h) = &self.frozen_exact_sha256 {
            println!(" Gate B nested FrozenWire bytes sha256: {}", hex::encode(h));
        }
        if let Some(b) = &self.body {
            println!(" Parsed {}:", b.version.label());
            println!("   receipt_id            : {}", hex::encode(b.receipt_id));
            println!("   nonce                 : {}", hex::encode(b.nonce));
            println!("   index_canister_id     : {}", b.index_canister_id);
            println!("   user_canister_id      : {}", b.user_canister_id);
            println!("   record_id             : {} (non-identifying; recomputable only with RevealWire record_salt)", hex::encode(b.record_id));
            println!("   deletion_seq          : {}", b.deletion_seq);
            println!("   h_user_pre            : {} (Index-recorded observation; integrity-bound, not independently attested)", hex::encode(b.h_user_pre));
            if let (Some(h), Some(c)) = (b.h_index, b.commitment) {
                println!("   h_index (historical)  : {}", hex::encode(h));
                println!("   commitment (historical): {}", hex::encode(c));
            }
            println!(
                "   uninstall_completed_at: {} ns",
                b.uninstall_completed_at_ns
            );
            println!(
                "   receipt_committed_at  : {} ns",
                b.receipt_committed_at_ns
            );
            println!("   targets_count         : {}", b.targets_count);
            println!(
                "   targets_commitment    : {}",
                hex::encode(b.targets_commitment)
            );
            println!();
        }
        println!(" Checks:");
        for (rule, c) in &self.checks {
            println!("   [{}] {:<34} {}", c.glyph(), rule, c.text());
        }
        if let Some(w) = &self.window_note {
            println!();
            println!(" Finalization window (non-gating): {}", w);
        }
        if let Some(idx) = &self.v3a {
            println!();
            println!(" V3A — subnet-attested Index code identity:");
            println!("   outcome : {}", idx.label());
            println!("   timing  : {} (non-gating)", idx.timing);
            println!("   detail  : {}", idx.detail);
            if let Some(mh) = &idx.certified_module_hash_hex {
                println!("   certified module_hash : {}", mh);
            }
            if let Some(t) = idx.index_cert_time_ns {
                println!("   INDEX cert /time      : {} ns", t);
            }
            if matches!(
                idx.outcome,
                Ok(V3aOutcome::PendingInProtectedWindow) | Ok(V3aOutcome::PermanentlyUnavailable)
            ) {
                println!(
                    "   evaluated at          : {} ns (source: {})",
                    self.evaluated_at.0,
                    self.evaluated_at.1.label()
                );
                println!("   note    : {}", AS_OF_NOTE);
            }
            if let Some(tr) = &idx.trust_root {
                println!(
                    "   trust root            : selector '{}' -> {} root ({} bytes DER){}",
                    tr.selector,
                    if tr.non_production {
                        "NON-PRODUCTION"
                    } else {
                        "mainnet"
                    },
                    tr.der_len,
                    if tr.non_production {
                        "  ** TEST VERDICT ONLY **"
                    } else {
                        ""
                    }
                );
            }
            println!("   claim   : {}", index_attestation::OCZD_SUPPORTED_CLAIM);
        }
        if let Some(c) = &self.corroboration {
            println!();
            println!(" Live module_hash (DIAGNOSTIC — never part of validity):");
            println!("   [{}] {}", c.glyph(), c.text());
        }
        println!();
        println!("============================================================");
        match &self.reason {
            Some(r) => println!(" validity: {} ({})", self.validity.label(), r),
            None => println!(" validity: {}", self.validity.label()),
        }
        println!("============================================================");
    }
}

/// Result of the certificate stage (V2): `Ok` = the certificate's `/time`; `Err` = reject reason.
pub type CertVerdict = std::result::Result<u64, String>;

/// The V2 certificate stage as an injectable closure — tests drive the pipeline with a
/// controllable stage while the REAL BLS path is exercised against the mainnet fixtures.
pub trait CertVerifier {
    fn verify(&self, cert_bytes: &[u8], canister_id: Principal, expected: &[u8; 32])
        -> CertVerdict;
}

impl<F> CertVerifier for F
where
    F: Fn(&[u8], Principal, &[u8; 32]) -> CertVerdict,
{
    fn verify(
        &self,
        cert_bytes: &[u8],
        canister_id: Principal,
        expected: &[u8; 32],
    ) -> CertVerdict {
        self(cert_bytes, canister_id, expected)
    }
}

/// Production V2 verifier over an explicit trust-root DER (already SELECTED — see [`select_trust_root`]).
pub struct NnsCertVerifier {
    pub trust_root_der: Vec<u8>,
}

impl CertVerifier for NnsCertVerifier {
    fn verify(
        &self,
        cert_bytes: &[u8],
        canister_id: Principal,
        expected: &[u8; 32],
    ) -> CertVerdict {
        verify_certificate_over_certified_data(
            cert_bytes,
            canister_id,
            expected,
            &self.trust_root_der,
        )
        .map(|o| o.certificate_time_ns)
    }
}

/// The selected trust root for this verification, or the reason none could be selected.
#[derive(Debug, Clone)]
pub struct SelectedTrustRoot {
    pub der: Vec<u8>,
    pub used: TrustRootUsed,
}

/// Resolve the trust root from the SELECTOR (G rule 1): the package's `trust_root_key_id` for a V3
/// package (a differing `--trust-root-key-id` is a conflict), else the CLI/default id.
/// - `mainnet` → the built-in NNS mainnet root.
/// - `non-production-test-root` → ONLY with `allow_fixture_root_key` AND a fixture root in the
///   FrozenWire (`root_key_hex`); announced as non-production.
/// - anything else → unknown selector, fail closed.
pub fn select_trust_root(
    package_selector: Option<&str>,
    cli_selector: Option<&str>,
    allow_fixture_root_key: bool,
    fixture_root_der: Option<&[u8]>,
) -> std::result::Result<SelectedTrustRoot, String> {
    let selector = match (package_selector, cli_selector) {
        (Some(p), Some(c)) if p != c => {
            return Err(format!(
                "trust-root selector conflict: package carries '{p}' but --trust-root-key-id '{c}' was given"
            ))
        }
        (Some(p), _) => p.to_string(),
        (None, Some(c)) => c.to_string(),
        (None, None) => nns_keys::active_key_id().to_string(),
    };
    if selector == TRUST_ROOT_NON_PRODUCTION {
        if !allow_fixture_root_key {
            return Err(format!(
                "selector '{TRUST_ROOT_NON_PRODUCTION}' selects a fixture root, which requires the explicit \
                 --allow-fixture-root-key flag (refused: a non-production root is never used silently)"
            ));
        }
        let Some(der) = fixture_root_der else {
            return Err(format!(
                "selector '{TRUST_ROOT_NON_PRODUCTION}' with --allow-fixture-root-key, but the package carries no \
                 fixture root (`root_key_hex`) — no non-production root to select"
            ));
        };
        eprintln!(
            "WARNING --allow-fixture-root-key: selector '{TRUST_ROOT_NON_PRODUCTION}' -> FIXTURE-SUPPLIED trust \
             anchor ({} bytes). TEST VERDICT ONLY; never use for a real verdict.",
            der.len()
        );
        return Ok(SelectedTrustRoot {
            der: der.to_vec(),
            used: TrustRootUsed {
                selector,
                non_production: true,
                der_len: der.len(),
            },
        });
    }
    let key = nns_keys::lookup_key(selector.trim()).ok_or_else(|| {
        let known: Vec<&str> = nns_keys::MAINNET_KEYS.iter().map(|k| k.id).collect();
        format!(
            "unknown trust-root selector '{}' (known: {}, '{}') — fail closed",
            selector,
            known.join(", "),
            TRUST_ROOT_NON_PRODUCTION
        )
    })?;
    let non_production = selector != TRUST_ROOT_MAINNET;
    Ok(SelectedTrustRoot {
        der: key.der_bytes.to_vec(),
        used: TrustRootUsed {
            selector,
            non_production,
            der_len: key.der_bytes.len(),
        },
    })
}

/// Package-version ↔ body-tag consistency (G rule 3). `None` = consistent.
pub fn version_tag_mismatch(package_version: Option<u64>, body: BodyVersion) -> Option<String> {
    match (package_version, body) {
        (Some(PORTABLE_VERSION_V3), BodyVersion::V2) | (Some(PORTABLE_VERSION_V2), BodyVersion::V1) | (None, _) => None,
        (Some(v), b) => Some(format!(
            "PortablePackageV{v} carries {} — a V3 package must carry RECEIPT_BODY_V2 and a (historical) V2 package RECEIPT_BODY_V1; structurally malformed",
            b.label()
        )),
    }
}

fn now_ns_default() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

/// Compute the offline validity for a decoded package (pure; no network).
pub fn verify_offline(
    input: &PackageInput,
    reveal: Option<&RevealPackage>,
    window_hours: u64,
    expect_module_hash: Option<[u8; 32]>,
    trust: &SelectedTrustRoot,
    now_ns: u64,
    now_source: NowSource,
) -> Report {
    verify_offline_with(
        input,
        reveal,
        window_hours,
        expect_module_hash,
        &NnsCertVerifier {
            trust_root_der: trust.der.clone(),
        },
        Some((trust.der.as_slice(), trust.used.clone())),
        now_ns,
        now_source,
    )
}

/// Core verifier with an injectable V2 certificate stage (see [`CertVerifier`]). `v3a_trust` is
/// the selected root handed to V3A (`None` = the selector could not be honoured).
#[allow(clippy::too_many_arguments)]
pub fn verify_offline_with(
    input: &PackageInput,
    reveal: Option<&RevealPackage>,
    window_hours: u64,
    expect_module_hash: Option<[u8; 32]>,
    cert_verifier: &dyn CertVerifier,
    v3a_trust: Option<(&[u8], TrustRootUsed)>,
    now_ns: u64,
    now_source: NowSource,
) -> Report {
    let pkg = input.frozen();
    let mut report = Report {
        validity: Validity::Fail,
        reason: None,
        evaluated_at: (now_ns, now_source),
        body: None,
        package_version: input.portable_version(),
        frozen_exact_sha256: input.frozen_exact_sha256(),
        checks: Vec::new(),
        window_note: None,
        corroboration: None,
        v3a: None,
    };
    let fail_now = |mut report: Report, reason: &str| {
        report.validity = Validity::Fail;
        report.reason = Some(reason.to_string());
        report
    };

    // --- V1: exact dispatch — body tag, then package-version ↔ body-tag pairing -----------
    let parsed = match ReceiptBody::parse(&pkg.receipt_body) {
        Ok(b) => b,
        Err(e) => {
            report.push("V1 body: tag dispatch + parse", Check::Fail(e.to_string()));
            return fail_now(report, "v1:body-malformed");
        }
    };
    if let Some(why) = version_tag_mismatch(input.portable_version(), parsed.version) {
        report.push("V1 package version ↔ body tag", Check::Fail(why));
        report.body = Some(parsed);
        return fail_now(report, "v1:version-tag-mismatch");
    }
    report.push(
        "V1 package version ↔ body tag",
        Check::Pass(format!(
            "{} with {}",
            match input.portable_version() {
                Some(v) => format!("PortablePackageV{v}"),
                None => "FrozenWire".to_string(),
            },
            parsed.version.label()
        )),
    );
    report.push(
        "V1 body: tag dispatch + parse",
        Check::Pass(format!(
            "{} bytes, {} all fields decoded",
            pkg.receipt_body.len(),
            parsed.version.label()
        )),
    );

    // --- V1: receipt_id recomputed from the displayed fields (R-5) --------------------------
    let recomputed_rid =
        body::receipt_id_for(&parsed.record_id, parsed.deletion_seq, &parsed.nonce);
    if recomputed_rid == parsed.receipt_id {
        report.push(
            "V1 receipt_id recompute",
            Check::Pass(format!("receipt_id {}", hex::encode(recomputed_rid))),
        );
    } else {
        report.push(
            "V1 receipt_id recompute",
            Check::Fail(format!(
                "SHA256(RECEIPT_ID_TAG‖record_id‖deletion_seq‖nonce)={} != body.receipt_id={}",
                hex::encode(recomputed_rid),
                hex::encode(parsed.receipt_id)
            )),
        );
        report.body = Some(parsed);
        return fail_now(report, "v1:receipt-id");
    }

    // --- V1: leaf == receipt_hash ----------------------------------------------------------
    let recomputed_leaf = body::receipt_leaf(&pkg.receipt_body);
    if recomputed_leaf == pkg.receipt_hash {
        report.push(
            "V1 leaf == receipt_hash",
            Check::Pass(format!("leaf {}", hex::encode(recomputed_leaf))),
        );
    } else {
        report.push(
            "V1 leaf == receipt_hash",
            Check::Fail(format!(
                "SHA256(RECEIPT_LEAF_TAG‖body)={} != package.receipt_hash={}",
                hex::encode(recomputed_leaf),
                hex::encode(pkg.receipt_hash)
            )),
        );
    }

    // --- V1: RevealWire (optional): targets_commitment, and (v2) record_id -----------------
    match reveal {
        None => report.push(
            "V1 reveal: targets / record_id",
            Check::Info(
                "no reveal package supplied (targets_commitment / record_id not re-derived)"
                    .to_string(),
            ),
        ),
        Some(rv) => {
            let count_ok = rv.targets.len() as u64 == parsed.targets_count as u64;
            match body::targets_commitment(&rv.salt, &rv.targets, true) {
                Ok(tc) if tc == parsed.targets_commitment && count_ok => report.push(
                    "V1 reveal: targets_commitment",
                    Check::Pass(format!(
                        "{} targets → {} == body.targets_commitment",
                        rv.targets.len(),
                        hex::encode(tc)
                    )),
                ),
                Ok(_) if !count_ok => report.push(
                    "V1 reveal: targets_commitment",
                    Check::Fail(format!(
                        "targets_count mismatch: reveal has {} targets, body says {}",
                        rv.targets.len(),
                        parsed.targets_count
                    )),
                ),
                Ok(tc) => report.push(
                    "V1 reveal: targets_commitment",
                    Check::Fail(format!(
                        "recomputed {} != body.targets_commitment {}",
                        hex::encode(tc),
                        hex::encode(parsed.targets_commitment)
                    )),
                ),
                Err(e) => report.push("V1 reveal: targets_commitment", Check::Fail(e.to_string())),
            }
            match (parsed.version, rv.record_salt) {
                (BodyVersion::V2, Some(rs)) => {
                    let rid = record_id_v2(&rs, parsed.user_canister_id);
                    if rid == parsed.record_id {
                        report.push(
                            "V1 reveal: record_id_v2",
                            Check::Pass(format!(
                                "SHA256(RECORD_ID_TAG_V2‖record_salt‖{}) == body.record_id (authorised linkage)",
                                parsed.user_canister_id
                            )),
                        );
                    } else {
                        report.push(
                            "V1 reveal: record_id_v2",
                            Check::Fail(format!("recomputed {} != body.record_id {}", hex::encode(rid), hex::encode(parsed.record_id))),
                        );
                    }
                }
                (BodyVersion::V2, None) => report.push(
                    "V1 reveal: record_id_v2",
                    Check::Fail("RECEIPT_BODY_V2 requires a RevealWire v2 (`record_salt`); a v1 reveal cannot link this receipt".to_string()),
                ),
                (BodyVersion::V1, Some(_)) => report.push(
                    "V1 reveal: record_id_v2",
                    Check::Fail("historical RECEIPT_BODY_V1 with a RevealWire v2 record_salt — mismatched wire versions".to_string()),
                ),
                (BodyVersion::V1, None) => report.push(
                    "V1 reveal: record_id_v2",
                    Check::Info("historical RECEIPT_BODY_V1: record_id is the retired UserId-only derivation; not re-derived".to_string()),
                ),
            }
        }
    }

    // --- V2: witness -----------------------------------------------------------------------
    let mut witness_root: Option<[u8; 32]> = None;
    match witness::decode_and_locate(&pkg.witness_bytes, &parsed.receipt_id) {
        Ok(w) => {
            if w.leaf_value == pkg.receipt_hash {
                report.push(
                    "V2 receipt_hash == witness leaf",
                    Check::Pass(String::new()),
                );
            } else {
                report.push(
                    "V2 receipt_hash == witness leaf",
                    Check::Fail(format!(
                        "witness leaf {} != receipt_hash {}",
                        hex::encode(w.leaf_value),
                        hex::encode(pkg.receipt_hash)
                    )),
                );
            }
            if w.root == pkg.tree_root {
                report.push(
                    "V2 witness root == tree_root",
                    Check::Pass(format!("root {}", hex::encode(w.root))),
                );
            } else {
                report.push(
                    "V2 witness root == tree_root",
                    Check::Fail(format!(
                        "witness root {} != tree_root {}",
                        hex::encode(w.root),
                        hex::encode(pkg.tree_root)
                    )),
                );
            }
            witness_root = Some(w.root);
        }
        Err(e) => {
            report.push(
                "V2 receipt_hash == witness leaf",
                Check::Fail(e.to_string()),
            );
            report.push(
                "V2 witness root == tree_root",
                Check::Skipped("witness undecodable".to_string()),
            );
        }
    }

    // --- V2: certificate under the selected root ---------------------------------------------
    match witness_root {
        Some(root) => {
            match cert_verifier.verify(&pkg.certificate_bytes, parsed.index_canister_id, &root) {
                Ok(certificate_time_ns) => {
                    report.push(
                        "V2 cert BLS+delegation+range+certified_data",
                        Check::Pass(format!(
                            "certified_data == witness root; canister {} in delegation range",
                            parsed.index_canister_id
                        )),
                    );
                    if pkg.certificate_time == certificate_time_ns {
                        report.push(
                            "V2 certificate_time == cert /time",
                            Check::Pass(format!("{} ns", certificate_time_ns)),
                        );
                    } else {
                        report.push(
                            "V2 certificate_time == cert /time",
                            Check::Fail(format!(
                                "package.certificate_time {} != certificate /time {}",
                                pkg.certificate_time, certificate_time_ns
                            )),
                        );
                    }
                }
                Err(e) => report.push(
                    "V2 cert BLS+delegation+range+certified_data",
                    Check::Fail(e),
                ),
            }
        }
        None => report.push(
            "V2 cert BLS+delegation+range+certified_data",
            Check::Skipped("prerequisite (witness root) unavailable".to_string()),
        ),
    }

    // --- Finalization window: reported, NON-GATING ------------------------------------------
    let window_ns = window_hours.saturating_mul(NS_PER_HOUR);
    let (cert_t, committed) = (pkg.certificate_time, parsed.receipt_committed_at_ns);
    report.window_note = Some(if cert_t >= committed && cert_t - committed <= window_ns {
        format!(
            "certificate_time − receipt_committed_at = {} ns ≤ {} ns ({} h) → in window",
            cert_t - committed,
            window_ns,
            window_hours
        )
    } else if cert_t < committed {
        format!("certificate_time {cert_t} PRECEDES receipt_committed_at {committed} — late/anomalous ordering (non-gating)")
    } else {
        format!("certificate_time − receipt_committed_at = {} ns > {} ns ({} h) → late finalization (non-gating)", cert_t - committed, window_ns, window_hours)
    });

    // --- V3A ---------------------------------------------------------------------------------
    let v3a = index_attestation::evaluate(
        input.index_evidence(),
        &parsed,
        pkg.certificate_time,
        now_ns,
        v3a_trust,
    );
    match &v3a.outcome {
        Ok(V3aOutcome::Pass) => report.push(
            "V3A subnet-attested Index code identity",
            Check::Pass(v3a.detail.clone()),
        ),
        Ok(o) => report.push(
            "V3A subnet-attested Index code identity",
            Check::Info(format!("{}: {}", o.label(), v3a.detail)),
        ),
        Err((name, why)) => report.push(
            "V3A subnet-attested Index code identity",
            Check::Fail(format!("{name}: {why}")),
        ),
    }

    // --- Operator expectation (gating only when supplied) -----------------------------------
    match (expect_module_hash, parsed.version) {
        (None, _) => report.push(
            "expect: Index module hash",
            Check::Info("no --expect-module-hash supplied; no operator expectation was compared".to_string()),
        ),
        (Some(expected), BodyVersion::V2) => match &v3a.certified_module_hash_hex {
            Some(certified) if *certified == hex::encode(expected) => {
                report.push("expect: Index module hash", Check::Pass(format!("V3A-certified module_hash == --expect-module-hash {certified}")))
            }
            Some(certified) => report.push(
                "expect: Index module hash",
                Check::Fail(format!("V3A-certified module_hash {certified} != --expect-module-hash {}", hex::encode(expected))),
            ),
            None => report.push(
                "expect: Index module hash",
                Check::Fail("--expect-module-hash asked for an assertion, but no authenticated Index module hash is available (V3A not PASS)".to_string()),
            ),
        },
        (Some(expected), BodyVersion::V1) => {
            let recomputed = body::h_index_for(parsed.index_canister_id, &expected);
            if Some(recomputed) == parsed.h_index {
                report.push("expect: Index module hash", Check::Pass("historical h_index reproduces --expect-module-hash".to_string()));
            } else {
                report.push(
                    "expect: Index module hash",
                    Check::Fail(format!("historical h_index does not reproduce --expect-module-hash {}", hex::encode(expected))),
                );
            }
        }
    }

    // --- Validity ----------------------------------------------------------------------------
    let first_fail = report
        .checks
        .iter()
        .find(|(_, c)| c.is_fail())
        .map(|(rule, _)| rule.to_string());
    report.validity = match (&first_fail, &v3a.outcome) {
        (Some(_), _) | (None, Err(_)) => Validity::Fail,
        (None, Ok(V3aOutcome::Pass)) => Validity::Pass,
        (None, Ok(_)) => Validity::Incomplete,
    };
    report.reason = match (&first_fail, &v3a.outcome) {
        (Some(rule), _) => Some(rule.clone()),
        (None, Err((name, _))) => Some(name.to_string()),
        (None, Ok(V3aOutcome::PendingInProtectedWindow)) => Some(REASON_V3A_PENDING.to_string()),
        (None, Ok(V3aOutcome::PermanentlyUnavailable)) => {
            Some(REASON_V3A_PERMANENTLY_UNAVAILABLE.to_string())
        }
        (None, Ok(V3aOutcome::Pass)) => None,
    };
    report.v3a = Some(v3a);
    report.body = Some(parsed);
    report
}

/// Live `module_hash` read — DIAGNOSTIC ONLY. Says what the Index runs *now*; never enters validity.
async fn corroborate_live_module_hash(
    agent: &Agent,
    index_canister_id: Principal,
    expected: Option<[u8; 32]>,
) -> Check {
    match agent.read_state_canister_info(index_canister_id, "module_hash").await {
        Err(e) => Check::Info(format!("live module_hash fetch failed (diagnostic): {e}")),
        Ok(live) => match expected {
            Some(exp) if live.as_slice() == exp.as_slice() => Check::Info(format!(
                "live module_hash of {} == --expect-module-hash (diagnostic: the Index currently runs that module)",
                index_canister_id
            )),
            Some(exp) => Check::Info(format!(
                "live module_hash of {} = {} != --expect-module-hash {} (diagnostic: the Index may have been upgraded since the receipt; validity unaffected)",
                index_canister_id,
                hex::encode(&live),
                hex::encode(exp)
            )),
            None => Check::Info(format!("live module_hash of {} = {} (diagnostic only)", index_canister_id, hex::encode(&live))),
        },
    }
}

/// Entry point for `--package` mode. Returns the process exit code.
pub async fn run(agent: &Agent, cfg: Config) -> Result<i32> {
    let input = PackageInput::from_path(&cfg.package_path)?;
    let pkg = input.frozen();
    let reveal = match &cfg.reveal_path {
        Some(p) => Some(RevealPackage::from_path(p)?),
        None => None,
    };
    let (now_ns, now_source) = match cfg.now_ns {
        Some(n) => (n, NowSource::CliNowNs),
        None => (now_ns_default(), NowSource::SystemClock),
    };

    let mut report = match select_trust_root(
        input.trust_root_key_id(),
        cfg.trust_root_key_id.as_deref(),
        cfg.allow_fixture_root_key,
        cfg.fixture_root_key_der
            .as_deref()
            .or(pkg.root_key_der.as_deref()),
    ) {
        Ok(trust) => verify_offline(
            &input,
            reveal.as_ref(),
            cfg.window_hours,
            cfg.expect_module_hash,
            &trust,
            now_ns,
            now_source,
        ),
        Err(why) => {
            // No trusted root could be selected: nothing can be authenticated. Still parse and show
            // the body, but the verdict is FAIL with the selector error named.
            let failing =
                |_: &[u8], _: Principal, _: &[u8; 32]| -> CertVerdict { Err(why.clone()) };
            let mut r = verify_offline_with(
                &input,
                reveal.as_ref(),
                cfg.window_hours,
                cfg.expect_module_hash,
                &failing,
                None,
                now_ns,
                now_source,
            );
            r.validity = Validity::Fail;
            r.reason = Some(format!("trust-root: {why}"));
            r
        }
    };

    if cfg.corroborate_h_index {
        if let Some(b) = &report.body {
            report.corroboration = Some(
                corroborate_live_module_hash(agent, b.index_canister_id, cfg.expect_module_hash)
                    .await,
            );
        }
    }

    report.render();
    Ok(report.validity.exit_code())
}

#[cfg(test)]
mod selector_tests {
    use super::*;

    #[test]
    fn selector_is_not_evidence_and_fails_closed() {
        let m = select_trust_root(Some("mainnet"), None, false, None).unwrap();
        assert!(!m.used.non_production);
        assert_eq!(m.der, nns_keys::lookup_key("mainnet").unwrap().der_bytes);
        assert!(
            select_trust_root(Some("mainnet"), Some("other"), false, None)
                .unwrap_err()
                .contains("conflict")
        );
        assert!(select_trust_root(Some("nonsense"), None, false, None)
            .unwrap_err()
            .contains("unknown trust-root selector"));
        assert!(select_trust_root(Some(""), None, false, None)
            .unwrap_err()
            .contains("unknown"));
        let np = select_trust_root(
            Some(TRUST_ROOT_NON_PRODUCTION),
            None,
            false,
            Some(&[1, 2, 3]),
        )
        .unwrap_err();
        assert!(np.contains("--allow-fixture-root-key"));
        let np2 = select_trust_root(Some(TRUST_ROOT_NON_PRODUCTION), None, true, None).unwrap_err();
        assert!(np2.contains("no non-production root"));
        let ok = select_trust_root(
            Some(TRUST_ROOT_NON_PRODUCTION),
            None,
            true,
            Some(&[1, 2, 3]),
        )
        .unwrap();
        assert!(ok.used.non_production);
        assert_eq!(ok.der, vec![1, 2, 3]);
    }

    #[test]
    fn version_tag_pairing_is_exact() {
        assert_eq!(version_tag_mismatch(Some(3), BodyVersion::V2), None);
        assert_eq!(version_tag_mismatch(Some(2), BodyVersion::V1), None);
        assert_eq!(version_tag_mismatch(None, BodyVersion::V1), None);
        assert_eq!(version_tag_mismatch(None, BodyVersion::V2), None);
        assert!(version_tag_mismatch(Some(3), BodyVersion::V1)
            .unwrap()
            .contains("malformed"));
        assert!(version_tag_mismatch(Some(2), BodyVersion::V2)
            .unwrap()
            .contains("malformed"));
    }

    #[test]
    fn exit_codes_follow_suite_vocabulary() {
        assert_eq!(Validity::Pass.exit_code(), 0);
        assert_eq!(Validity::Fail.exit_code(), 1);
        assert_eq!(Validity::Incomplete.exit_code(), 4);
    }
}
