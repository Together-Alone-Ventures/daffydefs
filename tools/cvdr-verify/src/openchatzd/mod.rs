//! OpenChatZD frozen-package verification (offline, end-to-end).
//!
//! Verifies a six-field frozen CVDR package against the FROZEN layouts pinned in
//! OpenChatZD's `CVDR_BUILD_SPEC_V1.md` (§2 receipt tree / RECEIPT_BODY_V1, §4
//! frozen package, §5 window/tiers, §9 verifier reject list). The BLS→NNS
//! →delegation→canister-range certificate path is REUSED verbatim from the
//! committed V2 path (`v2_certificate::verify_certificate_over_certified_data`).
//!
//! Verdict tiers (§5, never merged):
//! - `VerifiedFinal`  — cryptographically valid AND certificate within the window.
//! - `LateFinalized`  — cryptographically valid but late (or cert precedes the
//!                      commit anchor); a DISTINCT output, never promoted.
//! - `Reject`         — any §9 rule 1–4 failure, or a packaging-integrity failure
//!                      (body does not hash to receipt_hash; certificate_time
//!                      disagrees with the certificate's `/time`).

pub mod body;
pub mod package;
pub mod witness;

#[cfg(test)]
mod fixtures;

use anyhow::{anyhow, Result};
use candid::Principal;
use ic_agent::Agent;
use zombie_core::nns_keys;

use crate::v2_certificate::verify_certificate_over_certified_data;
use body::ReceiptBody;
use package::{FrozenPackage, RevealPackage};

/// Default finalization window (spec §5): 24h, aligned to the retry cap.
pub const DEFAULT_WINDOW_HOURS: u64 = 24;
const NS_PER_HOUR: u64 = 3_600_000_000_000;

/// CLI-supplied configuration for an OpenChatZD package verification.
pub struct Config {
    /// Frozen package JSON path.
    pub package_path: String,
    /// Optional reveal package `{version, salt, sorted target list}` (spec §2).
    pub reveal_path: Option<String>,
    /// Allowed finalization window in hours (spec §5; default 24).
    pub window_hours: u64,
    /// Trust-root key id (`nns_keys`); default = build's active key (mainnet).
    pub trust_root_key_id: Option<String>,
    /// TEST-ONLY opt-in: when true, a `root_key_hex` supplied IN the frozen package is used as the
    /// certificate trust anchor (e.g. a PocketIC NNS root, which is not a built-in key). Default
    /// false — a fixture must never silently supply its own trust anchor; built-in NNS roots win.
    pub allow_fixture_root_key: bool,
    /// Optional live `module_hash` read_state. Informational on its own; GATES against
    /// `expect_module_hash` when that is also supplied.
    pub corroborate_h_index: bool,
    /// Expected executor module hash. When supplied, `body.h_index` is recomputed from it
    /// OFFLINE and a mismatch is a hard reject.
    pub expect_module_hash: Option<[u8; 32]>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    VerifiedFinal,
    LateFinalized,
    Reject,
}

impl Verdict {
    pub fn label(self) -> &'static str {
        match self {
            Verdict::VerifiedFinal => "VerifiedFinal",
            Verdict::LateFinalized => "LateFinalized",
            Verdict::Reject => "REJECT",
        }
    }
    /// Process exit code: distinct per tier so a late finalization is never
    /// mistaken for a full one by a caller keying on `$?`.
    pub fn exit_code(self) -> i32 {
        match self {
            Verdict::VerifiedFinal => 0,
            Verdict::Reject => 1,
            Verdict::LateFinalized => 3,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Check {
    Pass(String),
    Fail(String),
    /// Not evaluated because a prerequisite failed (still forces REJECT).
    Skipped(String),
    /// Informational only — never affects the verdict.
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

/// Full structured report; `render()` prints it and `verdict` drives the exit code.
pub struct Report {
    pub verdict: Verdict,
    body: Option<ReceiptBody>,
    checks: Vec<(&'static str, Check)>,
    window_note: Option<String>,
    corroboration: Option<Check>,
}

impl Report {
    fn push(&mut self, rule: &'static str, c: Check) {
        self.checks.push((rule, c));
    }

    pub fn render(&self) {
        println!("============================================================");
        println!(" CVDR-Verify: OpenChatZD Frozen Package (spec §2/§4/§5/§9)");
        println!("============================================================");
        if let Some(b) = &self.body {
            println!(" Parsed RECEIPT_BODY_V1:");
            println!("   receipt_id            : {}", hex::encode(b.receipt_id));
            println!("   nonce                 : {}", hex::encode(b.nonce));
            println!("   index_canister_id     : {}", b.index_canister_id);
            println!("   user_canister_id      : {}", b.user_canister_id);
            println!("   record_id             : {}", hex::encode(b.record_id));
            println!("   deletion_seq          : {}", b.deletion_seq);
            println!("   h_user_pre            : {}", hex::encode(b.h_user_pre));
            println!("   h_index               : {}", hex::encode(b.h_index));
            println!("   commitment            : {}", hex::encode(b.commitment));
            println!("   uninstall_completed_at: {} ns", b.uninstall_completed_at_ns);
            println!("   receipt_committed_at  : {} ns", b.receipt_committed_at_ns);
            println!("   targets_count         : {}", b.targets_count);
            println!("   targets_commitment    : {}", hex::encode(b.targets_commitment));
            println!();
        }
        println!(" Checks:");
        for (rule, c) in &self.checks {
            println!("   [{}] {:<28} {}", c.glyph(), rule, c.text());
        }
        if let Some(w) = &self.window_note {
            println!();
            println!(" Window (§5): {}", w);
        }
        if let Some(c) = &self.corroboration {
            println!();
            match c {
                Check::Info(_) => println!(
                    " Live module_hash (INFORMATIONAL — no --expect-module-hash supplied, so nothing\n \
                      was compared; this is NOT a hash verification):"
                ),
                _ => println!(" Live module_hash vs --expect-module-hash (GATING):"),
            }
            println!("   [{}] {}", c.glyph(), c.text());
        }
        println!();
        println!("============================================================");
        println!(" VERDICT: {}", self.verdict.label());
        println!("============================================================");
    }
}

/// Decide the certificate trust-anchor override, honouring the "no silent fixture trust anchor"
/// rule (G): the package's `root_key_hex` is used ONLY when `--allow-fixture-root-key` is passed,
/// and its use is announced loudly. Without the flag, a present fixture key is IGNORED.
fn resolve_fixture_root_key(allow: bool, fixture_der: Option<&[u8]>) -> Option<Vec<u8>> {
    match (allow, fixture_der) {
        (true, Some(d)) => {
            eprintln!(
                "WARNING --allow-fixture-root-key: verifying against the FIXTURE-SUPPLIED trust anchor \
                 ({} bytes), NOT a built-in NNS root. TEST-ONLY; never use for a real verdict.",
                d.len()
            );
            Some(d.to_vec())
        }
        (true, None) => {
            eprintln!("Note: --allow-fixture-root-key set, but the package carries no root_key_hex; using built-in NNS roots.");
            None
        }
        (false, Some(_)) => {
            eprintln!("Note: package carries root_key_hex but --allow-fixture-root-key was NOT passed; IGNORING it (built-in NNS roots).");
            None
        }
        (false, None) => None,
    }
}

/// Resolve the trust-root DER for the certificate path.
fn trust_root_der(trust_root_key_id: &Option<String>) -> Result<&'static [u8]> {
    let id = trust_root_key_id
        .clone()
        .unwrap_or_else(|| nns_keys::active_key_id().to_string());
    let key = nns_keys::lookup_key(id.trim()).ok_or_else(|| {
        let known: Vec<&str> = nns_keys::MAINNET_KEYS.iter().map(|k| k.id).collect();
        anyhow!(
            "unknown trust_root_key_id '{}'. Known IDs: {}. For local-dev, rebuild with --features local-replica.",
            id,
            known.join(", ")
        )
    })?;
    Ok(key.der_bytes)
}

/// Result of the certificate stage: the reused BLS→NNS→delegation→range path
/// plus the `certified_data == witness_root` comparison (§9.3/§9.4). `Ok` carries
/// the certificate's `/time`; `Err` carries the reject reason.
pub type CertVerdict = std::result::Result<u64, String>;

/// The certificate stage as an injectable closure `(cert_bytes, index_canister_id,
/// expected_certified_data) -> CertVerdict`. Production resolves the NNS trust
/// root and runs the committed BLS path; tests drive the full pipeline (window
/// tiers, §9.4 reject) with a controllable stage while the REAL BLS path is
/// exercised directly against the A1 mainnet fixture.
pub trait CertVerifier {
    fn verify(&self, cert_bytes: &[u8], canister_id: Principal, expected: &[u8; 32]) -> CertVerdict;
}

impl<F> CertVerifier for F
where
    F: Fn(&[u8], Principal, &[u8; 32]) -> CertVerdict,
{
    fn verify(&self, cert_bytes: &[u8], canister_id: Principal, expected: &[u8; 32]) -> CertVerdict {
        self(cert_bytes, canister_id, expected)
    }
}

/// Production certificate verifier: run the committed BLS→NNS→delegation→canister-range path over
/// `certified_data`. The trust anchor is a BUILT-IN NNS root resolved by key id, UNLESS an explicit
/// DER override is present (only ever set when `--allow-fixture-root-key` gated it in).
struct NnsCertVerifier {
    trust_root_key_id: Option<String>,
    /// Explicit trust-anchor DER (fixture-supplied). `None` => resolve a built-in NNS root.
    explicit_der: Option<Vec<u8>>,
}

impl CertVerifier for NnsCertVerifier {
    fn verify(&self, cert_bytes: &[u8], canister_id: Principal, expected: &[u8; 32]) -> CertVerdict {
        let der: Vec<u8> = match &self.explicit_der {
            Some(d) => d.clone(),
            None => trust_root_der(&self.trust_root_key_id).map_err(|e| e.to_string())?.to_vec(),
        };
        verify_certificate_over_certified_data(cert_bytes, canister_id, expected, &der)
            .map(|o| o.certificate_time_ns)
    }
}

/// Compute the offline verdict for a decoded package (pure; no network).
///
/// `reveal` optionally supplies the TARGETS_COMMITMENT_V1 reveal package. The
/// §9 rules 1–4 and the two packaging-integrity checks are hard rejects; the §5
/// window only tiers a cryptographically valid package (never rejects, §9.5).
pub fn verify_offline(
    pkg: &FrozenPackage,
    reveal: Option<&RevealPackage>,
    window_hours: u64,
    trust_root_key_id: &Option<String>,
    expect_module_hash: Option<[u8; 32]>,
) -> Report {
    verify_offline_with(
        pkg,
        reveal,
        window_hours,
        expect_module_hash,
        &NnsCertVerifier {
            trust_root_key_id: trust_root_key_id.clone(),
            explicit_der: None,
        },
    )
}

/// Core verifier with an injectable certificate stage (see [`CertVerifier`]).
///
/// `expect_module_hash` gates: when `Some(m)`, `body.h_index` must equal
/// `SHA256(H_INDEX_TAG ‖ index_canister_id ‖ m)` or the package is REJECTED. When
/// `None`, no module hash is checked and the verdict is exactly the un-gated one.
pub fn verify_offline_with(
    pkg: &FrozenPackage,
    reveal: Option<&RevealPackage>,
    window_hours: u64,
    expect_module_hash: Option<[u8; 32]>,
    cert_verifier: &dyn CertVerifier,
) -> Report {
    let mut report = Report {
        verdict: Verdict::Reject,
        body: None,
        checks: Vec::new(),
        window_note: None,
        corroboration: None,
    };

    // --- Parse RECEIPT_BODY_V1 -------------------------------------------------
    let parsed = match ReceiptBody::parse(&pkg.receipt_body) {
        Ok(b) => b,
        Err(e) => {
            report.push("body: RECEIPT_BODY_V1 parse", Check::Fail(e.to_string()));
            report.verdict = Verdict::Reject;
            return report;
        }
    };
    report.push(
        "body: RECEIPT_BODY_V1 parse",
        Check::Pass(format!("{} bytes, all fields decoded", pkg.receipt_body.len())),
    );

    // --- Packaging integrity: receipt_hash == SHA256(LEAF_TAG‖body) -----------
    let recomputed_leaf = body::receipt_leaf(&pkg.receipt_body);
    if recomputed_leaf == pkg.receipt_hash {
        report.push(
            "body: leaf == receipt_hash",
            Check::Pass(format!("leaf {}", hex::encode(recomputed_leaf))),
        );
    } else {
        report.push(
            "body: leaf == receipt_hash",
            Check::Fail(format!(
                "SHA256(RECEIPT_LEAF_TAG‖body)={} != package.receipt_hash={}",
                hex::encode(recomputed_leaf),
                hex::encode(pkg.receipt_hash)
            )),
        );
    }

    // --- h_index binding (gating, offline) -------------------------------------
    // The body's h_index is hash-bound; recomputing it from a supplied module hash
    // decides whether THIS receipt commits to THAT module. Absent an expectation we
    // state plainly that nothing was verified, rather than staying silent.
    match expect_module_hash {
        None => report.push(
            "h_index: binds expected module",
            Check::Info(
                "no --expect-module-hash supplied; body.h_index was NOT verified against any module hash"
                    .to_string(),
            ),
        ),
        Some(expected) => {
            let recomputed = body::h_index_for(parsed.index_canister_id, &expected);
            if recomputed == parsed.h_index {
                report.push(
                    "h_index: binds expected module",
                    Check::Pass(format!(
                        "SHA256(H_INDEX_TAG ‖ {} ‖ {}) == body.h_index",
                        parsed.index_canister_id,
                        hex::encode(expected)
                    )),
                );
            } else {
                report.push(
                    "h_index: binds expected module",
                    Check::Fail(format!(
                        "H_INDEX_MISMATCH: the receipt does NOT commit to this module. \
                         SHA256(H_INDEX_TAG ‖ {} ‖ {}) = {} != body.h_index = {}",
                        parsed.index_canister_id,
                        hex::encode(expected),
                        hex::encode(recomputed),
                        hex::encode(parsed.h_index)
                    )),
                );
            }
        }
    }

    // --- Witness (§9 rules 1 & 2) ---------------------------------------------
    // receipt_id is HASH-BOUND (from the parsed body), not a caller argument.
    let mut witness_root: Option<[u8; 32]> = None;
    match witness::decode_and_locate(&pkg.witness_bytes, &parsed.receipt_id) {
        Ok(w) => {
            // §9.1: receipt hash == witness leaf.
            if w.leaf_value == pkg.receipt_hash {
                report.push("§9.1 receipt_hash == witness leaf", Check::Pass(String::new()));
            } else {
                report.push(
                    "§9.1 receipt_hash == witness leaf",
                    Check::Fail(format!(
                        "witness leaf {} != receipt_hash {}",
                        hex::encode(w.leaf_value),
                        hex::encode(pkg.receipt_hash)
                    )),
                );
            }
            // §9.2: witness root == bundled tree_root.
            if w.root == pkg.tree_root {
                report.push(
                    "§9.2 witness root == tree_root",
                    Check::Pass(format!("root {}", hex::encode(w.root))),
                );
            } else {
                report.push(
                    "§9.2 witness root == tree_root",
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
            report.push("§9.1 receipt_hash == witness leaf", Check::Fail(e.to_string()));
            report.push(
                "§9.2 witness root == tree_root",
                Check::Skipped("witness undecodable".to_string()),
            );
        }
    }

    // --- Reveal package (TARGETS_COMMITMENT_V1, optional input) ----------------
    match reveal {
        None => report.push(
            "reveal: targets_commitment",
            Check::Info("no reveal package supplied (targets_commitment not re-derived)".to_string()),
        ),
        Some(rv) => {
            let count_ok = rv.targets.len() as u64 == parsed.targets_count as u64;
            match body::targets_commitment(&rv.salt, &rv.targets, true) {
                Ok(tc) if tc == parsed.targets_commitment && count_ok => report.push(
                    "reveal: targets_commitment",
                    Check::Pass(format!(
                        "{} targets → {} == body.targets_commitment",
                        rv.targets.len(),
                        hex::encode(tc)
                    )),
                ),
                Ok(_) if !count_ok => report.push(
                    "reveal: targets_commitment",
                    Check::Fail(format!(
                        "targets_count mismatch: reveal has {} targets, body says {}",
                        rv.targets.len(),
                        parsed.targets_count
                    )),
                ),
                Ok(tc) => report.push(
                    "reveal: targets_commitment",
                    Check::Fail(format!(
                        "recomputed {} != body.targets_commitment {}",
                        hex::encode(tc),
                        hex::encode(parsed.targets_commitment)
                    )),
                ),
                Err(e) => report.push("reveal: targets_commitment", Check::Fail(e.to_string())),
            }
        }
    }

    // --- Certificate (§9 rules 3 & 4 + certificate_time cross-check) -----------
    // certified_data must equal the witness root (§9.3). We require the witness
    // to have decoded (else we cannot state the §9.3 comparison honestly).
    match witness_root {
        Some(root) => {
            match cert_verifier.verify(&pkg.certificate_bytes, parsed.index_canister_id, &root) {
                Ok(certificate_time_ns) => {
                    report.push(
                        "§9.3/§9.4 cert BLS+delegation+range+certified_data",
                        Check::Pass(format!(
                            "certified_data == witness root; canister {} in delegation range",
                            parsed.index_canister_id
                        )),
                    );
                    // certificate_time cross-check (packaging integrity): the
                    // bundled field MUST equal the certificate's own /time.
                    if pkg.certificate_time == certificate_time_ns {
                        report.push(
                            "cert: certificate_time == cert /time",
                            Check::Pass(format!("{} ns", certificate_time_ns)),
                        );
                    } else {
                        report.push(
                            "cert: certificate_time == cert /time",
                            Check::Fail(format!(
                                "package.certificate_time {} != certificate /time {}",
                                pkg.certificate_time, certificate_time_ns
                            )),
                        );
                    }
                }
                Err(e) => report.push(
                    "§9.3/§9.4 cert BLS+delegation+range+certified_data",
                    Check::Fail(e),
                ),
            }
        }
        None => report.push(
            "§9.3/§9.4 cert BLS+delegation+range+certified_data",
            Check::Skipped("prerequisite (witness root) unavailable".to_string()),
        ),
    }

    // --- Verdict: hard checks first (§9 1–4 + integrity), then window tier ----
    let any_fail = report.checks.iter().any(|(_, c)| c.is_fail());
    if any_fail {
        report.verdict = Verdict::Reject;
        report.body = Some(parsed);
        return report;
    }

    // All hard checks passed → cryptographically valid. Tier by the window (§5).
    // certificate_time == cert /time is proven above, so use the bundled value.
    let window_ns = window_hours.saturating_mul(NS_PER_HOUR);
    let cert_t = pkg.certificate_time;
    let committed = parsed.receipt_committed_at_ns;
    if cert_t >= committed && cert_t - committed <= window_ns {
        let delta = cert_t - committed;
        report.window_note = Some(format!(
            "certificate_time - receipt_committed_at = {} ns ≤ window {} ns ({} h) → IN WINDOW",
            delta, window_ns, window_hours
        ));
        report.verdict = Verdict::VerifiedFinal;
    } else {
        let note = if cert_t < committed {
            format!(
                "certificate_time {} PRECEDES receipt_committed_at {} (Δ = -{} ns) — out of window",
                cert_t,
                committed,
                committed - cert_t
            )
        } else {
            format!(
                "certificate_time - receipt_committed_at = {} ns > window {} ns ({} h) — late",
                cert_t - committed,
                window_ns,
                window_hours
            )
        };
        report.window_note = Some(format!("{} → LateFinalized (valid, NOT promoted)", note));
        report.verdict = Verdict::LateFinalized;
    }

    report.body = Some(parsed);
    report
}

/// Live `module_hash` corroboration via `read_state`. Two distinct behaviours:
///
/// - `expect_module_hash = None` → **informational only**. Reports the live hash and
///   says explicitly that nothing was compared. Never affects the verdict, and must
///   never be read as "the hash was verified".
/// - `expect_module_hash = Some(m)` → **gating**. The live certified `module_hash` must
///   equal `m`. A mismatch, or an unreachable network, is a FAILING check: the caller
///   asked for a live assertion, so we fail closed rather than pass on silence.
///
/// This is a claim about what the index canister runs *now*, NOT about the receipt.
/// The receipt-binding claim is the offline `h_index` gate in [`verify_offline_with`];
/// a canister legitimately upgraded after the deletion will mismatch here while its
/// receipts remain perfectly valid.
async fn corroborate_h_index(
    agent: &Agent,
    index_canister_id: Principal,
    expect_module_hash: Option<[u8; 32]>,
) -> Check {
    let live = match agent
        .read_state_canister_info(index_canister_id, "module_hash")
        .await
    {
        Ok(bytes) => bytes,
        Err(e) => {
            return match expect_module_hash {
                Some(_) => Check::Fail(format!(
                    "LIVE_MODULE_HASH_UNAVAILABLE: --expect-module-hash asked for a live assertion, \
                     but read_state module_hash for {} failed: {}",
                    index_canister_id, e
                )),
                None => Check::Info(format!("live module_hash fetch failed (non-fatal): {}", e)),
            }
        }
    };

    match expect_module_hash {
        None => Check::Info(format!(
            "live certified module_hash of {} = {} — INFORMATIONAL ONLY; no --expect-module-hash \
             was supplied, so nothing was compared and no hash was verified",
            index_canister_id,
            hex::encode(&live)
        )),
        Some(expected) if live.as_slice() == expected.as_slice() => Check::Pass(format!(
            "live certified module_hash of {} == --expect-module-hash {}",
            index_canister_id,
            hex::encode(expected)
        )),
        Some(expected) => Check::Fail(format!(
            "LIVE_MODULE_HASH_MISMATCH: live certified module_hash of {} = {} != --expect-module-hash {} \
             (the canister may have been upgraded since the receipt; this does not by itself impeach the receipt)",
            index_canister_id,
            hex::encode(&live),
            hex::encode(expected)
        )),
    }
}

/// Entry point for `--package` mode. Returns the process exit code.
pub async fn run(agent: &Agent, cfg: Config) -> Result<i32> {
    let pkg = FrozenPackage::from_path(&cfg.package_path)?;
    let reveal = match &cfg.reveal_path {
        Some(p) => Some(RevealPackage::from_path(p)?),
        None => None,
    };

    // Certificate trust anchor: built-in NNS roots by default; the fixture-supplied `root_key_hex`
    // is used ONLY under the explicit --allow-fixture-root-key opt-in (loud), never silently.
    let explicit_der = resolve_fixture_root_key(cfg.allow_fixture_root_key, pkg.root_key_der.as_deref());
    let verifier = NnsCertVerifier {
        trust_root_key_id: cfg.trust_root_key_id.clone(),
        explicit_der,
    };
    let mut report = verify_offline_with(
        &pkg,
        reveal.as_ref(),
        cfg.window_hours,
        cfg.expect_module_hash,
        &verifier,
    );

    // Live corroboration runs after the offline verdict, but — unlike v0.5.0 — it can
    // still DEGRADE that verdict: a failing live assertion rejects. It can never promote.
    if cfg.corroborate_h_index {
        if let Some(b) = &report.body {
            let c = corroborate_h_index(agent, b.index_canister_id, cfg.expect_module_hash).await;
            if c.is_fail() {
                report.verdict = Verdict::Reject;
            }
            report.corroboration = Some(c);
        }
    }

    report.render();
    Ok(report.verdict.exit_code())
}
