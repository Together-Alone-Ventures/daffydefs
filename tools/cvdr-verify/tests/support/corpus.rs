//! **Test-only** loader for the countersigned zombie-core mktd02-v5 corpus.
//!
//! No vector content is copied into this crate, and no zombie-core 0.5.0 type
//! is used: the loader reads bytes and hash-checks them.
//!
//! 1. `cargo metadata --locked` on this crate yields the single `zombie-core`
//!    package, which must be a **git** source from the zombie-core repository.
//!    Its checkout path locates cargo's git database for that repository
//!    (`$CARGO_HOME/git/checkouts/<ident>/<rev>` → `$CARGO_HOME/git/db/<ident>`).
//! 2. The package must be pinned by `?rev=`; the corpus is read from that
//!    database **at the graph's own pinned rev** (a full commit id, so the
//!    bytes are content-addressed), which must equal [`V5_CORPUS_REV`], the
//!    spec's pin.
//! 3. `docs/test-vectors/manifest.json` at that rev must be `countersigned`.
//!    Every file in `countersignature.vector_file_sha256` is refused unless its
//!    SHA-256 equals the countersigned value.

#![allow(dead_code)] // each includer uses a subset

use serde_json::Value;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

/// zombie-core `v5` @ 2237238: countersignature over corpus 40ba6db.
pub const V5_CORPUS_REV: &str = "223723885cfbb548d6b218aee8500b073fda4b58";
const ZOMBIE_CORE_GIT: &str = "git+https://github.com/Together-Alone-Ventures/zombie-core";

/// The hash-checked corpus.
pub struct SignedCorpus {
    /// Cargo's git database for the zombie-core repository.
    pub git_db: PathBuf,
    pub rev: String,
    pub manifest: Value,
    /// Relative path → raw bytes, each matched to its countersigned SHA-256.
    pub files: BTreeMap<String, Vec<u8>>,
}

impl SignedCorpus {
    /// Parsed JSON of a hash-checked file.
    pub fn json(&self, rel: &str) -> Value {
        let bytes = self
            .files
            .get(rel)
            .unwrap_or_else(|| panic!("{rel} is not in the countersignature"));
        serde_json::from_slice(bytes).unwrap_or_else(|e| panic!("{rel}: {e}"))
    }

    /// Every vector id the manifest lists (positive, negative, historical).
    pub fn manifest_ids(&self) -> Vec<String> {
        let mut ids = Vec::new();
        for group in ["positive", "negative_and_compatibility"] {
            for id in self.manifest["vectors"][group].as_array().expect(group) {
                ids.push(id.as_str().unwrap().to_string());
            }
        }
        for entry in self.manifest["historical"].as_array().expect("historical") {
            ids.push(entry["id"].as_str().unwrap().to_string());
        }
        ids
    }
}

/// `Ok` iff SHA-256(`bytes`) equals the countersigned hex digest.
pub fn check_sha256(bytes: &[u8], countersigned_hex: &str) -> Result<(), String> {
    let actual = hex::encode(zombie_core::hashing::sha256(bytes));
    if actual == countersigned_hex {
        Ok(())
    } else {
        Err(format!(
            "SHA-256 {actual} does not match countersigned {countersigned_hex}"
        ))
    }
}

/// Load and hash-check the corpus at the rev this crate's graph pins, which
/// must be [`V5_CORPUS_REV`]. Panics on any mismatch.
pub fn load_signed_corpus() -> SignedCorpus {
    let (_, pinned) = zombie_core_git_source().unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        pinned, V5_CORPUS_REV,
        "the graph pins zombie-core {pinned}, not the countersigned corpus rev"
    );
    load_signed_corpus_at(&pinned).unwrap_or_else(|e| panic!("{e}"))
}

/// Load and hash-check the corpus at `rev`.
pub fn load_signed_corpus_at(rev: &str) -> Result<SignedCorpus, String> {
    let (git_db, _) = zombie_core_git_source()?;
    let kind = git(&git_db, &["cat-file", "-t", &format!("{rev}^{{commit}}")]).map_err(|e| {
        format!(
            "zombie-core rev {rev} is not in cargo's git database {}: {e}",
            git_db.display()
        )
    })?;
    if String::from_utf8_lossy(&kind).trim() != "commit" {
        return Err(format!("zombie-core rev {rev} is not a commit"));
    }

    let manifest_rel = "docs/test-vectors/manifest.json";
    let manifest: Value = serde_json::from_slice(&git_show(&git_db, rev, manifest_rel)?)
        .map_err(|e| format!("zombie-core @ {rev}: manifest is not JSON: {e}"))?;
    if manifest["status"] != "countersigned" {
        return Err(format!(
            "zombie-core @ {rev}: corpus manifest is not countersigned"
        ));
    }
    let signed = manifest["countersignature"]["vector_file_sha256"]
        .as_object()
        .ok_or_else(|| format!("zombie-core @ {rev}: no countersignature.vector_file_sha256"))?;

    let mut files = BTreeMap::new();
    for (rel, sha) in signed {
        let bytes = git_show(&git_db, rev, rel)?;
        let sha = sha
            .as_str()
            .ok_or_else(|| format!("{rel}: countersigned SHA-256 is not a string"))?;
        check_sha256(&bytes, sha).map_err(|e| format!("zombie-core @ {rev}: {rel}: {e}"))?;
        files.insert(rel.clone(), bytes);
    }
    Ok(SignedCorpus {
        git_db,
        rev: rev.to_string(),
        manifest,
        files,
    })
}

/// Cargo's git database for the zombie-core repository the graph depends on,
/// and the full commit id the graph pins it at.
fn zombie_core_git_source() -> Result<(PathBuf, String), String> {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    let out = Command::new(cargo)
        .args([
            "metadata",
            "--format-version",
            "1",
            "--locked",
            "--manifest-path",
        ])
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"))
        .output()
        .map_err(|e| format!("cargo metadata did not run: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "cargo metadata failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    let meta: Value = serde_json::from_slice(&out.stdout).map_err(|e| e.to_string())?;
    let zc: Vec<&Value> = meta["packages"]
        .as_array()
        .ok_or("cargo metadata has no packages")?
        .iter()
        .filter(|p| p["name"] == "zombie-core")
        .collect();
    if zc.len() != 1 {
        return Err(format!(
            "expected one zombie-core package, found {}",
            zc.len()
        ));
    }
    let source = zc[0]["source"].as_str().unwrap_or("");
    if !source.starts_with(ZOMBIE_CORE_GIT) {
        return Err(format!(
            "zombie-core must be a git source from {ZOMBIE_CORE_GIT}: {source:?}"
        ));
    }
    let pinned = source
        .strip_prefix(&format!("{ZOMBIE_CORE_GIT}?rev="))
        .and_then(|rest| rest.split_once('#'))
        .filter(|(query, fragment)| query == fragment)
        .map(|(_, fragment)| fragment.to_string())
        .ok_or_else(|| format!("zombie-core must be pinned by a full ?rev=: {source:?}"))?;
    // .../git/checkouts/<ident>/<short-rev>/Cargo.toml
    let manifest_path = PathBuf::from(zc[0]["manifest_path"].as_str().unwrap_or(""));
    let checkout_rev_dir = manifest_path
        .parent()
        .ok_or("zombie-core manifest has no parent")?;
    let ident_dir = checkout_rev_dir
        .parent()
        .ok_or("zombie-core checkout has no parent")?;
    let checkouts = ident_dir.parent().ok_or("zombie-core checkout layout")?;
    if checkouts.file_name().and_then(|n| n.to_str()) != Some("checkouts") {
        return Err(format!(
            "zombie-core is not in a cargo git checkout: {}",
            manifest_path.display()
        ));
    }
    let db = checkouts
        .parent()
        .ok_or("cargo git directory")?
        .join("db")
        .join(ident_dir.file_name().ok_or("checkout ident")?);
    if !db.is_dir() {
        return Err(format!("cargo git database not found: {}", db.display()));
    }
    Ok((db, pinned))
}

fn git(git_db: &Path, args: &[&str]) -> Result<Vec<u8>, String> {
    let out = Command::new("git")
        .arg("--git-dir")
        .arg(git_db)
        .args(args)
        .output()
        .map_err(|e| format!("git did not run: {e}"))?;
    if out.status.success() {
        Ok(out.stdout)
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
    }
}

fn git_show(git_db: &Path, rev: &str, rel: &str) -> Result<Vec<u8>, String> {
    git(git_db, &["show", &format!("{rev}:{rel}")])
        .map_err(|e| format!("zombie-core @ {rev}: cannot read {rel}: {e}"))
}
