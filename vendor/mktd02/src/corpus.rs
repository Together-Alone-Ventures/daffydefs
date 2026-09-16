//! **Test-only** loader for the countersigned zombie-core v5 corpus
//! (Slice 3 phase 9).
//!
//! No vector content is copied into Leaf. The loader:
//!
//! 1. runs `cargo metadata` on the calling crate's manifest and takes the
//!    single `zombie-core` package, which must be a **git** source (the pin);
//!    its `manifest_path` parent is the pinned checkout;
//! 2. reads `docs/test-vectors/manifest.json` from that checkout, which must be
//!    `countersigned`, and looks the vector up in its
//!    `countersignature.vector_file_sha256` block;
//! 3. reads `docs/test-vectors/v5/<id>.json` and refuses it unless its SHA-256
//!    equals the countersigned value — so a passing test has read the SIGNED
//!    bytes, not whatever happens to be on disk.
//!
//! Self-contained (std + `zombie_core` + `hex`, no dev-dependencies): mktd02
//! compiles it as `#[cfg(test)] mod corpus`, and the PocketIC harness includes
//! the same file via `#[path]`. JSON is read by the minimal parser below
//! because `serde_json` is optional in mktd02 and absent from default-feature
//! test builds.

#![allow(dead_code)] // each includer uses a subset

use std::path::{Path, PathBuf};
use std::process::Command;

const ZOMBIE_CORE_GIT: &str = "git+https://github.com/Together-Alone-Ventures/zombie-core?rev=";

/// A v5 vector whose bytes matched the countersignature.
pub struct SignedVector {
    /// Parsed vector file.
    pub json: Json,
    /// Commit of the pinned checkout (from the cargo `source` fragment).
    pub rev: String,
    /// Countersigned SHA-256 of the file (hex), which the bytes matched.
    pub sha256_hex: String,
}

/// Load `docs/test-vectors/v5/<id>.json` from the zombie-core checkout that
/// `manifest_dir`'s Cargo graph pins. Panics unless the file hash equals the
/// countersigned value.
pub fn load_signed_v5_vector(manifest_dir: &str, id: &str) -> SignedVector {
    let (checkout, rev) = pinned_zombie_core_checkout(manifest_dir);

    let manifest = read_json(&checkout.join("docs/test-vectors/manifest.json"));
    assert_eq!(
        manifest.str_at(&["status"]),
        "countersigned",
        "zombie-core @ {rev}: corpus manifest is not countersigned"
    );
    let rel = format!("docs/test-vectors/v5/{id}.json");
    let signed = manifest
        .at(&["countersignature", "vector_file_sha256"])
        .get(&rel)
        .and_then(Json::as_str)
        .unwrap_or_else(|| panic!("zombie-core @ {rev}: {rel} is not in the countersignature"))
        .to_string();

    let bytes = std::fs::read(checkout.join(&rel))
        .unwrap_or_else(|e| panic!("zombie-core @ {rev}: cannot read {rel}: {e}"));
    check_sha256(&bytes, &signed).unwrap_or_else(|e| panic!("zombie-core @ {rev}: {rel}: {e}"));

    let json = parse(std::str::from_utf8(&bytes).expect("vector is not UTF-8"))
        .unwrap_or_else(|e| panic!("{rel}: {e}"));
    assert_eq!(json.str_at(&["id"]), id, "{rel}: id field mismatch");
    SignedVector {
        json,
        rev,
        sha256_hex: signed,
    }
}

/// `Ok` iff SHA-256(`bytes`) equals `expected_hex`.
pub fn check_sha256(bytes: &[u8], expected_hex: &str) -> Result<(), String> {
    let actual = hex::encode(zombie_core::hashing::sha256_concat(&[bytes]));
    if actual == expected_hex {
        Ok(())
    } else {
        Err(format!(
            "SHA-256 {actual} does not match countersigned {expected_hex}"
        ))
    }
}

/// Decode a hex string field of a vector.
pub fn hex_at(v: &Json, path: &[&str]) -> Vec<u8> {
    hex::decode(v.str_at(path)).unwrap_or_else(|e| panic!("{path:?}: bad hex: {e}"))
}

/// Decode a 32-byte hex string field of a vector.
pub fn hex32_at(v: &Json, path: &[&str]) -> [u8; 32] {
    hex_at(v, path)
        .try_into()
        .unwrap_or_else(|_| panic!("{path:?}: expected 32 bytes"))
}

/// The pinned checkout root and its commit, via `cargo metadata`.
fn pinned_zombie_core_checkout(manifest_dir: &str) -> (PathBuf, String) {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    let out = Command::new(cargo)
        .args([
            "metadata",
            "--format-version",
            "1",
            "--locked",
            "--manifest-path",
        ])
        .arg(Path::new(manifest_dir).join("Cargo.toml"))
        .output()
        .expect("failed to run cargo metadata");
    assert!(
        out.status.success(),
        "cargo metadata failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let meta = parse(std::str::from_utf8(&out.stdout).expect("metadata is not UTF-8"))
        .expect("cargo metadata output is not JSON");

    let zc: Vec<&Json> = meta
        .at(&["packages"])
        .as_arr()
        .expect("packages is not an array")
        .iter()
        .filter(|p| p.get("name").and_then(Json::as_str) == Some("zombie-core"))
        .collect();
    assert_eq!(zc.len(), 1, "expected exactly one zombie-core package");

    let source = zc[0].str_at(&["source"]);
    let rev = source
        .strip_prefix(ZOMBIE_CORE_GIT)
        .and_then(|s| s.split_once('#'))
        .map(|(q, commit)| {
            assert_eq!(q, commit, "zombie-core source rev and commit disagree");
            commit.to_string()
        })
        .unwrap_or_else(|| panic!("zombie-core is not the git pin: {source}"));
    let checkout = Path::new(zc[0].str_at(&["manifest_path"]))
        .parent()
        .expect("manifest_path has no parent")
        .to_path_buf();
    (checkout, rev)
}

fn read_json(path: &Path) -> Json {
    let text = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    parse(&text).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

// ---------------------------------------------------------------------------
// Minimal JSON reader (RFC 8259 values; numbers kept as their source text).
// ---------------------------------------------------------------------------

#[derive(Debug, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    Num(String),
    Str(String),
    Arr(Vec<Json>),
    Obj(Vec<(String, Json)>),
}

impl Json {
    pub fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Obj(members) => members.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Json::Str(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_arr(&self) -> Option<&[Json]> {
        match self {
            Json::Arr(a) => Some(a),
            _ => None,
        }
    }

    /// Follow `path` through nested objects; panics naming the path if absent.
    pub fn at(&self, path: &[&str]) -> &Json {
        path.iter().fold(self, |v, k| {
            v.get(k)
                .unwrap_or_else(|| panic!("missing JSON key {path:?}"))
        })
    }

    pub fn str_at(&self, path: &[&str]) -> &str {
        self.at(path)
            .as_str()
            .unwrap_or_else(|| panic!("{path:?} is not a string"))
    }

    pub fn u64_at(&self, path: &[&str]) -> u64 {
        match self.at(path) {
            Json::Num(n) => n.parse().unwrap_or_else(|e| panic!("{path:?}: {e}")),
            _ => panic!("{path:?} is not a number"),
        }
    }
}

pub fn parse(text: &str) -> Result<Json, String> {
    let mut p = Parser {
        s: text.as_bytes(),
        i: 0,
    };
    let v = p.value()?;
    p.ws();
    if p.i != p.s.len() {
        return Err(format!("trailing data at byte {}", p.i));
    }
    Ok(v)
}

struct Parser<'a> {
    s: &'a [u8],
    i: usize,
}

impl Parser<'_> {
    fn ws(&mut self) {
        while matches!(self.s.get(self.i), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.i += 1;
        }
    }

    fn eat(&mut self, lit: &[u8]) -> Result<(), String> {
        if self.s[self.i..].starts_with(lit) {
            self.i += lit.len();
            Ok(())
        } else {
            Err(format!("expected {:?} at byte {}", lit, self.i))
        }
    }

    fn value(&mut self) -> Result<Json, String> {
        self.ws();
        match self.s.get(self.i) {
            Some(b'{') => self.object(),
            Some(b'[') => self.array(),
            Some(b'"') => self.string().map(Json::Str),
            Some(b't') => self.eat(b"true").map(|_| Json::Bool(true)),
            Some(b'f') => self.eat(b"false").map(|_| Json::Bool(false)),
            Some(b'n') => self.eat(b"null").map(|_| Json::Null),
            Some(b'-' | b'0'..=b'9') => self.number(),
            _ => Err(format!("unexpected input at byte {}", self.i)),
        }
    }

    fn object(&mut self) -> Result<Json, String> {
        self.eat(b"{")?;
        let mut members = Vec::new();
        self.ws();
        if self.eat(b"}").is_ok() {
            return Ok(Json::Obj(members));
        }
        loop {
            self.ws();
            let k = self.string()?;
            self.ws();
            self.eat(b":")?;
            members.push((k, self.value()?));
            self.ws();
            if self.eat(b",").is_err() {
                self.eat(b"}")?;
                return Ok(Json::Obj(members));
            }
        }
    }

    fn array(&mut self) -> Result<Json, String> {
        self.eat(b"[")?;
        let mut items = Vec::new();
        self.ws();
        if self.eat(b"]").is_ok() {
            return Ok(Json::Arr(items));
        }
        loop {
            items.push(self.value()?);
            self.ws();
            if self.eat(b",").is_err() {
                self.eat(b"]")?;
                return Ok(Json::Arr(items));
            }
        }
    }

    fn number(&mut self) -> Result<Json, String> {
        let start = self.i;
        while matches!(
            self.s.get(self.i),
            Some(b'-' | b'+' | b'.' | b'e' | b'E' | b'0'..=b'9')
        ) {
            self.i += 1;
        }
        let n = std::str::from_utf8(&self.s[start..self.i]).expect("ASCII");
        Ok(Json::Num(n.to_string()))
    }

    fn hex4(&mut self) -> Result<u32, String> {
        let h = self
            .s
            .get(self.i..self.i + 4)
            .and_then(|h| std::str::from_utf8(h).ok())
            .and_then(|h| u32::from_str_radix(h, 16).ok())
            .ok_or_else(|| format!("bad \\u escape at byte {}", self.i))?;
        self.i += 4;
        Ok(h)
    }

    fn string(&mut self) -> Result<String, String> {
        self.eat(b"\"")?;
        let mut out = String::new();
        loop {
            let start = self.i;
            while !matches!(self.s.get(self.i), Some(b'"' | b'\\') | None) {
                self.i += 1;
            }
            out.push_str(std::str::from_utf8(&self.s[start..self.i]).map_err(|e| e.to_string())?);
            match self.s.get(self.i) {
                Some(b'"') => {
                    self.i += 1;
                    return Ok(out);
                }
                Some(b'\\') => {
                    let esc = *self.s.get(self.i + 1).ok_or("unterminated escape")?;
                    self.i += 2;
                    match esc {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{8}'),
                        b'f' => out.push('\u{c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let mut c = self.hex4()?;
                            if (0xD800..0xDC00).contains(&c) {
                                self.eat(b"\\u")?;
                                let lo = self.hex4()?;
                                c = 0x10000 + ((c - 0xD800) << 10) + (lo.wrapping_sub(0xDC00));
                            }
                            out.push(char::from_u32(c).ok_or("invalid \\u code point")?);
                        }
                        _ => return Err(format!("bad escape at byte {}", self.i - 1)),
                    }
                }
                _ => return Err("unterminated string".into()),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_reader_handles_the_shapes_the_corpus_uses() {
        let v =
            parse(r#" {"a":"§x\"\\","n":1700000000000000000,"z":[true,null,{}],"e":[]} "#).unwrap();
        assert_eq!(v.str_at(&["a"]), "\u{a7}x\"\\");
        assert_eq!(v.u64_at(&["n"]), 1_700_000_000_000_000_000);
        assert_eq!(
            v.at(&["z"]).as_arr().unwrap(),
            &[Json::Bool(true), Json::Null, Json::Obj(vec![])]
        );
        assert_eq!(parse("\"\\ud83d\\ude00\"").unwrap(), Json::Str("😀".into()));
        assert!(parse("{\"a\":1} x").is_err());
    }

    /// The hash gate refuses bytes that differ from the countersigned value.
    #[test]
    fn sha256_gate_refuses_altered_bytes() {
        let v = load_signed_v5_vector(env!("CARGO_MANIFEST_DIR"), "gv5-002");
        let (checkout, _) = pinned_zombie_core_checkout(env!("CARGO_MANIFEST_DIR"));
        let mut bytes = std::fs::read(checkout.join("docs/test-vectors/v5/gv5-002.json")).unwrap();
        assert!(check_sha256(&bytes, &v.sha256_hex).is_ok());
        bytes.push(b' ');
        assert!(check_sha256(&bytes, &v.sha256_hex).is_err());
    }

    /// P9.2: both phase-9 vectors load from the pinned checkout and match the
    /// countersignature recorded there.
    #[test]
    fn p9_2_gv5_002_and_gv5_011_load_from_the_countersigned_pin() {
        for id in ["gv5-002", "gv5-011"] {
            let v = load_signed_v5_vector(env!("CARGO_MANIFEST_DIR"), id);
            assert_eq!(v.rev.len(), 40, "{id}: pin must be a full commit");
            assert_eq!(v.sha256_hex.len(), 64);
            assert!(v.json.get("expected").is_some(), "{id}: no expected block");
        }
    }
}
