//! The trust root that certificate checks chain to. Always explicit on the
//! MKTd02 path: a built-in key named with `--trust-root`, or a PEM file named
//! with `--trust-root-pem`. The receipt's own `trust_root_key_id` never selects
//! a key; it is recorded and compared ([`TrustRoot::mismatch`]).

use anyhow::{anyhow, Result};
use base64::Engine;
use zombie_core::nns_keys;

use crate::report::{TrustRootMismatch, TrustRootUsed};
use crate::v2_certificate::extract_der_public_key;

/// A resolved IC root public key (DER) and how it was identified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustRoot {
    id: String,
    source: &'static str,
    der: Vec<u8>,
}

impl TrustRoot {
    /// A built-in NNS root key from `zombie_core::nns_keys` (e.g. `mainnet`).
    pub fn built_in(id: &str) -> Result<Self> {
        let key = nns_keys::lookup_key(id).ok_or_else(|| {
            let known: Vec<&str> = nns_keys::MAINNET_KEYS.iter().map(|k| k.id).collect();
            anyhow!(
                "unknown built-in trust root '{}'. Known: {}",
                id,
                known.join(", ")
            )
        })?;
        Ok(TrustRoot {
            id: key.id.to_string(),
            source: "built-in",
            der: key.der_bytes.to_vec(),
        })
    }

    /// A root key from a PEM `PUBLIC KEY` block holding the DER-encoded
    /// BLS12-381 key (e.g. a PocketIC root key). Identified as
    /// `pem:<first 16 hex digits of SHA-256(DER)>`.
    pub fn from_pem(pem: &str) -> Result<Self> {
        let mut in_block = false;
        let mut body = String::new();
        for line in pem.lines().map(str::trim) {
            if line.starts_with("-----BEGIN ") {
                if in_block {
                    return Err(anyhow!("PEM: nested BEGIN line"));
                }
                in_block = true;
            } else if line.starts_with("-----END ") {
                if !in_block {
                    return Err(anyhow!("PEM: END line without BEGIN"));
                }
                in_block = false;
                break;
            } else if in_block {
                body.push_str(line);
            }
        }
        if body.is_empty() || in_block {
            return Err(anyhow!("PEM: no complete BEGIN/END block found"));
        }
        let der = base64::engine::general_purpose::STANDARD
            .decode(body)
            .map_err(|e| anyhow!("PEM: invalid base64: {e}"))?;
        extract_der_public_key(&der)
            .map_err(|e| anyhow!("PEM: not an IC BLS12-381 root public key: {e}"))?;
        let digest = zombie_core::sha256(&der);
        Ok(TrustRoot {
            id: format!("pem:{}", &hex::encode(digest)[..16]),
            source: "pem",
            der,
        })
    }

    pub fn from_pem_file(path: &str) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| anyhow!("failed to read trust root PEM '{path}': {e}"))?;
        Self::from_pem(&text).map_err(|e| anyhow!("{path}: {e}"))
    }

    /// Identifier recorded in the facts and compared with the receipt's
    /// `trust_root_key_id`.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// DER-encoded BLS12-381 public key.
    pub fn der(&self) -> &[u8] {
        &self.der
    }

    pub fn fact(&self) -> TrustRootUsed {
        TrustRootUsed {
            id: self.id.clone(),
            source: self.source,
        }
    }

    /// A warning fact when the receipt names a different root than the one used.
    pub fn mismatch(&self, receipt_trust_root_key_id: &str) -> Option<TrustRootMismatch> {
        (receipt_trust_root_key_id != self.id).then(|| TrustRootMismatch {
            receipt_says: receipt_trust_root_key_id.to_string(),
            verification_used: self.id.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mainnet_pem() -> String {
        let b64 = base64::engine::general_purpose::STANDARD.encode(nns_keys::MAINNET_KEY_DER);
        let lines: Vec<&str> = b64
            .as_bytes()
            .chunks(64)
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect();
        format!(
            "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
            lines.join("\n")
        )
    }

    #[test]
    fn mainnet_is_built_in_and_unknown_is_refused() {
        let root = TrustRoot::built_in("mainnet").unwrap();
        assert_eq!(root.id(), "mainnet");
        assert_eq!(root.fact().source, "built-in");
        assert_eq!(root.der(), nns_keys::MAINNET_KEY_DER);
        assert!(TrustRoot::built_in("test-key").is_err());
    }

    #[test]
    fn pem_root_is_identified_by_digest_prefix() {
        let root = TrustRoot::from_pem(&mainnet_pem()).unwrap();
        assert_eq!(root.der(), nns_keys::MAINNET_KEY_DER);
        assert_eq!(root.fact().source, "pem");
        let expected = format!(
            "pem:{}",
            &hex::encode(zombie_core::sha256(nns_keys::MAINNET_KEY_DER))[..16]
        );
        assert_eq!(root.id(), expected);
    }

    #[test]
    fn malformed_pem_is_refused() {
        assert!(TrustRoot::from_pem("no pem here").is_err());
        assert!(
            TrustRoot::from_pem("-----BEGIN PUBLIC KEY-----\n!!!\n-----END PUBLIC KEY-----")
                .is_err()
        );
        let short = base64::engine::general_purpose::STANDARD.encode([0u8; 40]);
        assert!(TrustRoot::from_pem(&format!(
            "-----BEGIN PUBLIC KEY-----\n{short}\n-----END PUBLIC KEY-----"
        ))
        .is_err());
    }

    #[test]
    fn mismatch_is_a_recorded_fact_not_a_selector() {
        let mainnet = TrustRoot::built_in("mainnet").unwrap();
        assert_eq!(mainnet.mismatch("mainnet"), None);
        let pem = TrustRoot::from_pem(&mainnet_pem()).unwrap();
        let m = pem.mismatch("mainnet").unwrap();
        assert_eq!(m.receipt_says, "mainnet");
        assert_eq!(m.verification_used, pem.id());
    }
}
