//! MKTd02 receipt verification (library half of the `mktd02-verify` binary).
//!
//! Verification produces structured facts ([`report`]); presentation lives in
//! the provisional [`render`] module. The OpenChatZD package path stays in the
//! binary crate and reuses [`v2_certificate`].

pub mod diagnostics;
pub mod intake;
pub mod render;
pub mod report;
pub mod trust_root;
pub mod v1_transition;
pub mod v2_certificate;
pub mod v3_module;
pub mod v4_tombstone;
pub mod verify;
