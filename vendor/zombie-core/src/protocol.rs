//! Protocol-level constants shared across the Zombie Delete CVDR system.

/// Normative finalization-delay threshold (G ruling, 15 Jul 2026).
/// delta = t(module_hash_certificate) − t(bls_certificate), in nanoseconds.
/// delta < 0  => ordering FAILURE (never a delay verdict).
/// delta > MAX_FINALIZATION_DELAY_NS => verdict DELAY_EXCEEDED (a downgrade,
/// not receipt rejection), aligned with LateFinalized handling.
/// CVDR-Verify is the authoritative interpreter of this threshold; any helper
/// flag is operator convenience and never alters the protocol verdict.
/// Applies identically to Leaf and Tree mode. No deployment-specific override.
/// This threshold does not strengthen the certificate binding itself; it makes
/// abnormally late finalization explicit to the verifier and in the RTS.
pub const MAX_FINALIZATION_DELAY_NS: u64 = 3_600_000_000_000;

#[cfg(test)]
mod tests {
    use super::MAX_FINALIZATION_DELAY_NS;

    #[test]
    fn max_finalization_delay_is_3600_seconds_in_ns() {
        assert_eq!(MAX_FINALIZATION_DELAY_NS, 3_600 * 1_000_000_000);
    }
}
