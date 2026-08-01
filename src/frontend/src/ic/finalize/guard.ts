// ============================================================
// Pre-finalize ops-integrity guard (G1–G5) — browser implementation
// ============================================================
//
// Semantics copied from the ratified Rust guard, zd-finalize-helper
// (ICP-Delete-Leaf helper/src/main.rs:872-1068). Check ids, ordering, pass
// conditions, detail strings and the status ladder all match, so a browser
// guard report is directly comparable with an F1 guard report for the same
// deletion. Where this file diverges it is only in language mechanics
// (bigint for ns times, exceptions instead of Result).
//
//   G1_path_identity     /canister/<receipt.canister_id>/module_hash present as a
//                        leaf; path supplied by the caller, never discovered.
//   G2_module_hash_value certified module_hash == the receipt's embedded module_hash.
//   G4_same_trust_root   Phase B certificate independently validates (BLS +
//                        delegation range) under the same root key as the
//                        module-hash certificate. The host's query response is
//                        not trusted merely because the host returned it.
//   G3_commitment_match  Phase B certified_data == the pending receipt's
//                        certified commitment.
//   G5_time_relation     t(module-hash cert) >= t(commitment cert). A negative
//                        delta is an ORDERING FAILURE, never a delay verdict.
//   G5b_delay_threshold  delta > MAX_FINALIZATION_DELAY_NS → DELAY_EXCEEDED.
//                        Only evaluated when G5 is ordered.
//
// G4 is evaluated before G3 for the same reason as in the helper: the Phase B
// certificate must be parsed and trusted before its leaves mean anything.

import { Principal } from "@dfinity/principal";
import type { HashTree } from "@dfinity/agent";
import {
  HASH_LEN,
  LookupError,
  bytesEqual,
  certTimeNs,
  lookupCertifiedData,
  lookupModuleHash,
  toHex,
} from "./certs";

/**
 * NORMATIVE finalization-delay threshold: 3_600_000_000_000 ns (1 hour).
 *
 * Source of truth is zombie-core v0.4.1 `protocol.rs:13`
 * (`pub const MAX_FINALIZATION_DELAY_NS: u64 = 3_600_000_000_000;`), which
 * zd-finalize-helper pins and compares against. It is restated here because the
 * browser cannot link the Rust crate; it must not be changed independently of
 * that constant.
 */
export const MAX_FINALIZATION_DELAY_NS = 3_600_000_000_000n;

export const GUARD_REPORT_SCHEMA_VERSION = 1;

/** FAIL beats DELAY_EXCEEDED beats PASS (helper/src/main.rs:300-308). */
export type GuardStatus = "PASS" | "DELAY_EXCEEDED" | "FAIL";

export interface CheckResult {
  id: string;
  description: string;
  passed: boolean;
  detail: string;
}

export interface OperatorDelayWarning {
  thresholdSecs: number;
  exceeded: boolean;
}

export interface GuardReport {
  schemaVersion: number;
  guardStatus: GuardStatus;
  checks: CheckResult[];
  canisterId: string;
  receiptId: string;
  certifiedModuleHash: string | null;
  moduleHashCertTimeNs: string | null;
  commitmentCertTimeNs: string | null;
  finalizationDelaySecs: number | null;
  maxFinalizationDelayNs: string;
  operatorDelayWarning: OperatorDelayWarning | null;
  moduleHashCertificateBytes: number;
  phaseBCertificateBytes: number;
  note: string;
}

export interface GuardInputs {
  /** Derived from the receipt's own canister_id — both certs are read under it. */
  canisterId: Principal;
  receiptId: string;
  /** The receipt's embedded module_hash (G2 expectation). */
  expectedModuleHash: Uint8Array;
  /** The pending receipt's certified commitment (G3 expectation). */
  commitment: Uint8Array;
  moduleHashTree: HashTree;
  phaseBTree: HashTree;
  /**
   * Outcome of independently verifying the Phase B certificate (BLS +
   * delegation range) against the trust anchor — G4. Passed in rather than
   * performed here so the rest of the guard stays pure and fixture-testable.
   */
  phaseBTrustOk: boolean;
  phaseBTrustDetail: string;
  moduleHashCertificateBytes: number;
  phaseBCertificateBytes: number;
  /** NON-NORMATIVE operator warning; never affects guardStatus. */
  warnDelayThresholdSecs?: number;
}

/**
 * Status ladder: failure dominates delay (helper/src/main.rs:300-308).
 *
 * Exported for the vector replay in guard.vectors.test.ts — visibility only,
 * the body is unchanged.
 */
export function guardStatus(ok: boolean, delayExceeded: boolean): GuardStatus {
  if (!ok) return "FAIL";
  if (delayExceeded) return "DELAY_EXCEEDED";
  return "PASS";
}

/** NORMATIVE G5b decision (helper/src/main.rs:313-315). */
export function normativeDelayExceeded(deltaNs: bigint): boolean {
  return deltaNs > MAX_FINALIZATION_DELAY_NS;
}

/** NON-NORMATIVE operator warning (helper/src/main.rs:319-321). */
export function operatorWarningExceeded(deltaNs: bigint, thresholdSecs: number): boolean {
  return deltaNs > BigInt(thresholdSecs) * 1_000_000_000n;
}

/**
 * Evaluate G1–G5 over already-acquired certificate trees.
 *
 * Pure: no network, no clock, no BLS. Every trust-dependent input arrives as a
 * parameter, which is what lets the fixtures drive it.
 */
export function evaluateGuard(inputs: GuardInputs): GuardReport {
  const {
    canisterId,
    receiptId,
    expectedModuleHash,
    commitment,
    moduleHashTree,
    phaseBTree,
    phaseBTrustOk,
    phaseBTrustDetail,
    moduleHashCertificateBytes,
    phaseBCertificateBytes,
    warnDelayThresholdSecs,
  } = inputs;

  const checks: CheckResult[] = [];
  let ok = true;

  // --- G1: exact canister identity + explicit path assertion ---------------
  let certifiedHash: Uint8Array | null = null;
  try {
    certifiedHash = lookupModuleHash(moduleHashTree, canisterId);
    checks.push({
      id: "G1_path_identity",
      description:
        "/canister/<receipt.canister_id>/module_hash present as leaf; path supplied by caller",
      passed: true,
      detail: `leaf found for canister ${canisterId.toText()}`,
    });
  } catch (e) {
    ok = false;
    checks.push({
      id: "G1_path_identity",
      description:
        "/canister/<receipt.canister_id>/module_hash present as leaf; path supplied by caller",
      passed: false,
      detail: e instanceof LookupError ? e.message : String(e),
    });
  }

  // --- G2: certified value == expected embedded module_hash ----------------
  // Only meaningful when G1 produced a leaf, matching the helper's `if let`.
  if (certifiedHash) {
    const passed = bytesEqual(certifiedHash, expectedModuleHash);
    if (!passed) ok = false;
    checks.push({
      id: "G2_module_hash_value",
      description: "certified module_hash equals the receipt's embedded module_hash",
      passed,
      detail: passed
        ? `match: ${toHex(certifiedHash)}`
        : `MISMATCH: certified ${toHex(certifiedHash)} vs expected ${toHex(expectedModuleHash)}`,
    });
  }

  // --- G4: Phase B certificate under the same trust anchor -----------------
  if (!phaseBTrustOk) ok = false;
  checks.push({
    id: "G4_same_trust_root",
    description:
      "Phase B certificate validates under the same root key and delegation range",
    passed: phaseBTrustOk,
    detail: phaseBTrustDetail,
  });

  // --- G3: certified_data leaf == the pending commitment -------------------
  try {
    const certifiedData = lookupCertifiedData(phaseBTree, canisterId);
    const passed = bytesEqual(certifiedData, commitment);
    if (!passed) ok = false;
    checks.push({
      id: "G3_commitment_match",
      description: "Phase B certified_data equals the pending receipt's certified commitment",
      passed,
      detail: passed
        ? `match: ${toHex(certifiedData)}`
        : `MISMATCH: certified ${toHex(certifiedData)} vs pending ${toHex(commitment)}`,
    });
  } catch (e) {
    ok = false;
    checks.push({
      id: "G3_commitment_match",
      description: "Phase B certified_data equals the pending receipt's certified commitment",
      passed: false,
      detail: e instanceof LookupError ? e.message : String(e),
    });
  }

  // --- G5 / G5b: ordering, then the normative delay threshold --------------
  let tModuleHash: bigint | null = null;
  let tCommitment: bigint | null = null;
  try {
    tModuleHash = certTimeNs(moduleHashTree);
  } catch {
    tModuleHash = null;
  }
  try {
    tCommitment = certTimeNs(phaseBTree);
  } catch {
    tCommitment = null;
  }

  let delaySecs: number | null = null;
  let delayExceeded = false;
  let operatorDelayWarning: OperatorDelayWarning | null =
    warnDelayThresholdSecs === undefined
      ? null
      : { thresholdSecs: warnDelayThresholdSecs, exceeded: false };

  if (tModuleHash !== null && tCommitment !== null) {
    const ordered = tModuleHash >= tCommitment;
    if (!ordered) ok = false;

    // Negative delta is an ordering FAILURE, never a delay verdict; the delta is
    // only meaningful — and the thresholds only evaluated — when ordered.
    // Mirrors the helper's `tm.saturating_sub(tc)`: an out-of-order pair reports
    // a delta of 0, and the FAIL comes from `ordered` alone.
    const deltaNs = ordered ? tModuleHash - tCommitment : 0n;
    delaySecs = Number(deltaNs) / 1e9;
    delayExceeded = ordered && normativeDelayExceeded(deltaNs);

    checks.push({
      id: "G5_time_relation",
      description: "module-hash certificate /time >= commitment certificate /time (S4)",
      passed: ordered,
      detail: `t_module_hash=${tModuleHash} ns, t_commitment=${tCommitment} ns, delta=${delaySecs.toFixed(1)}s`,
    });

    if (delayExceeded) {
      checks.push({
        id: "G5b_delay_threshold",
        description:
          "finalization delay within MAX_FINALIZATION_DELAY_NS (zombie-core); beyond it, LateFinalized-style downgrade (S4 recommendation (b))",
        passed: false,
        detail: `delta ${deltaNs} ns exceeds normative MAX_FINALIZATION_DELAY_NS ${MAX_FINALIZATION_DELAY_NS} ns`,
      });
    }

    if (warnDelayThresholdSecs !== undefined) {
      operatorDelayWarning = {
        thresholdSecs: warnDelayThresholdSecs,
        exceeded: ordered && operatorWarningExceeded(deltaNs, warnDelayThresholdSecs),
      };
    }
  } else {
    ok = false;
    checks.push({
      id: "G5_time_relation",
      description: "module-hash certificate /time >= commitment certificate /time (S4)",
      passed: false,
      detail: "could not extract /time from one or both certificates",
    });
  }

  return {
    schemaVersion: GUARD_REPORT_SCHEMA_VERSION,
    guardStatus: guardStatus(ok, delayExceeded),
    checks,
    canisterId: canisterId.toText(),
    receiptId,
    certifiedModuleHash: certifiedHash ? toHex(certifiedHash) : null,
    moduleHashCertTimeNs: tModuleHash === null ? null : tModuleHash.toString(),
    commitmentCertTimeNs: tCommitment === null ? null : tCommitment.toString(),
    finalizationDelaySecs: delaySecs,
    maxFinalizationDelayNs: MAX_FINALIZATION_DELAY_NS.toString(),
    operatorDelayWarning,
    moduleHashCertificateBytes,
    phaseBCertificateBytes,
    note: "ops-integrity guard result (S5) — not an attestation verdict; archival verdicts come from CVDR-Verify V3-A",
  };
}

/**
 * Whether a guard verdict permits submitting Phase C.
 *
 * DELAY_EXCEEDED is a downgrade, not a stop: the helper still finalizes and the
 * downgrade is recorded for the archival verdict. FAIL blocks.
 */
export function guardPermitsFinalize(report: GuardReport): boolean {
  return report.guardStatus !== "FAIL";
}

/** Sanity bound shared with the factory's per-blob check (profile_factory:44). */
export const MAX_CERT_BLOB_BYTES = 4096;

export function checkCertBlob(blob: Uint8Array, name: string): void {
  if (blob.length === 0 || blob.length > MAX_CERT_BLOB_BYTES) {
    throw new Error(
      `InvalidCertificate: ${name} length must be 1..=${MAX_CERT_BLOB_BYTES} bytes (got ${blob.length})`
    );
  }
}

export { HASH_LEN };
