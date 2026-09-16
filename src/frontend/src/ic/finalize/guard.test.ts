// ============================================================
// Guard vectors — browser guard vs the ratified Rust semantics
// ============================================================
//
// Minimum vector set, copied from the Rust guard's own tests
// (ICP-Delete-Leaf helper/src/main.rs:1074-1400):
//
//   1. valid pair                → PASS, all checks pass
//   2. wrong module hash         → G2 fails  → FAIL
//   3. wrong certified commitment→ G3 fails  → FAIL
//   4. ordering negative         → G5 fails  → FAIL   (t_mh < t_commit)
//   + path negative              → G1 Absent/Unknown  → FAIL
//   + trust negative             → G4 fails  → FAIL
//   + delay classification       → DELAY_EXCEEDED at the ratified threshold
//
// No shared corpus, no fixture framework — the trees are built inline.

import { describe, expect, it } from "vitest";
import { Principal } from "@dfinity/principal";
import {
  MAX_FINALIZATION_DELAY_NS,
  evaluateGuard,
  guardPermitsFinalize,
  normativeDelayExceeded,
  operatorWarningExceeded,
  type CheckResult,
  type GuardInputs,
  type GuardReport,
} from "./guard";
import { TEST_CANISTER, hash32, syntheticTree } from "./guard.fixtures";
import { certTimeNs, lookupCertifiedData, lookupModuleHash } from "./certs";

const MODULE_HASH = hash32(0x33);
const COMMITMENT = hash32(0xab);
const T_COMMIT = 1_700_000_000_000_000_000n;
const T_MODULE = T_COMMIT + 10n * 1_000_000_000n; // +10s, well inside the threshold

/** A guard input set that passes everything; individual tests perturb one axis. */
function validInputs(overrides: Partial<GuardInputs> = {}): GuardInputs {
  return {
    canisterId: TEST_CANISTER,
    receiptId: "a".repeat(64),
    expectedModuleHash: MODULE_HASH,
    expectedCertifiedData: COMMITMENT,
    moduleHashTree: syntheticTree({ moduleHash: MODULE_HASH, timeNs: T_MODULE }),
    phaseBTree: syntheticTree({ certifiedData: COMMITMENT, timeNs: T_COMMIT }),
    phaseBTrustOk: true,
    phaseBTrustDetail: "BLS + delegation OK against agent trust anchor",
    moduleHashCertificateBytes: 1576,
    phaseBCertificateBytes: 1024,
    ...overrides,
  };
}

const check = (report: GuardReport, id: string): CheckResult | undefined =>
  report.checks.find((c) => c.id === id);

describe("pure tree lookups", () => {
  it("finds the module_hash leaf", () => {
    const tree = syntheticTree({ moduleHash: MODULE_HASH, timeNs: T_MODULE });
    expect(lookupModuleHash(tree, TEST_CANISTER)).toEqual(MODULE_HASH);
  });

  it("reports Absent for a different canister id", () => {
    const tree = syntheticTree({ moduleHash: MODULE_HASH, timeNs: T_MODULE });
    const other = Principal.fromUint8Array(Uint8Array.from([9, 9, 9, 9]));
    expect(() => lookupModuleHash(tree, other)).toThrow(/Absent/);
  });

  it("rejects a module_hash leaf of the wrong length", () => {
    const tree = syntheticTree({ moduleHash: new Uint8Array(16).fill(0x33), timeNs: T_MODULE });
    expect(() => lookupModuleHash(tree, TEST_CANISTER)).toThrow(/unexpected length/);
  });

  it("reports Unknown for a pruned module_hash path", () => {
    const tree = syntheticTree({ timeNs: T_MODULE, pruneModuleHash: true });
    expect(() => lookupModuleHash(tree, TEST_CANISTER)).toThrow(/Unknown \(pruned\)/);
  });

  it("errors when certified_data is absent", () => {
    const tree = syntheticTree({ moduleHash: MODULE_HASH, timeNs: T_MODULE });
    expect(() => lookupCertifiedData(tree, TEST_CANISTER)).toThrow(/not present/);
  });

  it("round-trips /time through LEB128 without precision loss", () => {
    const tree = syntheticTree({ moduleHash: MODULE_HASH, timeNs: T_MODULE });
    expect(certTimeNs(tree)).toBe(T_MODULE);
  });
});

describe("G1–G5 vectors", () => {
  it("1. valid pair → PASS with every check passing", () => {
    const report = evaluateGuard(validInputs());
    expect(report.guardStatus).toBe("PASS");
    expect(report.checks.every((c) => c.passed)).toBe(true);
    expect(report.certifiedModuleHash).toBe("33".repeat(32));
    expect(report.finalizationDelaySecs).toBeCloseTo(10, 6);
    expect(guardPermitsFinalize(report)).toBe(true);
    // No G5b check is emitted unless the threshold is actually exceeded.
    expect(check(report, "G5b_delay_threshold")).toBeUndefined();
  });

  it("2. wrong module hash → G2 fails, status FAIL", () => {
    const report = evaluateGuard(validInputs({ expectedModuleHash: hash32(0x44) }));
    expect(check(report, "G1_path_identity")?.passed).toBe(true);
    expect(check(report, "G2_module_hash_value")?.passed).toBe(false);
    expect(check(report, "G2_module_hash_value")?.detail).toMatch(/MISMATCH/);
    expect(report.guardStatus).toBe("FAIL");
    expect(guardPermitsFinalize(report)).toBe(false);
  });

  it("3. wrong certified commitment → G3 fails, status FAIL", () => {
    const report = evaluateGuard(validInputs({ expectedCertifiedData: hash32(0xcd) }));
    expect(check(report, "G3_certified_data_match")?.passed).toBe(false);
    expect(check(report, "G3_certified_data_match")?.detail).toMatch(/MISMATCH/);
    expect(report.guardStatus).toBe("FAIL");
  });

  it("4. ordering negative → G5 fails and is never reported as a delay", () => {
    const report = evaluateGuard(
      validInputs({
        // Module-hash certificate predates the expectedCertifiedData: impossible ordering.
        moduleHashTree: syntheticTree({
          moduleHash: MODULE_HASH,
          timeNs: T_COMMIT - 5n * 1_000_000_000n,
        }),
      })
    );
    expect(check(report, "G5_time_relation")?.passed).toBe(false);
    expect(report.guardStatus).toBe("FAIL");
    // A negative delta is an ordering failure, never a DELAY_EXCEEDED verdict.
    expect(check(report, "G5b_delay_threshold")).toBeUndefined();
    // Saturating delta, mirroring the helper's `tm.saturating_sub(tc)`.
    expect(report.finalizationDelaySecs).toBe(0);
  });

  it("path negative → G1 Absent when the tree is built under another canister", () => {
    const other = Principal.fromUint8Array(Uint8Array.from([9, 9, 9, 9]));
    const report = evaluateGuard(
      validInputs({
        moduleHashTree: syntheticTree({
          canister: other,
          moduleHash: MODULE_HASH,
          timeNs: T_MODULE,
        }),
      })
    );
    expect(check(report, "G1_path_identity")?.passed).toBe(false);
    expect(check(report, "G1_path_identity")?.detail).toMatch(/Absent/);
    // G2 is not emitted at all when G1 yielded no leaf — same as the helper.
    expect(check(report, "G2_module_hash_value")).toBeUndefined();
    expect(report.guardStatus).toBe("FAIL");
  });

  it("trust negative → G4 fails when the Phase B certificate does not verify", () => {
    const report = evaluateGuard(
      validInputs({
        phaseBTrustOk: false,
        phaseBTrustDetail: "verification failed: Signature verification failed",
      })
    );
    expect(check(report, "G4_same_trust_root")?.passed).toBe(false);
    expect(report.guardStatus).toBe("FAIL");
    expect(guardPermitsFinalize(report)).toBe(false);
  });

  it("missing /time on either certificate → G5 fails", () => {
    const report = evaluateGuard({
      ...validInputs(),
      // A bare empty tree carries no /time leaf.
      phaseBTree: [0] as never,
    });
    expect(check(report, "G5_time_relation")?.passed).toBe(false);
    expect(check(report, "G5_time_relation")?.detail).toMatch(/could not extract/);
    expect(report.guardStatus).toBe("FAIL");
  });
});

describe("delay classification (ratified threshold)", () => {
  it("holds the threshold at zombie-core's 1 hour", () => {
    expect(MAX_FINALIZATION_DELAY_NS).toBe(3_600_000_000_000n);
    expect(normativeDelayExceeded(MAX_FINALIZATION_DELAY_NS)).toBe(false);
    expect(normativeDelayExceeded(MAX_FINALIZATION_DELAY_NS + 1n)).toBe(true);
  });

  it("exactly at the threshold → still PASS", () => {
    const report = evaluateGuard(
      validInputs({
        moduleHashTree: syntheticTree({
          moduleHash: MODULE_HASH,
          timeNs: T_COMMIT + MAX_FINALIZATION_DELAY_NS,
        }),
      })
    );
    expect(report.guardStatus).toBe("PASS");
  });

  it("one nanosecond beyond → DELAY_EXCEEDED, and still permits finalize", () => {
    const report = evaluateGuard(
      validInputs({
        moduleHashTree: syntheticTree({
          moduleHash: MODULE_HASH,
          timeNs: T_COMMIT + MAX_FINALIZATION_DELAY_NS + 1n,
        }),
      })
    );
    expect(report.guardStatus).toBe("DELAY_EXCEEDED");
    expect(check(report, "G5_time_relation")?.passed).toBe(true);
    expect(check(report, "G5b_delay_threshold")?.passed).toBe(false);
    // DELAY_EXCEEDED is a downgrade, not a stop.
    expect(guardPermitsFinalize(report)).toBe(true);
  });

  it("FAIL outranks DELAY_EXCEEDED", () => {
    const report = evaluateGuard(
      validInputs({
        expectedModuleHash: hash32(0x44),
        moduleHashTree: syntheticTree({
          moduleHash: MODULE_HASH,
          timeNs: T_COMMIT + MAX_FINALIZATION_DELAY_NS + 1n,
        }),
      })
    );
    expect(report.guardStatus).toBe("FAIL");
  });

  it("operator warning is non-normative and never changes the verdict", () => {
    expect(operatorWarningExceeded(2_000_000_000n, 1)).toBe(true);
    expect(operatorWarningExceeded(500_000_000n, 1)).toBe(false);
    const report = evaluateGuard(validInputs({ warnDelayThresholdSecs: 1 }));
    expect(report.operatorDelayWarning).toEqual({ thresholdSecs: 1, exceeded: true });
    expect(report.guardStatus).toBe("PASS");
  });
});
