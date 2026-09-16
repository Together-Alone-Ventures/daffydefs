// ============================================================================
// Recorded guard vectors — ported from the reference implementation
// ============================================================================
//
// Ported verbatim from src/frontend/src/finalize/guardVectors.ts on
// feat/browser-finalize (e660247) in the zd-test-26jul working copy, which is
// retained as an independent reference implementation. Only the replay harness
// differs: rather than re-deriving the arithmetic, each timing vector is pushed
// through this implementation's real evaluateGuard() over synthetic trees, so
// the vectors pin the shipped decision path rather than a parallel copy of it.
//
// Sources of the recorded values (verbatim, not reconstructions):
//   ~/zd-test-26jul/out/guard_report.json        (delta 0.437903414 s, PASS)
//   ~/zd-test-26jul/out/guard_report_final.json  (delta 2.198268403 s, PASS)
//   helper/src/lib.rs:315                        (strict `>` at the threshold)
//   helper/src/lib.rs:1141-1145                  (guard_status matrix)
//
// Certificate parsing and BLS are deliberately not fixtured: a valid BLS
// certificate cannot be fabricated offline, and a stubbed one would prove
// nothing. Those paths are exercised live.

import { describe, expect, it } from "vitest";
import {
  MAX_FINALIZATION_DELAY_NS,
  evaluateGuard,
  guardStatus,
  type GuardStatus,
} from "./guard";
import { TEST_CANISTER, hash32, syntheticTree } from "./guard.fixtures";

const MODULE_HASH = hash32(0x33);
const COMMITMENT = hash32(0xab);

/** Anchor time from the recorded ceremony reports. */
const T_ANCHOR = 1785186969785240182n;

interface GuardVector {
  name: string;
  source: string;
  tModuleHashNs: bigint;
  tCommitmentNs: bigint;
  expectedDelaySecs: number;
  expectedStatus: GuardStatus;
}

const GUARD_VECTORS: GuardVector[] = [
  {
    name: "ceremony guard_report (0.4s delay)",
    source: "out/guard_report.json",
    tModuleHashNs: 1785186970223143596n,
    tCommitmentNs: 1785186969785240182n,
    expectedDelaySecs: 0.437903414,
    expectedStatus: "PASS",
  },
  {
    name: "ceremony guard_report_final (2.2s delay)",
    source: "out/guard_report_final.json",
    tModuleHashNs: 1785187050384456602n,
    tCommitmentNs: 1785187048186188199n,
    expectedDelaySecs: 2.198268403,
    expectedStatus: "PASS",
  },
  {
    name: "exactly at threshold — strict `>` means NOT exceeded",
    source: "helper/src/lib.rs:315",
    tModuleHashNs: T_ANCHOR + MAX_FINALIZATION_DELAY_NS,
    tCommitmentNs: T_ANCHOR,
    expectedDelaySecs: 3600,
    expectedStatus: "PASS",
  },
  {
    name: "one ns past threshold — downgrade, not rejection",
    source: "helper/src/lib.rs:315,1033",
    tModuleHashNs: T_ANCHOR + MAX_FINALIZATION_DELAY_NS + 1n,
    tCommitmentNs: T_ANCHOR,
    expectedDelaySecs: 3600.000000001,
    expectedStatus: "DELAY_EXCEEDED",
  },
  {
    name: "module-hash cert older than commitment — ordering failure",
    source: "helper/src/lib.rs:1016-1019",
    tModuleHashNs: 1785186969785240182n,
    tCommitmentNs: 1785186970223143596n,
    expectedDelaySecs: 0,
    expectedStatus: "FAIL",
  },
];

describe("recorded guard vectors (replayed through evaluateGuard)", () => {
  for (const v of GUARD_VECTORS) {
    it(`${v.name} [${v.source}]`, () => {
      const report = evaluateGuard({
        canisterId: TEST_CANISTER,
        receiptId: "b".repeat(64),
        expectedModuleHash: MODULE_HASH,
        expectedCertifiedData: COMMITMENT,
        moduleHashTree: syntheticTree({
          moduleHash: MODULE_HASH,
          timeNs: v.tModuleHashNs,
        }),
        phaseBTree: syntheticTree({
          certifiedData: COMMITMENT,
          timeNs: v.tCommitmentNs,
        }),
        phaseBTrustOk: true,
        phaseBTrustDetail: "BLS + delegation OK against agent trust anchor",
        moduleHashCertificateBytes: 1576,
        phaseBCertificateBytes: 1024,
      });

      expect(report.guardStatus).toBe(v.expectedStatus);
      // ns→s float conversion: compare within half a nanosecond.
      expect(Math.abs((report.finalizationDelaySecs ?? NaN) - v.expectedDelaySecs)).toBeLessThan(
        5e-10
      );
    });
  }
});

describe("guard_status matrix [helper/src/lib.rs:1141-1145]", () => {
  const matrix: Array<[boolean, boolean, GuardStatus]> = [
    [true, false, "PASS"],
    [true, true, "DELAY_EXCEEDED"],
    [false, false, "FAIL"],
    [false, true, "FAIL"],
  ];

  for (const [ok, delayed, want] of matrix) {
    it(`guardStatus(ok=${ok}, delayExceeded=${delayed}) === ${want}`, () => {
      expect(guardStatus(ok, delayed)).toBe(want);
    });
  }
});
