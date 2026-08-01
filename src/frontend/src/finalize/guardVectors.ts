// ============================================================================
// Minimum guard fixtures — copied from the real Rust guard vectors.
// ============================================================================
//
// Sources (verbatim values, not reconstructions):
//   ~/zd-test-26jul/out/guard_report.json        (delta 0.437903414 s, PASS)
//   ~/zd-test-26jul/out/guard_report_final.json  (delta 2.198268403 s, PASS)
//   helper/src/lib.rs:1141-1145                  (guard_status matrix)
//   helper/src/lib.rs:315                        (strict `>` at the threshold)
//
// These pin the pure decision functions — the parts that decide a verdict —
// against recorded reality. Certificate parsing/BLS paths are exercised
// live, not fixtured: fabricating a valid BLS certificate offline is not
// possible, and a stubbed one would prove nothing.

import { MAX_FINALIZATION_DELAY_NS, guardStatus, normativeDelayExceeded } from "./guard";

export interface GuardVector {
  name: string;
  source: string;
  t_module_hash_ns: bigint;
  t_commitment_ns: bigint;
  expected_delay_secs: number;
  expected_status: "PASS" | "FAIL" | "DELAY_EXCEEDED";
}

export const GUARD_VECTORS: GuardVector[] = [
  {
    name: "ceremony guard_report (0.4s delay)",
    source: "out/guard_report.json",
    t_module_hash_ns: 1785186970223143596n,
    t_commitment_ns: 1785186969785240182n,
    expected_delay_secs: 0.437903414,
    expected_status: "PASS",
  },
  {
    name: "ceremony guard_report_final (2.2s delay)",
    source: "out/guard_report_final.json",
    t_module_hash_ns: 1785187050384456602n,
    t_commitment_ns: 1785187048186188199n,
    expected_delay_secs: 2.198268403,
    expected_status: "PASS",
  },
  {
    name: "exactly at threshold — strict `>` means NOT exceeded",
    source: "helper/src/lib.rs:315",
    t_module_hash_ns: 1785186969785240182n + MAX_FINALIZATION_DELAY_NS,
    t_commitment_ns: 1785186969785240182n,
    expected_delay_secs: 3600,
    expected_status: "PASS",
  },
  {
    name: "one ns past threshold — downgrade, not rejection",
    source: "helper/src/lib.rs:315,1033",
    t_module_hash_ns: 1785186969785240182n + MAX_FINALIZATION_DELAY_NS + 1n,
    t_commitment_ns: 1785186969785240182n,
    expected_delay_secs: 3600.000000001,
    expected_status: "DELAY_EXCEEDED",
  },
  {
    name: "module-hash cert older than commitment — ordering failure",
    source: "helper/src/lib.rs:1016-1019",
    t_module_hash_ns: 1785186969785240182n,
    t_commitment_ns: 1785186970223143596n,
    expected_delay_secs: 0,
    expected_status: "FAIL",
  },
];

export interface VectorResult {
  name: string;
  passed: boolean;
  detail: string;
}

/// Replays each vector through the same pure functions runGuard() uses.
/// Pure and dependency-free so it can run in a browser console or via node.
export function runGuardVectorSelfCheck(): VectorResult[] {
  const results: VectorResult[] = [];

  for (const v of GUARD_VECTORS) {
    const ordered = v.t_module_hash_ns >= v.t_commitment_ns;
    const deltaNs = ordered ? v.t_module_hash_ns - v.t_commitment_ns : 0n;
    const delaySecs = Number(deltaNs) / 1e9;
    const delayExceeded = ordered && normativeDelayExceeded(deltaNs);
    const status = guardStatus(ordered, delayExceeded);

    const statusOk = status === v.expected_status;
    // ns→s float conversion: compare within half a nanosecond.
    const delayOk = Math.abs(delaySecs - v.expected_delay_secs) < 5e-10;
    results.push({
      name: v.name,
      passed: statusOk && delayOk,
      detail: `status=${status} (want ${v.expected_status}), delay=${delaySecs}s (want ${v.expected_delay_secs}s) [${v.source}]`,
    });
  }

  // guard_status matrix — helper/src/lib.rs:1141-1145; failure dominates delay.
  const matrix: Array<[boolean, boolean, string]> = [
    [true, false, "PASS"],
    [true, true, "DELAY_EXCEEDED"],
    [false, false, "FAIL"],
    [false, true, "FAIL"],
  ];
  for (const [ok, delayed, want] of matrix) {
    const got = guardStatus(ok, delayed);
    results.push({
      name: `guard_status(ok=${ok}, delay_exceeded=${delayed})`,
      passed: got === want,
      detail: `got ${got}, want ${want} [helper/src/lib.rs:1141-1145]`,
    });
  }

  return results;
}
