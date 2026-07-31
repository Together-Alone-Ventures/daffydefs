// ============================================================
// Guard fixtures — synthetic certificate trees
// ============================================================
//
// Direct port of `synthetic_cert` from the Rust guard's test module
// (ICP-Delete-Leaf helper/src/main.rs:1089-1121). Self-contained on purpose:
// no shared corpus, no fixture framework, no cross-repo file loading. These
// exist only to pin the browser guard to the same pass/fail decisions as the
// Rust one for the same inputs.
//
// BLS is NOT exercised here — a synthetic tree cannot be signed by a subnet, so
// G4's trust half is supplied to `evaluateGuard` as a parameter. That mirrors
// the Rust tests' own note: "BLS validation is NOT exercised here (that is the
// live-only G4 path)."
//
// Label ordering matters. agent-js `find_label` (certificate.js:392) does an
// ordered search and gives up once it has looked too far, so sibling labels must
// be sorted: `certified_data` < `module_hash`, and `canister` < `time`. The Rust
// fixture pushes them in the same order.

import { NodeType, type HashTree } from "@dfinity/agent";
import { Principal } from "@dfinity/principal";

const enc = new TextEncoder();

export const leaf = (value: Uint8Array): HashTree =>
  [NodeType.Leaf, value] as unknown as HashTree;

export const labeled = (label: string | Uint8Array, subtree: HashTree): HashTree =>
  [
    NodeType.Labeled,
    typeof label === "string" ? enc.encode(label) : label,
    subtree,
  ] as unknown as HashTree;

export const fork = (left: HashTree, right: HashTree): HashTree =>
  [NodeType.Fork, left, right] as unknown as HashTree;

export const empty = (): HashTree => [NodeType.Empty] as unknown as HashTree;

export const pruned = (hash: Uint8Array): HashTree =>
  [NodeType.Pruned, hash] as unknown as HashTree;

/** LEB128-encode an unsigned time, matching `leb_time` in the Rust fixture. */
export function lebTime(ns: bigint): Uint8Array {
  const out: number[] = [];
  let value = ns;
  do {
    let byte = Number(value & 0x7fn);
    value >>= 7n;
    if (value !== 0n) byte |= 0x80;
    out.push(byte);
  } while (value !== 0n);
  return Uint8Array.from(out);
}

/** A 32-byte hash filled with one repeated byte — the Rust tests' `[0x33; 32]`. */
export const hash32 = (fill: number): Uint8Array => new Uint8Array(32).fill(fill);

export const TEST_CANISTER = Principal.fromUint8Array(Uint8Array.from([1, 2, 3, 4]));

export interface SyntheticCertOptions {
  canister?: Principal;
  certifiedData?: Uint8Array | null;
  moduleHash?: Uint8Array | null;
  timeNs: bigint;
  /** Replace the module_hash leaf with a Pruned node, to exercise Unknown. */
  pruneModuleHash?: boolean;
}

/**
 * Build a synthetic (unsigned) certificate tree for lookup/value tests.
 * Shape: fork(labeled("canister", labeled(<id>, subtree)), labeled("time", …)).
 */
export function syntheticTree(options: SyntheticCertOptions): HashTree {
  const canister = options.canister ?? TEST_CANISTER;

  let subtree: HashTree | null = null;
  const push = (t: HashTree) => {
    subtree = subtree === null ? t : fork(subtree, t);
  };

  if (options.certifiedData) {
    push(labeled("certified_data", leaf(options.certifiedData)));
  }
  if (options.pruneModuleHash) {
    push(labeled("module_hash", pruned(hash32(0xee))));
  } else if (options.moduleHash) {
    push(labeled("module_hash", leaf(options.moduleHash)));
  }

  const canisterSubtree: HashTree = subtree ?? empty();

  return fork(
    labeled("canister", labeled(canister.toUint8Array(), canisterSubtree)),
    labeled("time", leaf(lebTime(options.timeNs)))
  );
}
