// ============================================================
// Certificate acquisition + pure tree inspection
// ============================================================
//
// Browser-side equivalent of the certificate half of zd-finalize-helper
// (ICP-Delete-Leaf helper/src/main.rs). Two responsibilities, kept apart on
// purpose:
//
//   1. IMPURE — acquiring certificates from the network and validating them
//      (BLS + delegation chain) via @dfinity/agent's Certificate.create.
//   2. PURE   — reading leaves out of an already-parsed HashTree.
//
// The split is what makes the G-guard testable: BLS cannot be exercised against
// a synthetic certificate (no subnet key to sign with), exactly as the Rust
// helper's tests note ("BLS validation is NOT exercised here — that is the
// live-only G4 path"). Everything else is a tree lookup, and tree lookups can be
// fixture-driven.
//
// Verified against @dfinity/agent 2.4.1:
//   Certificate.create(...)  certificate.d.ts:82 — calls verify() unconditionally
//   verify()                 certificate.js:181  — BLS over domain_sep('ic-state-root')‖rootHash
//   _checkDelegationAndGetKey certificate.js:224 — delegation cert verified, nesting
//                                                  rejected, check_canister_ranges enforced
//   lookup_path / LookupStatus certificate.d.ts:100,127

import {
  Cbor,
  Certificate,
  CertificateVerificationError,
  NodeType,
  lookup_path,
  lookupResultToBuffer,
  LookupStatus,
  type HashTree,
} from "@dfinity/agent";
import type { HttpAgent } from "@dfinity/agent";
import { Principal } from "@dfinity/principal";

export const HASH_LEN = 32;

/** The one canister id for which agent-js skips its own range check. */
const MANAGEMENT_CANISTER_ID = Principal.fromText("aaaaa-aa");

const textEncoder = new TextEncoder();
const label = (s: string): Uint8Array => textEncoder.encode(s);

/** `/canister/<id>/module_hash` — the path the guard asserts explicitly (G1). */
export function moduleHashPath(canisterId: Principal): Uint8Array[] {
  return [label("canister"), canisterId.toUint8Array(), label("module_hash")];
}

/** `/canister/<id>/certified_data` — the Phase B commitment leaf (G3). */
export function certifiedDataPath(canisterId: Principal): Uint8Array[] {
  return [label("canister"), canisterId.toUint8Array(), label("certified_data")];
}

/** `/time` — present in every IC certificate (G5). */
export function timePath(): Uint8Array[] {
  return [label("time")];
}

export function toHex(bytes: ArrayBuffer | Uint8Array | number[]): string {
  const view =
    bytes instanceof ArrayBuffer ? new Uint8Array(bytes) : Uint8Array.from(bytes as never);
  return Array.from(view)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export function fromHex(hex: string): Uint8Array {
  const s = hex.trim().replace(/^0x/i, "");
  if (s.length % 2 !== 0) throw new Error(`odd-length hex string (${s.length} chars)`);
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) {
    const byte = Number.parseInt(s.slice(i * 2, i * 2 + 2), 16);
    if (Number.isNaN(byte)) throw new Error(`invalid hex at byte ${i}`);
    out[i] = byte;
  }
  return out;
}

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

// ------------------------------------------------------------
// Pure tree lookups
// ------------------------------------------------------------
//
// Error strings deliberately mirror the Rust helper's, so a browser guard
// report reads the same as an F1 guard report for the same failure.

/** Thrown by the pure lookups; carries the guard-facing detail string. */
export class LookupError extends Error {}

// agent-js types `lookup_path`'s path as Array<ArrayBuffer | string>; it accepts
// Uint8Array labels at runtime (find_label compares bytes). Narrow the cast once.
function lookupAt(path: Uint8Array[], tree: HashTree) {
  return lookup_path(path as unknown as Array<ArrayBuffer | string>, tree);
}

/** True for a `[NodeType.Pruned, hash]` node — a witness-free stand-in. */
function isPrunedNode(value: unknown): boolean {
  return Array.isArray(value) && value[0] === NodeType.Pruned;
}

function lookupBuffer(tree: HashTree, path: Uint8Array[]): Uint8Array | undefined {
  const result = lookupAt(path, tree);
  if (result.status !== LookupStatus.Found) return undefined;
  const buf = lookupResultToBuffer(result);
  return buf ? new Uint8Array(buf) : undefined;
}

/**
 * G1 leaf read: `/canister/<id>/module_hash`, with the Absent/Unknown
 * distinction preserved (helper/src/main.rs:785-804).
 *
 * Absent  → canister is empty or the wrong canister id was supplied.
 * Unknown → the path is pruned; this certificate does not witness it.
 */
export function lookupModuleHash(tree: HashTree, canisterId: Principal): Uint8Array {
  const result = lookupAt(moduleHashPath(canisterId), tree);
  switch (result.status) {
    case LookupStatus.Found: {
      const buf = lookupResultToBuffer(result);
      if (!buf) {
        // agent-js diverges from Rust's ic-certification here: a TERMINAL pruned
        // node comes back as Found-with-subtree rather than Unknown (only an
        // INTERMEDIATE pruned node yields Unknown, via find_label). Both mean the
        // same thing — the certificate does not witness the path — so map the
        // terminal case back onto the Rust verdict rather than calling it
        // malformed, which would misreport a pruned certificate as corrupt.
        if (isPrunedNode(result.value)) {
          throw new LookupError(
            `/canister/${canisterId.toText()}/module_hash is Unknown (pruned) — certificate does not witness the path`
          );
        }
        throw new LookupError("malformed lookup for /canister/<id>/module_hash");
      }
      const value = new Uint8Array(buf);
      if (value.length !== HASH_LEN) {
        throw new LookupError(`module_hash leaf has unexpected length ${value.length}`);
      }
      return value;
    }
    case LookupStatus.Absent:
      throw new LookupError(
        `/canister/${canisterId.toText()}/module_hash is Absent — canister is empty or wrong canister id`
      );
    case LookupStatus.Unknown:
      throw new LookupError(
        `/canister/${canisterId.toText()}/module_hash is Unknown (pruned) — certificate does not witness the path`
      );
    default:
      throw new LookupError("malformed lookup for /canister/<id>/module_hash");
  }
}

/** G3 leaf read: `/canister/<id>/certified_data` (helper/src/main.rs:806-814). */
export function lookupCertifiedData(tree: HashTree, canisterId: Principal): Uint8Array {
  const result = lookupAt(certifiedDataPath(canisterId), tree);
  if (result.status !== LookupStatus.Found) {
    throw new LookupError(
      `/canister/<id>/certified_data not present in commitment certificate: ${result.status}`
    );
  }
  const buf = lookupResultToBuffer(result);
  if (!buf) {
    throw new LookupError(
      "/canister/<id>/certified_data not present in commitment certificate: subtree, not leaf"
    );
  }
  return new Uint8Array(buf);
}

/**
 * G5 input: `/time`, LEB128-encoded nanoseconds since epoch
 * (helper/src/main.rs:816-825).
 *
 * Returned as bigint — IC times are ~1.8e18 ns and do not fit in a JS number
 * without losing precision, which would corrupt the ordering comparison.
 */
export function certTimeNs(tree: HashTree): bigint {
  const raw = lookupBuffer(tree, timePath());
  if (!raw) throw new LookupError("/time not found in certificate");
  let value = 0n;
  let shift = 0n;
  let complete = false;
  for (const byte of raw) {
    value |= BigInt(byte & 0x7f) << shift;
    shift += 7n;
    if ((byte & 0x80) === 0) {
      complete = true;
      break;
    }
  }
  if (!complete) throw new LookupError("bad /time leb128: truncated");
  return value;
}

// ------------------------------------------------------------
// Impure: acquisition + trust validation
// ------------------------------------------------------------

// ------------------------------------------------------------
// Delegation canister-range check (G4, explicit)
// ------------------------------------------------------------
//
// WHY THIS IS NOT LEFT TO agent-js.
//
// Certificate.create runs its own range check (certificate.js:240-249) via
// check_canister_ranges, which only ever reads the OLD layout:
//
//     /subnet/<subnet_id>/canister_ranges  ->  CBOR [[start, end], ...]
//
// The IC also emits a NEWER layout, in which that path is Absent and the ranges
// live at top level, sharded:
//
//     /canister_ranges/<subnet_id>/<shard>  ->  CBOR [[start, end], ...]
//
// Both were observed on this subnet: certificates archived in the July 2026 ceremony
// receipt use the new layout, and agent-js 2.4.1 rejects them outright with
// "Could not find canister ranges for subnet". Live certificates currently use
// the old layout and verify fine — but a subnet that switches would break every
// browser finalisation at G4, with a message that looks like a trust failure
// rather than a library gap.
//
// So the range assertion is made here, over both layouts, and the library's
// built-in check is bypassed (see verifyCertificate). Cryptographic verification
// — BLS and the delegation chain — is still done entirely by agent-js.

/** Bytewise lexicographic comparison, the IC's principal ordering. */
function compareBytes(a: Uint8Array, b: Uint8Array): number {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) {
    if (a[i] !== b[i]) return a[i] < b[i] ? -1 : 1;
  }
  return a.length === b.length ? 0 : a.length < b.length ? -1 : 1;
}

/** Collect every leaf value in a subtree (the new layout shards across leaves). */
function collectLeaves(tree: unknown, out: Uint8Array[] = []): Uint8Array[] {
  if (!Array.isArray(tree)) return out;
  switch (tree[0]) {
    case NodeType.Leaf:
      out.push(new Uint8Array(tree[1] as ArrayBufferLike));
      break;
    case NodeType.Labeled:
      collectLeaves(tree[2], out);
      break;
    case NodeType.Fork:
      collectLeaves(tree[1], out);
      collectLeaves(tree[2], out);
      break;
    default:
      break;
  }
  return out;
}

function decodeRanges(leaf: Uint8Array): Array<[Uint8Array, Uint8Array]> {
  const decoded = Cbor.decode(
    (leaf.buffer as ArrayBuffer).slice(leaf.byteOffset, leaf.byteOffset + leaf.byteLength)
  ) as unknown as Array<[ArrayBufferLike, ArrayBufferLike]>;
  if (!Array.isArray(decoded)) return [];
  return decoded.map(([start, end]) => [new Uint8Array(start), new Uint8Array(end)]);
}

export interface RangeCheckResult {
  ok: boolean;
  detail: string;
}

/**
 * Assert that the delegation's subnet is authorised for `canisterId`, reading
 * whichever canister-range layout the certificate uses.
 *
 * A certificate with no delegation is signed directly by the root key and
 * carries no subnet restriction to check.
 */
export function checkDelegationRange(
  certificateBytes: Uint8Array,
  canisterId: Principal
): RangeCheckResult {
  let decoded: any;
  try {
    decoded = Cbor.decode(
      (certificateBytes.buffer as ArrayBuffer).slice(
        certificateBytes.byteOffset,
        certificateBytes.byteOffset + certificateBytes.byteLength
      )
    );
  } catch (e) {
    return { ok: false, detail: `certificate CBOR decode failed: ${String(e)}` };
  }

  const delegation = decoded?.delegation;
  if (!delegation) {
    return {
      ok: true,
      detail: "no delegation — certificate is signed directly by the root key",
    };
  }

  const subnetIdBytes = new Uint8Array(delegation.subnet_id);
  const subnetId = Principal.fromUint8Array(subnetIdBytes);
  const target = canisterId.toUint8Array();

  let delegationTree: HashTree;
  try {
    delegationTree = (Cbor.decode(delegation.certificate) as any).tree;
  } catch (e) {
    return { ok: false, detail: `delegation certificate CBOR decode failed: ${String(e)}` };
  }

  const leaves: Uint8Array[] = [];
  let layout = "";

  // Old layout: a single leaf under /subnet/<id>/canister_ranges.
  const legacy = lookupAt(
    [label("subnet"), subnetIdBytes, label("canister_ranges")],
    delegationTree
  );
  if (legacy.status === LookupStatus.Found) {
    const buf = lookupResultToBuffer(legacy);
    if (buf) {
      leaves.push(new Uint8Array(buf));
      layout = "/subnet/<id>/canister_ranges";
    }
  }

  // New layout: sharded leaves under /canister_ranges/<id>.
  if (leaves.length === 0) {
    const sharded = lookupAt([label("canister_ranges"), subnetIdBytes], delegationTree);
    if (sharded.status === LookupStatus.Found) {
      const found = collectLeaves((sharded as { value: unknown }).value);
      if (found.length > 0) {
        leaves.push(...found);
        layout = "/canister_ranges/<id>";
      }
    }
  }

  if (leaves.length === 0) {
    return {
      ok: false,
      detail: `could not find canister ranges for subnet ${subnetId.toText()} under either /subnet/<id>/canister_ranges or /canister_ranges/<id>`,
    };
  }

  for (const leafBytes of leaves) {
    let ranges: Array<[Uint8Array, Uint8Array]>;
    try {
      ranges = decodeRanges(leafBytes);
    } catch {
      continue;
    }
    for (const [start, end] of ranges) {
      if (compareBytes(start, target) <= 0 && compareBytes(target, end) <= 0) {
        return {
          ok: true,
          detail: `canister ${canisterId.toText()} within subnet ${subnetId.toText()} range (${layout})`,
        };
      }
    }
  }

  return {
    ok: false,
    detail: `canister ${canisterId.toText()} not in range of delegations for subnet ${subnetId.toText()} (${layout})`,
  };
}

export interface AcquiredCertificate {
  /** Raw CBOR bytes — this is what gets submitted to Phase C and exported. */
  bytes: Uint8Array;
  /** Verified certificate; `.cert.tree` feeds the pure lookups. */
  certificate: Certificate;
  tree: HashTree;
}

/**
 * Anonymous `read_state` for `/canister/<id>/module_hash`, then full
 * verification against the IC root key.
 *
 * Anonymous by design: the module hash is public subnet state and needs no
 * delegated authority to read. The caller passes an agent whose root key is
 * already resolved (mainnet: baked in; local: after fetchRootKey()).
 *
 * Throws CertificateVerificationError if BLS or the delegation chain fails —
 * that failure is the trust half of G4 for this certificate.
 */
export async function fetchModuleHashCertificate(
  agent: HttpAgent,
  canisterId: Principal
): Promise<AcquiredCertificate> {
  const path = moduleHashPath(canisterId);
  const response = await agent.readState(canisterId, {
    paths: [path as unknown as ArrayBuffer[]],
  });
  const bytes = new Uint8Array(response.certificate);
  const certificate = await verifyCertificate(agent, bytes, canisterId);
  return { bytes, certificate, tree: certificate.cert.tree };
}

/**
 * Verify an arbitrary certificate blob against the agent's root key for a given
 * canister. Used both for the module-hash certificate above and — independently
 * — for the Phase B certificate returned by the profile canister's query, which
 * the guard does not trust just because the host handed it over.
 */
export async function verifyCertificate(
  agent: HttpAgent,
  bytes: Uint8Array,
  canisterId: Principal
): Promise<Certificate> {
  const rootKey = agent.rootKey;
  if (!rootKey) {
    throw new Error(
      "agent has no root key — call fetchRootKey() on a local replica before verifying"
    );
  }

  // Passing the management canister id makes agent-js skip its own (old-layout
  // only) canister-range check — certificate.js:240 gates that check on exactly
  // this comparison. Everything else it does is unchanged: tree reconstruction,
  // delegation-certificate verification, no-nesting, and the BLS signature over
  // domain_sep('ic-state-root') ‖ rootHash.
  //
  // The range assertion is then made explicitly by checkDelegationRange, which
  // understands both layouts. Skipping the library's check NEVER weakens the
  // guard: G4 fails unless our own check passes.
  const certificate = await Certificate.create({
    certificate: bytes.buffer.slice(
      bytes.byteOffset,
      bytes.byteOffset + bytes.byteLength
    ) as ArrayBuffer,
    rootKey: rootKey as ArrayBuffer,
    canisterId: MANAGEMENT_CANISTER_ID,
  });

  const range = checkDelegationRange(bytes, canisterId);
  if (!range.ok) {
    throw new CertificateVerificationError(range.detail);
  }

  return certificate;
}
