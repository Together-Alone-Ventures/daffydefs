// ============================================================================
// Pre-finalize ops-integrity guard (G1–G5b) — browser port
// ============================================================================
//
// Faithful port of the Rust reference implementation in
// ICP-Delete-Leaf/helper/src/lib.rs (`run_guard`, :878-1081) and its pure
// helpers (`guard_status` :302, `normative_delay_exceeded` :315,
// `lookup_module_hash` :790, `lookup_certified_data` :811, `cert_time_ns` :822).
// Report shape mirrors guard_report.json schema_version "0.2".
//
// NOTE (helper/src/main.rs citations in R1 are stale — main.rs is a 4-line
// shim; the guard lives in helper/src/lib.rs. mktd02/src/guard.rs is a
// different guard entirely, tombstone/init only.)
//
// TRUST MODEL — read before changing anything here.
// This guard is CLIENT-SIDE INTEGRITY for the honest path only. It is not
// enforcement. The profile canister stores both certificate blobs opaquely and
// never parses them (profile_canister/src/lib.rs:703-716); the factory checks
// only per-blob length bounds 1..=4096 (profile_factory/src/lib.rs:47-57,
// :567-568). A hostile client can therefore submit blobs that never passed
// these checks. Archival verdicts are CVDR-Verify's job (V3-A).
// Ruled accepted for the demo; canister-side structural checks and caller
// policy are logged for production hardening.
//
// Verification is performed with agent.readState + Certificate.create ONLY.
// Never use canisterStatus.request(): it hardcodes disableTimeVerification
// (canisterStatus/index.js:87) and swallows lookup failures to null
// (:169-179), both of which would silently defeat this guard.

import { Certificate, Cbor, lookup_path, LookupStatus, type HttpAgent } from "@dfinity/agent";
import { Principal } from "@dfinity/principal";

export const GUARD_REPORT_SCHEMA_VERSION = "0.2";

/// zombie_core::MAX_FINALIZATION_DELAY_NS (zombie-core/src/protocol.rs:13).
/// The ONLY input that can drive DELAY_EXCEEDED. Not configurable, by design.
export const MAX_FINALIZATION_DELAY_NS = 3_600_000_000_000n;

const HASH_LEN = 32;

export type GuardStatus = "PASS" | "FAIL" | "DELAY_EXCEEDED";

export interface CheckResult {
  id: string;
  description: string;
  passed: boolean;
  detail: string;
}

export interface GuardReport {
  schema_version: string;
  guard_status: GuardStatus;
  guard_skipped: boolean;
  checks: CheckResult[];
  provenance: Record<string, string>;
  canister_id: string;
  receipt_id: string | null;
  certified_module_hash: string | null;
  module_hash_cert_time_ns: string | null;
  commitment_cert_time_ns: string | null;
  finalization_delay_secs: number | null;
  max_finalization_delay_ns: string;
  module_hash_certificate_bytes: number;
  phase_b_certificate_bytes: number;
  note: string;
}

const GUARD_NOTE =
  "ops-integrity guard result (S5) — not an attestation verdict; archival verdicts come from CVDR-Verify V3-A";

// ---------------------------------------------------------------------------
// Pure helpers (mirror of the Rust unit-tested helpers)
// ---------------------------------------------------------------------------

/// helper/src/lib.rs:302 — failure dominates delay.
export function guardStatus(ok: boolean, delayExceeded: boolean): GuardStatus {
  if (!ok) return "FAIL";
  if (delayExceeded) return "DELAY_EXCEEDED";
  return "PASS";
}

/// helper/src/lib.rs:315 — NORMATIVE G5b decision, strict `>`.
export function normativeDelayExceeded(deltaNs: bigint): boolean {
  return deltaNs > MAX_FINALIZATION_DELAY_NS;
}

const utf8 = (s: string): Uint8Array => new TextEncoder().encode(s);

const toHex = (bytes: Uint8Array): string =>
  Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

/// Unsigned LEB128 → bigint. /time is leb128-encoded ns since epoch and can
/// exceed Number.MAX_SAFE_INTEGER, so bigint throughout (the Rust reference
/// reads u64; Number would lose ns precision and break G5 comparisons).
function readUnsignedLeb128(bytes: Uint8Array): bigint {
  let result = 0n;
  let shift = 0n;
  for (const byte of bytes) {
    result |= BigInt(byte & 0x7f) << shift;
    if ((byte & 0x80) === 0) return result;
    shift += 7n;
  }
  throw new Error("bad /time leb128: truncated");
}

interface ParsedCertificate {
  tree: unknown;
}

/// helper/src/lib.rs:832 — parse only. Deliberately separate from verification
/// so that G3/G5 lookups still run (and are reported) when G4 fails, exactly
/// as the Rust reference does with parse_certificate + agent.verify.
export function parseCertificate(bytes: Uint8Array): ParsedCertificate {
  return Cbor.decode<ParsedCertificate>(new Uint8Array(bytes).buffer as ArrayBuffer);
}

const principalLabel = (p: Principal): Uint8Array => new Uint8Array(p.toUint8Array());

function lookupLeaf(tree: unknown, path: Uint8Array[]): Uint8Array {
  const result = lookup_path(path as unknown as Array<ArrayBuffer>, tree as never);
  if (result.status !== LookupStatus.Found) {
    throw new LookupError(result.status);
  }
  const value = (result as { value: unknown }).value;
  if (!(value instanceof ArrayBuffer) && !ArrayBuffer.isView(value)) {
    throw new Error("malformed lookup: path resolved to a subtree, not a leaf");
  }
  return value instanceof ArrayBuffer ? new Uint8Array(value) : new Uint8Array((value as ArrayBufferView).buffer);
}

class LookupError extends Error {
  constructor(public readonly status: LookupStatus) {
    super(status);
  }
}

/// helper/src/lib.rs:790 — distinguishes Absent (empty/wrong canister) from
/// Unknown (pruned) and enforces the 32-byte length, as the reference does.
export function lookupModuleHash(tree: unknown, canister: Principal): Uint8Array {
  const path = [utf8("canister"), principalLabel(canister), utf8("module_hash")];
  let leaf: Uint8Array;
  try {
    leaf = lookupLeaf(tree, path);
  } catch (e) {
    if (e instanceof LookupError) {
      if (e.status === LookupStatus.Absent) {
        throw new Error(
          `/canister/${canister.toText()}/module_hash is Absent — canister is empty or wrong canister id`,
        );
      }
      throw new Error(
        `/canister/${canister.toText()}/module_hash is Unknown (pruned) — certificate does not witness the path`,
      );
    }
    throw e;
  }
  if (leaf.length !== HASH_LEN) {
    throw new Error(`module_hash leaf has unexpected length ${leaf.length}`);
  }
  return leaf;
}

/// helper/src/lib.rs:811
export function lookupCertifiedData(tree: unknown, canister: Principal): Uint8Array {
  const path = [utf8("canister"), principalLabel(canister), utf8("certified_data")];
  try {
    return lookupLeaf(tree, path);
  } catch (e) {
    const status = e instanceof LookupError ? e.status : String(e);
    throw new Error(
      `/canister/<id>/certified_data not present in commitment certificate: ${status}`,
    );
  }
}

/// helper/src/lib.rs:822
export function certTimeNs(tree: unknown): bigint {
  let leaf: Uint8Array;
  try {
    leaf = lookupLeaf(tree, [utf8("time")]);
  } catch (e) {
    const status = e instanceof LookupError ? e.status : String(e);
    throw new Error(`/time not found in certificate: ${status}`);
  }
  return readUnsignedLeb128(leaf);
}

// ---------------------------------------------------------------------------
// Certificate acquisition
// ---------------------------------------------------------------------------

/// Anonymous read_state for /canister/<id>/module_hash.
///
/// Anonymous by ruling: the module hash is public state and the read must not
/// depend on the user's delegation. Returns the raw certificate bytes, which
/// are what Phase C stores — so the bytes we verify are the bytes we submit.
export async function fetchModuleHashCertificate(
  anonymousAgent: HttpAgent,
  canister: Principal,
): Promise<{ bytes: Uint8Array; verifiedTree: unknown }> {
  const path = [utf8("canister"), principalLabel(canister), utf8("module_hash")];
  const response = await anonymousAgent.readState(canister, {
    paths: [path as unknown as ArrayBuffer[]],
  });

  if (!anonymousAgent.rootKey) {
    throw new Error("anonymous agent has no root key; cannot verify module-hash certificate");
  }

  // Throws CertificateVerificationError on bad BLS / delegation / range / age.
  // Time verification left ENABLED (5 min default): this certificate is fetched
  // fresh in this call, so a stale one indicates a real problem.
  const verified = await Certificate.create({
    certificate: new Uint8Array(response.certificate).buffer as ArrayBuffer,
    rootKey: anonymousAgent.rootKey,
    canisterId: canister,
  });

  return {
    bytes: new Uint8Array(response.certificate),
    verifiedTree: (verified as unknown as { cert: { tree: unknown } }).cert.tree,
  };
}

// ---------------------------------------------------------------------------
// Guard
// ---------------------------------------------------------------------------

export interface GuardInput {
  /// Agent whose root key is the trust anchor. Anonymous — see ruling.
  anonymousAgent: HttpAgent;
  canister: Principal;
  /// Phase B certificate bytes, exactly as returned by mktd_get_certificate().
  phaseBCertificate: Uint8Array;
  /// The pending receipt's certified commitment (query-derived).
  commitment: Uint8Array;
  /// The receipt's embedded module_hash (query-derived here; the Rust helper
  /// takes it operator-supplied, hence the differing provenance label).
  expectedModuleHash: Uint8Array;
  receiptId: string | null;
}

export interface GuardOutcome {
  report: GuardReport;
  moduleHashCertificate: Uint8Array;
}

/// Port of run_guard (helper/src/lib.rs:878). Check emission order is
/// G1, G2, G4, G3, G5[, G5b] — matching guard_report.json exactly.
export async function runGuard(input: GuardInput): Promise<GuardOutcome> {
  const { anonymousAgent, canister, phaseBCertificate, commitment, expectedModuleHash } = input;
  const checks: CheckResult[] = [];
  let ok = true;

  // Acquire + validate the module-hash certificate (BLS/delegation enforced by
  // Certificate.create; a throw here aborts before any finalize submission).
  const { bytes: mhCertBytes, verifiedTree: mhTree } = await fetchModuleHashCertificate(
    anonymousAgent,
    canister,
  );

  // G1 — exact canister identity + explicit path assertion.
  let certifiedHash: Uint8Array | null = null;
  const g1Description =
    "/canister/<receipt.canister_id>/module_hash present as leaf; path supplied by caller";
  try {
    certifiedHash = lookupModuleHash(mhTree, canister);
    checks.push({
      id: "G1_path_identity",
      description: g1Description,
      passed: true,
      detail: `leaf found for canister ${canister.toText()}`,
    });
  } catch (e) {
    ok = false;
    checks.push({
      id: "G1_path_identity",
      description: g1Description,
      passed: false,
      detail: String(e instanceof Error ? e.message : e),
    });
  }

  // G2 — certified value == expected embedded module_hash.
  if (certifiedHash) {
    const passed = toHex(certifiedHash) === toHex(expectedModuleHash);
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

  // Parse the Phase B certificate independently of verification — the host
  // query is not trusted (G ruling), and G3/G5 must still be reported if G4
  // fails.
  let commitTree: unknown = null;
  let parseError: string | null = null;
  try {
    commitTree = parseCertificate(phaseBCertificate).tree;
  } catch (e) {
    parseError = `certificate CBOR decode failed: ${e instanceof Error ? e.message : String(e)}`;
  }

  // G4 — Phase B certificate under the same trust anchor as the module-hash
  // certificate (same rootKey, same canister range).
  const g4Description =
    "Phase B certificate validates under the same root key and delegation range";
  try {
    if (!anonymousAgent.rootKey) throw new Error("agent has no root key");
    await Certificate.create({
      certificate: new Uint8Array(phaseBCertificate).buffer as ArrayBuffer,
      rootKey: anonymousAgent.rootKey,
      canisterId: canister,
    });
    checks.push({
      id: "G4_same_trust_root",
      description: g4Description,
      passed: true,
      detail: "BLS + delegation OK against agent trust anchor",
    });
  } catch (e) {
    ok = false;
    checks.push({
      id: "G4_same_trust_root",
      description: g4Description,
      passed: false,
      detail: `verification failed: ${e instanceof Error ? e.message : String(e)}`,
    });
  }

  // G3 — certified_data leaf == the pending receipt's commitment.
  const g3Description =
    "Phase B certified_data equals the pending receipt's certified commitment";
  try {
    if (parseError) throw new Error(parseError);
    const certifiedData = lookupCertifiedData(commitTree, canister);
    const passed = toHex(certifiedData) === toHex(commitment);
    if (!passed) ok = false;
    checks.push({
      id: "G3_commitment_match",
      description: g3Description,
      passed,
      detail: passed
        ? `match: ${toHex(certifiedData)}`
        : `MISMATCH: certified ${toHex(certifiedData)} vs pending ${toHex(commitment)}`,
    });
  } catch (e) {
    ok = false;
    checks.push({
      id: "G3_commitment_match",
      description: g3Description,
      passed: false,
      detail: String(e instanceof Error ? e.message : e),
    });
  }

  // G5 — time ordering, and G5b the NORMATIVE delay threshold.
  const g5Description = "module-hash certificate /time >= commitment certificate /time (S4)";
  let tModuleHash: bigint | null = null;
  let tCommitment: bigint | null = null;
  try {
    tModuleHash = certTimeNs(mhTree);
  } catch {
    tModuleHash = null;
  }
  try {
    tCommitment = parseError ? null : certTimeNs(commitTree);
  } catch {
    tCommitment = null;
  }

  let delaySecs: number | null = null;
  let delayExceeded = false;

  if (tModuleHash !== null && tCommitment !== null) {
    const ordered = tModuleHash >= tCommitment;
    if (!ordered) ok = false;
    // Negative delta is an ordering FAILURE (G5), never a delay verdict;
    // saturating_sub mirrors the reference.
    const deltaNs = ordered ? tModuleHash - tCommitment : 0n;
    delaySecs = Number(deltaNs) / 1e9;
    delayExceeded = ordered && normativeDelayExceeded(deltaNs);
    checks.push({
      id: "G5_time_relation",
      description: g5Description,
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
  } else {
    ok = false;
    checks.push({
      id: "G5_time_relation",
      description: g5Description,
      passed: false,
      detail: "could not extract /time from one or both certificates",
    });
  }

  return {
    moduleHashCertificate: mhCertBytes,
    report: {
      schema_version: GUARD_REPORT_SCHEMA_VERSION,
      guard_status: guardStatus(ok, delayExceeded),
      guard_skipped: false,
      checks,
      // Differs from the Rust helper by design: in the browser the expected
      // module hash comes from the pending receipt, not an operator flag.
      provenance: {
        expected_module_hash: "query-derived",
        pending_commitment: "query-derived",
        phase_b_certificate: "query-fetched",
        receipt_id: "query-derived",
      },
      canister_id: canister.toText(),
      receipt_id: input.receiptId,
      certified_module_hash: certifiedHash ? toHex(certifiedHash) : null,
      module_hash_cert_time_ns: tModuleHash === null ? null : tModuleHash.toString(),
      commitment_cert_time_ns: tCommitment === null ? null : tCommitment.toString(),
      finalization_delay_secs: delaySecs,
      max_finalization_delay_ns: MAX_FINALIZATION_DELAY_NS.toString(),
      module_hash_certificate_bytes: mhCertBytes.length,
      phase_b_certificate_bytes: phaseBCertificate.length,
      note: GUARD_NOTE,
    },
  };
}
