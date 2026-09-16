import { receiptCertifiedData } from "./cvdr";
// ============================================================
// Browser finalisation flow — Phase B → read_state → guard → Phase C
// ============================================================
//
// The browser is the finalisation client. This module owns everything after
// Phase A: it never triggers a deletion and has no code path that can. That is
// deliberate — lazy repair on a later visit must resume a finalisation without
// re-asking the user to authorise a deletion they already authorised.
//
// Order of operations, and why:
//
//   1. RECEIPT FIRST. Read the receipt before doing any work. A finalized
//      receipt ends the flow immediately — this is what makes the whole thing
//      idempotent across tab-closes, remounts and retries.
//   2. Phase B query        → certificate + receipt id; v5 binds certified_data to deletion_event_hash.
//   3. Anonymous read_state → /canister/<id>/module_hash certificate.
//   4. G1–G5 guard          → FAIL blocks submission entirely.
//   5. Phase C via factory  → 4-arg finalize_profile_receipt, II-signed.
//   6. RECEIPT-FIRST CONFIRMATION. The submit's return value is not the proof.
//      Re-read the receipt and require both certificates to be present.
//
// F1 (the hosted finalizer) is untouched and remains the production fallback.

import { Cbor, type HttpAgent } from "@dfinity/agent";
import { Principal } from "@dfinity/principal";
import { getError, isOk } from "../agent";
import {
  fetchModuleHashCertificate,
  fromHex,
  verifyCertificate,
} from "./certs";
import {
  checkCertBlob,
  evaluateGuard,
  guardPermitsFinalize,
  type GuardReport,
} from "./guard";
import { isReceiptFinalized, mapReceiptToCvdr, type CvdrData } from "./cvdr";

export type FinalizeStage =
  | "idle"
  | "reading-receipt"
  | "phase-b"
  | "module-hash"
  | "guard"
  | "submitting"
  | "confirming"
  | "finalized"
  | "guard-blocked"
  | "failed";

export type FinalizeStatus =
  | "finalized"
  | "already-finalized"
  | "not-pending"
  | "guard-blocked"
  | "failed";

export interface FinalizeOutcome {
  status: FinalizeStatus;
  receipt: CvdrData | null;
  guard: GuardReport | null;
  error?: string;
}

export interface FinalizeParams {
  profileActor: any;
  factoryActor: any;
  /** Anonymous agent used for read_state — public state needs no delegation. */
  anonAgent: HttpAgent;
  profileCanisterId: string;
  /** Known receipt id; when omitted it is taken from the Phase B response. */
  receiptId?: string;
  onStage?: (stage: FinalizeStage) => void;
  signal?: AbortSignal;
}

// ------------------------------------------------------------
// Bounded retry
// ------------------------------------------------------------

const MAX_ATTEMPTS = 4;
const BASE_DELAY_MS = 600;

class Aborted extends Error {
  constructor() {
    super("aborted");
  }
}

function throwIfAborted(signal?: AbortSignal): void {
  if (signal?.aborted) throw new Aborted();
}

function sleep(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      signal?.removeEventListener("abort", onAbort);
      resolve();
    }, ms);
    const onAbort = () => {
      clearTimeout(timer);
      reject(new Aborted());
    };
    signal?.addEventListener("abort", onAbort, { once: true });
  });
}

/**
 * Retry a read-only step a bounded number of times with exponential backoff.
 *
 * Only ever wraps idempotent reads. The Phase C submit is NOT retried this way —
 * see submitAndConfirm, which re-reads the receipt between attempts so a call
 * that actually landed is never submitted twice.
 */
async function withRetry<T>(
  label: string,
  fn: () => Promise<T>,
  signal?: AbortSignal
): Promise<T> {
  let lastError: unknown;
  for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
    throwIfAborted(signal);
    try {
      return await fn();
    } catch (e) {
      if (e instanceof Aborted) throw e;
      lastError = e;
      if (attempt === MAX_ATTEMPTS) break;
      await sleep(BASE_DELAY_MS * 2 ** (attempt - 1), signal);
    }
  }
  throw new Error(`${label} failed after ${MAX_ATTEMPTS} attempts: ${describe(lastError)}`);
}

function describe(e: unknown): string {
  if (e instanceof Error) return e.message;
  return String(e);
}

// ------------------------------------------------------------
// Double-submit protection
// ------------------------------------------------------------
//
// Keyed by canister+receipt, not by component instance. A React remount, a
// second effect firing, and a user clicking twice all collapse onto the same
// in-flight promise. Entries are removed on settle so a genuine later retry
// after a failure is still possible.

const inFlight = new Map<string, Promise<FinalizeOutcome>>();

function flightKey(canisterId: string, receiptId: string | undefined): string {
  return `${canisterId}:${receiptId ?? "pending"}`;
}

/** Exposed for UI affordances (e.g. disabling a retry button). */
export function isFinalizeInFlight(canisterId: string, receiptId?: string): boolean {
  return inFlight.has(flightKey(canisterId, receiptId));
}

// ------------------------------------------------------------
// Receipt reads
// ------------------------------------------------------------

async function readReceipt(profileActor: any, receiptId: string): Promise<any | null> {
  const result = await profileActor.mktd_get_receipt(receiptId);
  if (Array.isArray(result)) return result.length > 0 ? result[0] : null;
  return result ?? null;
}

// ------------------------------------------------------------
// Main entry point
// ------------------------------------------------------------

/**
 * Finalise a pending receipt, or report that there is nothing to do.
 *
 * Safe to call on every authenticated mount: it is idempotent, deduplicated,
 * and returns `not-pending` when the canister has no pending finalisation.
 */
export function finalizePendingReceipt(params: FinalizeParams): Promise<FinalizeOutcome> {
  const key = flightKey(params.profileCanisterId, params.receiptId);
  const existing = inFlight.get(key);
  if (existing) return existing;

  const run = runFinalize(params).finally(() => {
    inFlight.delete(key);
  });
  inFlight.set(key, run);
  return run;
}

async function runFinalize(params: FinalizeParams): Promise<FinalizeOutcome> {
  const {
    profileActor,
    factoryActor,
    anonAgent,
    profileCanisterId,
    onStage,
    signal,
  } = params;

  const stage = (s: FinalizeStage) => onStage?.(s);

  try {
    const canisterId = Principal.fromText(profileCanisterId);

    // --- 1. Receipt first --------------------------------------------------
    stage("reading-receipt");
    let receiptId = params.receiptId;
    if (receiptId) {
      const existing = await withRetry(
        "mktd_get_receipt",
        () => readReceipt(profileActor, receiptId as string),
        signal
      );
      if (existing && isReceiptFinalized(existing)) {
        stage("finalized");
        return {
          status: "already-finalized",
          receipt: mapReceiptToCvdr(existing),
          guard: null,
        };
      }
    }

    // --- 2. Phase B --------------------------------------------------------
    stage("phase-b");
    const phaseB = await withRetry(
      "mktd_get_certificate",
      async () => {
        const result = await profileActor.mktd_get_certificate();
        if (Array.isArray(result)) return result.length > 0 ? result[0] : null;
        return result ?? null;
      },
      signal
    );

    if (!phaseB) {
      // No pending certificate. Either nothing is pending, or the receipt was
      // already finalized by another client (or by F1).
      const pending = await withRetry(
        "mktd_is_pending",
        () => profileActor.mktd_is_pending(),
        signal
      );
      if (receiptId) {
        const existing = await readReceipt(profileActor, receiptId);
        if (existing && isReceiptFinalized(existing)) {
          stage("finalized");
          return {
            status: "already-finalized",
            receipt: mapReceiptToCvdr(existing),
            guard: null,
          };
        }
        if (existing) {
          stage("failed");
          return {
            status: "failed",
            receipt: mapReceiptToCvdr(existing),
            guard: null,
            error: pending
              ? "canister reports a pending finalisation but returned no Phase B certificate"
              : "receipt is not finalized and no pending certificate is available",
          };
        }
      }
      stage("idle");
      return { status: "not-pending", receipt: null, guard: null };
    }

    receiptId = receiptId ?? phaseB.receipt_id;
    if (!receiptId) {
      throw new Error("Phase B response carried no receipt_id");
    }

    const phaseBCertBytes = toUint8(phaseB.certificate);


    // The receipt is the authority on which canister and which module hash the
    // guard must check — never the caller's ambient state.
    const receipt = await withRetry(
      "mktd_get_receipt",
      () => readReceipt(profileActor, receiptId as string),
      signal
    );
    if (!receipt) {
      throw new Error(`receipt ${receiptId} does not exist on ${profileCanisterId}`);
    }
    if (isReceiptFinalized(receipt)) {
      stage("finalized");
      return {
        status: "already-finalized",
        receipt: mapReceiptToCvdr(receipt),
        guard: null,
      };
    }

    const receiptCanisterId: Principal =
      typeof receipt.canister_id === "string"
        ? Principal.fromText(receipt.canister_id)
        : receipt.canister_id;

    // Same canister identity for both certificates: the receipt's own
    // canister_id must be the canister we are finalising on. If these ever
    // disagree, every downstream path lookup would be checking the wrong tree.
    if (receiptCanisterId.toText() !== canisterId.toText()) {
      stage("failed");
      return {
        status: "failed",
        receipt: mapReceiptToCvdr(receipt),
        guard: null,
        error: `receipt canister_id ${receiptCanisterId.toText()} does not match profile canister ${canisterId.toText()}`,
      };
    }

    const expectedModuleHash = fromHex(receipt.module_hash);
    const expectedCertifiedData = fromHex(receiptCertifiedData(receipt));

    // --- 3. Anonymous read_state for the module hash -----------------------
    stage("module-hash");
    const moduleHashCert = await withRetry(
      "read_state /canister/<id>/module_hash",
      () => fetchModuleHashCertificate(anonAgent, receiptCanisterId),
      signal
    );

    // --- 4. Guard ----------------------------------------------------------
    stage("guard");

    // G4 input: verify the Phase B certificate independently. The host handed it
    // to us over a query; that is not a reason to trust it.
    let phaseBTrustOk = false;
    let phaseBTrustDetail: string;
    let phaseBTree: any = null;
    try {
      const verified = await verifyCertificate(anonAgent, phaseBCertBytes, receiptCanisterId);
      phaseBTree = verified.cert.tree;
      phaseBTrustOk = true;
      phaseBTrustDetail = "BLS + delegation OK against agent trust anchor";
    } catch (e) {
      phaseBTrustDetail = `verification failed: ${describe(e)}`;
      // Still parse the tree if we can, so G3/G5 report something useful rather
      // than cascading into "could not extract /time".
      phaseBTree = tryParseTree(phaseBCertBytes);
    }

    const guard = evaluateGuard({
      canisterId: receiptCanisterId,
      receiptId,
      expectedModuleHash,
      expectedCertifiedData,
      moduleHashTree: moduleHashCert.tree,
      phaseBTree: phaseBTree ?? emptyTree(),
      phaseBTrustOk,
      phaseBTrustDetail,
      moduleHashCertificateBytes: moduleHashCert.bytes.length,
      phaseBCertificateBytes: phaseBCertBytes.length,
    });

    if (!guardPermitsFinalize(guard)) {
      stage("guard-blocked");
      return {
        status: "guard-blocked",
        receipt: mapReceiptToCvdr(receipt),
        guard,
        error: guard.checks
          .filter((c) => !c.passed)
          .map((c) => `${c.id}: ${c.detail}`)
          .join("; "),
      };
    }

    // Match the factory's own per-blob bounds before spending an update call.
    checkCertBlob(phaseBCertBytes, "phase_b_certificate");
    checkCertBlob(moduleHashCert.bytes, "module_hash_certificate");

    // --- 5 + 6. Submit, then confirm from the receipt ----------------------
    return await submitAndConfirm({
      factoryActor,
      profileActor,
      canisterId: receiptCanisterId,
      receiptId,
      phaseBCertBytes,
      moduleHashCertBytes: moduleHashCert.bytes,
      guard,
      stage,
      signal,
    });
  } catch (e) {
    if (e instanceof Aborted) {
      return { status: "failed", receipt: null, guard: null, error: "aborted" };
    }
    stage("failed");
    return { status: "failed", receipt: null, guard: null, error: describe(e) };
  }
}

interface SubmitParams {
  factoryActor: any;
  profileActor: any;
  canisterId: Principal;
  receiptId: string;
  phaseBCertBytes: Uint8Array;
  moduleHashCertBytes: Uint8Array;
  guard: GuardReport;
  stage: (s: FinalizeStage) => void;
  signal?: AbortSignal;
}

/**
 * Submit Phase C and confirm from the receipt.
 *
 * The submit is an update call, so a naive retry could apply it twice. Instead
 * each attempt re-reads the receipt first: if a previous attempt actually landed
 * (or F1 finalised concurrently), the receipt says so and we stop. Only a
 * still-pending receipt is submitted again.
 */
async function submitAndConfirm(params: SubmitParams): Promise<FinalizeOutcome> {
  const {
    factoryActor,
    profileActor,
    canisterId,
    receiptId,
    phaseBCertBytes,
    moduleHashCertBytes,
    guard,
    stage,
    signal,
  } = params;

  let lastError: string | undefined;

  for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
    throwIfAborted(signal);

    // Re-read before every attempt — this is the double-submit guard that
    // matters, because it survives page reloads, not just component remounts.
    const current = await readReceipt(profileActor, receiptId).catch(() => null);
    if (current && isReceiptFinalized(current)) {
      stage("finalized");
      return { status: "finalized", receipt: mapReceiptToCvdr(current), guard };
    }

    stage("submitting");
    try {
      // 4-arg factory proxy: (subject, receipt_id, phase_b_cert, module_hash_cert)
      const result = await factoryActor.finalize_profile_receipt(
        canisterId,
        receiptId,
        phaseBCertBytes,
        moduleHashCertBytes
      );
      if (!isOk(result as any)) {
        const message = getError(result as any);
        // The factory reports an already-finalized receipt as AlreadyExists.
        // That is a success for our purposes; confirm it from the receipt below.
        if (!/AlreadyFinalized/i.test(message)) {
          lastError = message;
        }
      }
    } catch (e) {
      if (e instanceof Aborted) throw e;
      lastError = describe(e);
    }

    // --- Receipt-first confirmation ---------------------------------------
    // The submit's return value is not the proof; the stored receipt is.
    stage("confirming");
    const confirmed = await readReceipt(profileActor, receiptId).catch(() => null);
    if (confirmed && isReceiptFinalized(confirmed)) {
      stage("finalized");
      return { status: "finalized", receipt: mapReceiptToCvdr(confirmed), guard };
    }

    if (attempt < MAX_ATTEMPTS) {
      await sleep(BASE_DELAY_MS * 2 ** (attempt - 1), signal);
    }
  }

  stage("failed");
  const receipt = await readReceipt(profileActor, receiptId).catch(() => null);
  return {
    status: "failed",
    receipt: receipt ? mapReceiptToCvdr(receipt) : null,
    guard,
    error: lastError ?? "finalisation did not complete; receipt is still pending",
  };
}

// ------------------------------------------------------------
// Helpers
// ------------------------------------------------------------

function toUint8(value: unknown): Uint8Array {
  if (value instanceof Uint8Array) return value;
  if (Array.isArray(value)) return Uint8Array.from(value as number[]);
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  throw new Error("expected a byte array");
}

function emptyTree(): any {
  return [0];
}

/**
 * Decode an UNVERIFIED certificate's tree, for diagnostics only.
 *
 * Reached only when G4 has already failed. It never grants trust: the guard
 * report still carries `G4_same_trust_root: passed=false`, which is a FAIL and
 * blocks submission regardless of what G3/G5 then report.
 */
function tryParseTree(bytes: Uint8Array): any {
  try {
    const decoded: any = Cbor.decode(
      (bytes.buffer as ArrayBuffer).slice(
        bytes.byteOffset,
        bytes.byteOffset + bytes.byteLength
      )
    );
    return decoded?.tree ?? null;
  } catch {
    return null;
  }
}
