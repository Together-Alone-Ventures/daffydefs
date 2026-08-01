// ============================================================================
// Browser finalisation — Phase B → anonymous read_state → G1–G5b → Phase C
// ============================================================================
//
// Supersedes the zd-finalizer-service HTTP client (see WIP branch
// wip/f2-service-path-2026-07-31 for the retired service-path code). The
// browser is now the finalisation client: it performs the Phase B query, the
// anonymous read_state for module_hash, the G1–G5b guard, and the 4-arg
// factory finalize using the user's II-delegated agent.
//
// Ordering is load-bearing: Phase B is queried BEFORE the module-hash
// read_state so that G5 (t_module_hash >= t_commitment) holds on the honest
// path. Reversing these two calls would fail G5 for no good reason.
//
// "Finalized" is never inferred from a call return value. It is only ever
// concluded from a fresh canister re-fetch of the receipt carrying BOTH
// certificate fields — receipt-first confirmation.

import { HttpAgent } from "@dfinity/agent";
import { Principal } from "@dfinity/principal";
import { runGuard, type GuardReport } from "./guard";

export type FinalizationStatus =
  | "idle"
  | "submitting"
  | "verifying"
  | "finalizing"
  | "retrying"
  | "finalized"
  | "delayed";

/// At most three submissions per deletion event (one initial + two retries),
/// each bounded by its own deadline. Mirrors the bound the service path had.
const MAX_ATTEMPTS = 3;
const ATTEMPT_DEADLINE_MS = 3 * 60 * 1_000;
const RETRY_BACKOFF_MS = [0, 2_000, 4_000];

const sleep = (ms: number) => new Promise<void>((resolve) => window.setTimeout(resolve, ms));

// ---------------------------------------------------------------------------
// Shape validation — canister responses are decoded Candid, not trusted JSON.
// Everything below narrows explicitly rather than casting.
// ---------------------------------------------------------------------------

function optValue<T>(opt: unknown): T | null {
  return Array.isArray(opt) && opt.length > 0 ? (opt[0] as T) : null;
}

function toBytes(value: unknown, field: string): Uint8Array {
  if (value instanceof Uint8Array) return value;
  if (Array.isArray(value) && value.every((n) => typeof n === "number")) {
    return Uint8Array.from(value as number[]);
  }
  throw new Error(`${field}: expected byte array, got ${Object.prototype.toString.call(value)}`);
}

function toText(value: unknown, field: string): string {
  if (typeof value !== "string") {
    throw new Error(`${field}: expected text, got ${typeof value}`);
  }
  return value;
}

function hexToBytes(hex: string, field: string): Uint8Array {
  if (!/^[0-9a-fA-F]*$/.test(hex) || hex.length % 2 !== 0) {
    throw new Error(`${field}: not valid hex (${hex.length} chars)`);
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

/// A finalized canister receipt carries BOTH certificates and a trust root.
/// This is the single definition of "finalized" used by the UI, by the
/// finalisation loop, and by the unmap invariant.
export function isReceiptFinalized(receipt: unknown): boolean {
  if (!receipt || typeof receipt !== "object") return false;
  const r = receipt as Record<string, unknown>;
  const bls = optValue<unknown>(r.bls_certificate);
  const moduleHashCert = optValue<unknown>(r.module_hash_certificate);
  const trustRoot = typeof r.trust_root_key_id === "string" ? r.trust_root_key_id : "";
  if (bls === null || moduleHashCert === null || trustRoot.length === 0) return false;
  const blsLen = bls instanceof Uint8Array ? bls.length : Array.isArray(bls) ? bls.length : 0;
  const mhLen =
    moduleHashCert instanceof Uint8Array
      ? moduleHashCert.length
      : Array.isArray(moduleHashCert)
        ? moduleHashCert.length
        : 0;
  return blsLen > 0 && mhLen > 0;
}

// ---------------------------------------------------------------------------

export interface FinalizeContext {
  profileActor: any;
  factoryActor: any;
  anonymousAgent: HttpAgent;
  profileCanisterId: string;
  receiptId: string;
  onStatus: (status: FinalizationStatus) => void;
  /// Called with the finalized canister receipt once receipt-first
  /// confirmation succeeds. Never called with an unconfirmed receipt.
  onFinalized: (receipt: unknown) => void;
}

export interface FinalizeResult {
  status: "finalized" | "delayed";
  guardReport: GuardReport | null;
  reason: string;
}

/// Terminal failures must not be retried — a guard mismatch is a statement
/// about the data, and re-submitting identical inputs cannot change it.
class TerminalFinalizationError extends Error {
  constructor(
    message: string,
    public readonly guardReport: GuardReport | null,
  ) {
    super(message);
  }
}

// Double-submit protection across every caller in the app (delete flow,
// mount-time lazy repair, React StrictMode double-invocation). Keyed per
// canister+receipt so two different deletions never share an entry.
const inFlight = new Map<string, Promise<FinalizeResult>>();

export function finalizationInFlight(profileCanisterId: string, receiptId: string): boolean {
  return inFlight.has(`${profileCanisterId}:${receiptId}`);
}

export function runBrowserFinalization(ctx: FinalizeContext): Promise<FinalizeResult> {
  const key = `${ctx.profileCanisterId}:${ctx.receiptId}`;
  const existing = inFlight.get(key);
  if (existing) return existing;

  const run = attemptLoop(ctx).finally(() => {
    inFlight.delete(key);
  });
  inFlight.set(key, run);
  return run;
}

async function attemptLoop(ctx: FinalizeContext): Promise<FinalizeResult> {
  let lastGuardReport: GuardReport | null = null;
  let lastReason = "no attempt completed";

  for (let attempt = 0; attempt < MAX_ATTEMPTS; attempt += 1) {
    ctx.onStatus(attempt === 0 ? "submitting" : "retrying");
    if (RETRY_BACKOFF_MS[attempt] > 0) await sleep(RETRY_BACKOFF_MS[attempt]);

    try {
      const result = await withDeadline(runOnce(ctx), ATTEMPT_DEADLINE_MS);
      lastGuardReport = result.guardReport ?? lastGuardReport;
      if (result.status === "finalized") return result;
      lastReason = result.reason;
    } catch (e) {
      if (e instanceof TerminalFinalizationError) {
        // Guard FAIL and malformed-response errors stop here by design.
        ctx.onStatus("delayed");
        return { status: "delayed", guardReport: e.guardReport, reason: e.message };
      }
      lastReason = e instanceof Error ? e.message : String(e);
      // Deadline / network / service errors fall through to the next bounded
      // attempt. An orphaned in-flight finalize is harmless: Phase C is
      // idempotent and the factory reports AlreadyFinalized, which the next
      // attempt treats as success.
    }
  }

  ctx.onStatus("delayed");
  return { status: "delayed", guardReport: lastGuardReport, reason: lastReason };
}

function withDeadline<T>(work: Promise<T>, ms: number): Promise<T> {
  let timer: number | undefined;
  const deadline = new Promise<never>((_resolve, reject) => {
    timer = window.setTimeout(
      () => reject(new Error(`attempt exceeded ${Math.round(ms / 1000)}s deadline`)),
      ms,
    );
  });
  return Promise.race([work, deadline]).finally(() => {
    if (timer !== undefined) window.clearTimeout(timer);
  }) as Promise<T>;
}

async function runOnce(ctx: FinalizeContext): Promise<FinalizeResult> {
  const canister = Principal.fromText(ctx.profileCanisterId);

  // Short-circuit: already finalized (e.g. a previous attempt landed after we
  // stopped waiting for it). Receipt-first, so this is authoritative.
  const preexisting = await fetchReceipt(ctx, ctx.receiptId);
  if (preexisting && isReceiptFinalized(preexisting)) {
    ctx.onFinalized(preexisting);
    ctx.onStatus("finalized");
    return { status: "finalized", guardReport: null, reason: "already finalized" };
  }

  ctx.onStatus("verifying");

  // --- Phase B (query). Must precede the module-hash read_state (G5).
  const pendingOpt = await ctx.profileActor.mktd_get_certificate();
  const pending = optValue<Record<string, unknown>>(pendingOpt);
  if (!pending) {
    throw new TerminalFinalizationError(
      "no pending certificate available for this receipt",
      null,
    );
  }

  const phaseBReceiptId = toText(pending.receipt_id, "phase B receipt_id");
  if (phaseBReceiptId !== ctx.receiptId) {
    throw new TerminalFinalizationError(
      `pending receipt mismatch: canister reports ${phaseBReceiptId}, expected ${ctx.receiptId}`,
      null,
    );
  }
  const phaseBCertificate = toBytes(pending.certificate, "phase B certificate");
  const commitment = toBytes(pending.certified_commitment, "phase B certified_commitment");

  // Expected module hash comes from the pending receipt itself (query-derived).
  const pendingReceipt = preexisting ?? (await fetchReceipt(ctx, ctx.receiptId));
  if (!pendingReceipt) {
    throw new TerminalFinalizationError(`receipt ${ctx.receiptId} not found on canister`, null);
  }
  const expectedModuleHash = hexToBytes(
    toText((pendingReceipt as Record<string, unknown>).module_hash, "receipt module_hash"),
    "receipt module_hash",
  );

  // --- Anonymous read_state + G1–G5b.
  const { report, moduleHashCertificate } = await runGuard({
    anonymousAgent: ctx.anonymousAgent,
    canister,
    phaseBCertificate,
    commitment,
    expectedModuleHash,
    receiptId: ctx.receiptId,
  });

  // G ruling (16 Jul): DELAY_EXCEEDED is a DOWNGRADE, not a rejection —
  // it proceeds, recorded. Only FAIL refuses to submit.
  // (helper/src/lib.rs:525-551)
  if (report.guard_status === "FAIL") {
    const failed = report.checks.filter((c) => !c.passed).map((c) => `${c.id}: ${c.detail}`);
    throw new TerminalFinalizationError(
      `pre-finalize guard FAILED; refusing to submit — ${failed.join(" | ")}`,
      report,
    );
  }
  if (report.guard_status === "DELAY_EXCEEDED") {
    console.warn(
      "[finalize] DELAY_EXCEEDED: finalization delay exceeds MAX_FINALIZATION_DELAY_NS. " +
        "This is a downgrade, not a rejection — proceeding. CVDR-Verify issues the archival verdict.",
      report,
    );
  }

  // --- Phase C via the factory proxy, signed by the user's II delegation.
  ctx.onStatus("finalizing");
  try {
    const result = await ctx.factoryActor.finalize_profile_receipt(
      canister,
      ctx.receiptId,
      phaseBCertificate,
      moduleHashCertificate,
    );
    if (result && typeof result === "object" && "Err" in result) {
      const err = (result as { Err: Record<string, { message?: string }> }).Err;
      const variant = Object.keys(err)[0] ?? "Unknown";
      const message = err[variant]?.message ?? "";
      // Idempotent: someone (a prior attempt, another tab) already finalized.
      // Fall through to receipt-first confirmation rather than failing.
      if (!(variant === "AlreadyExists" && message.includes("AlreadyFinalized"))) {
        return {
          status: "delayed",
          guardReport: report,
          reason: `factory finalize returned ${variant}: ${message}`,
        };
      }
    }
  } catch (e) {
    return {
      status: "delayed",
      guardReport: report,
      reason: `factory finalize call failed: ${e instanceof Error ? e.message : String(e)}`,
    };
  }

  // --- Receipt-first confirmation. The factory's Ok is NOT the proof.
  const confirmed = await fetchReceipt(ctx, ctx.receiptId);
  if (!confirmed || !isReceiptFinalized(confirmed)) {
    return {
      status: "delayed",
      guardReport: report,
      reason: "finalize submitted but canister receipt does not yet carry both certificates",
    };
  }

  ctx.onFinalized(confirmed);
  ctx.onStatus("finalized");
  return { status: "finalized", guardReport: report, reason: "finalized" };
}

async function fetchReceipt(ctx: FinalizeContext, receiptId: string): Promise<unknown | null> {
  const result = await ctx.profileActor.mktd_get_receipt(receiptId);
  return optValue<unknown>(result);
}
