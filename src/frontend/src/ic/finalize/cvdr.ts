// ============================================================
// CVDR mapping + export
// ============================================================
//
// Maps the profile canister's `MktdReceiptResponse` (15 fields — see
// src/profile_canister/src/lib.rs:144-161) onto the JSON shape CVDR-Verify
// v0.6.1 reads, and nothing else.
//
// The consuming contract is `FileReceiptV3` in CVDR-Verify
// mktd02/mktd02-verify/src/fetch.rs:160-185. Notes that constrain this file:
//
//   * FileReceipt is an UNTAGGED serde enum (fetch.rs:187-192): V3 is attempted
//     first, and if any V3-required field is missing or ill-typed it silently
//     falls back to V2 — which demands `subnet_id` and therefore fails with a
//     confusing error. Every V3-required field below must always be emitted.
//   * `bls_certificate` and `module_hash_certificate` accept null, a byte array,
//     or a hex string (parse_optional_bytes_field, fetch.rs:354-385). Hex string
//     is what we emit, matching the pre-existing export.
//   * `timestamp` and `deletion_seq` accept a number or a string
//     (parse_u64_field, fetch.rs:315-325). Emitted as strings: both are u64 and
//     would lose precision through JSON numbers.
//   * `record_id` accepts a byte array or a hex string, including "" (empty hex
//     decodes to an empty vec) — parse_record_id_field, fetch.rs:327-352.
//
// EXPORT COMPLETENESS: a finalized v4 receipt carries BOTH certificates.
// `module_hash_certificate` was the field missing from the earlier export and is
// the reason a genuinely-finalized receipt could read as unattested downstream.

export interface CvdrData {
  protocol_version: string;
  receipt_id: string;
  canister_id: string;
  record_id?: string | null;
  pre_state_hash: string;
  post_state_hash: string;
  tombstone_hash: string;
  deletion_event_hash: string;
  certified_commitment: string;
  module_hash: string;
  timestamp: bigint;
  deletion_seq: bigint;
  bls_certificate?: Array<number> | Uint8Array | null;
  trust_root_key_id: string;
  module_hash_certificate?: Array<number> | Uint8Array | null;
}

const bytesToHex = (bytes: Array<number> | Uint8Array): string =>
  Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

/**
 * Unwrap a Candid `opt blob`, which agent-js decodes as `[] | [Uint8Array]`.
 * Returns null for absent so the exported JSON carries an explicit null rather
 * than an empty array (which would decode to `Some(vec![])`, i.e. a *present but
 * empty* certificate — a different and wrong claim).
 */
function unwrapOptBytes(value: unknown): Uint8Array | Array<number> | null {
  if (value === null || value === undefined) return null;
  if (Array.isArray(value)) {
    if (value.length === 0) return null;
    const inner = value[0];
    if (inner instanceof Uint8Array) return inner;
    if (Array.isArray(inner)) return inner as Array<number>;
    // A plain byte array that was not an opt wrapper.
    return value as Array<number>;
  }
  if (value instanceof Uint8Array) return value;
  return null;
}

/**
 * Map a raw `mktd_get_receipt` response onto CvdrData. All 15 fields, including
 * both certificate blobs.
 */
export function mapReceiptToCvdr(r: any): CvdrData {
  const recordIdRaw = r.record_id && r.record_id.length > 0 ? r.record_id : null;
  return {
    protocol_version: r.protocol_version,
    receipt_id: r.receipt_id,
    canister_id:
      typeof r.canister_id === "string" ? r.canister_id : r.canister_id.toText(),
    record_id: recordIdRaw ? bytesToHex(recordIdRaw) : "",
    pre_state_hash: r.pre_state_hash,
    post_state_hash: r.post_state_hash,
    tombstone_hash: r.tombstone_hash,
    deletion_event_hash: r.deletion_event_hash,
    certified_commitment: r.certified_commitment,
    module_hash: r.module_hash,
    timestamp: r.timestamp,
    deletion_seq: r.deletion_seq,
    bls_certificate: unwrapOptBytes(r.bls_certificate),
    trust_root_key_id: r.trust_root_key_id,
    module_hash_certificate: unwrapOptBytes(r.module_hash_certificate),
  };
}

/** A receipt is finalized once both the BLS cert and its trust anchor are set. */
export function isReceiptFinalized(r: any): boolean {
  if (!r) return false;
  const bls = unwrapOptBytes(r.bls_certificate);
  return !!(
    bls &&
    (bls as { length: number }).length > 0 &&
    r.trust_root_key_id &&
    String(r.trust_root_key_id).length > 0
  );
}

export interface CvdrExport {
  protocol_version: string;
  receipt_id: string;
  canister_id: string;
  record_id: string;
  pre_state_hash: string;
  post_state_hash: string;
  tombstone_hash: string;
  deletion_event_hash: string;
  certified_commitment: string;
  module_hash: string;
  timestamp: string;
  deletion_seq: string;
  bls_certificate: string | null;
  trust_root_key_id: string;
  module_hash_certificate: string | null;
  timestamp_iso: string;
}

export function formatTimestampIso(ns: bigint): string {
  try {
    return new Date(Number(ns / 1_000_000n)).toISOString();
  } catch {
    return ns.toString();
  }
}

/** Build the exact JSON object written to disk. */
export function buildCvdrExport(receipt: CvdrData): CvdrExport {
  return {
    protocol_version: receipt.protocol_version,
    receipt_id: receipt.receipt_id,
    canister_id: receipt.canister_id,
    record_id: receipt.record_id ?? "",
    pre_state_hash: receipt.pre_state_hash,
    post_state_hash: receipt.post_state_hash,
    tombstone_hash: receipt.tombstone_hash,
    deletion_event_hash: receipt.deletion_event_hash,
    certified_commitment: receipt.certified_commitment,
    module_hash: receipt.module_hash,
    timestamp: receipt.timestamp.toString(),
    deletion_seq: receipt.deletion_seq.toString(),
    bls_certificate: receipt.bls_certificate ? bytesToHex(receipt.bls_certificate) : null,
    trust_root_key_id: receipt.trust_root_key_id,
    module_hash_certificate: receipt.module_hash_certificate
      ? bytesToHex(receipt.module_hash_certificate)
      : null,
    timestamp_iso: formatTimestampIso(receipt.timestamp),
  };
}

/**
 * Which certificate fields are present. Surfaced in the UI so a user can see —
 * before they walk away — whether the receipt they downloaded is the complete
 * v4 artefact.
 */
export function exportCompleteness(receipt: CvdrData): {
  blsCertificate: boolean;
  moduleHashCertificate: boolean;
  complete: boolean;
} {
  const bls = !!receipt.bls_certificate && (receipt.bls_certificate as { length: number }).length > 0;
  const mh =
    !!receipt.module_hash_certificate &&
    (receipt.module_hash_certificate as { length: number }).length > 0;
  return { blsCertificate: bls, moduleHashCertificate: mh, complete: bls && mh };
}

export function cvdrFileName(receipt: CvdrData): string {
  return `deletion-receipt-${receipt.receipt_id.slice(0, 8)}.json`;
}

export function downloadCvdr(receipt: CvdrData): void {
  const json = JSON.stringify(buildCvdrExport(receipt), null, 2);
  const blob = new Blob([json], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = cvdrFileName(receipt);
  a.click();
  URL.revokeObjectURL(url);
}
