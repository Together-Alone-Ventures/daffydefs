// Receipt mapping and lossless v5 JSON export. Candid nat64 remains bigint.
// Historical v4 retains its commitment and decimal-string JSON counters.
export interface CvdrData {
  protocol_version: string;
  receipt_id: string;
  canister_id: string;
  record_id?: string | null;
  pre_state_hash: string;
  post_state_hash: string;
  tombstone_hash: string;
  deletion_event_hash: string;
  certified_commitment?: string;
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
    ...(historicalCommitment(r) === undefined ? {} : { certified_commitment: historicalCommitment(r) }),
    module_hash: r.module_hash,
    timestamp: r.timestamp,
    deletion_seq: r.deletion_seq,
    bls_certificate: unwrapOptBytes(r.bls_certificate),
    trust_root_key_id: r.trust_root_key_id,
    module_hash_certificate: unwrapOptBytes(r.module_hash_certificate),
  };
}

/** Both certificate blobs and the engine trust-root identifier must be present. */
export function isReceiptFinalized(r: any): boolean {
  if (!r) return false;
  const bls = unwrapOptBytes(r.bls_certificate);
  const module = unwrapOptBytes(r.module_hash_certificate);
  return !!(
    bls &&
    (bls as { length: number }).length > 0 &&
    module && module.length > 0 &&
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
  certified_commitment?: string;
  module_hash: string;
  timestamp: string | bigint;
  deletion_seq: string | bigint;
  bls_certificate: string | null;
  trust_root_key_id: string;
  module_hash_certificate: string | null;
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
    ...(receipt.protocol_version === "mktd02-v5" ? {} : { certified_commitment: receipt.certified_commitment }),
    module_hash: receipt.module_hash,
    timestamp: receipt.protocol_version === "mktd02-v5" ? receipt.timestamp : receipt.timestamp.toString(),
    deletion_seq: receipt.protocol_version === "mktd02-v5" ? receipt.deletion_seq : receipt.deletion_seq.toString(),
    bls_certificate: receipt.bls_certificate ? bytesToHex(receipt.bls_certificate) : null,
    trust_root_key_id: receipt.trust_root_key_id,
    module_hash_certificate: receipt.module_hash_certificate
      ? bytesToHex(receipt.module_hash_certificate)
      : null,
  };
}

/**
 * Which certificate fields are present. Surfaced in the UI so a user can see —
 * before they walk away — whether the receipt they downloaded is the complete
 * receipt.
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
  const json = serializeCvdr(receipt);
  const blob = new Blob([json], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = cvdrFileName(receipt);
  a.click();
  URL.revokeObjectURL(url);
}

/** Explicit version dispatch; never synthesize a v5 commitment. */
function historicalCommitment(r: any): string | undefined {
  if (r.protocol_version === "mktd02-v5") return undefined;
  if (!String(r.protocol_version).startsWith("mktd02-v4")) {
    throw new Error(`Unsupported profile receipt version: ${r.protocol_version}`);
  }
  const value = Array.isArray(r.certified_commitment) ? r.certified_commitment[0] : r.certified_commitment;
  if (typeof value !== "string") throw new Error("Historical receipt missing certified_commitment");
  return value;
}

/** Value certified by Phase B, selected from the stored receipt, never the query's claim. */
export function receiptCertifiedData(r: any): string {
  return r.protocol_version === "mktd02-v5" ? r.deletion_event_hash : historicalCommitment(r)!;
}

/** Serialize the flat wire object, emitting validated bigint digits as JSON numbers.
 * No Number conversion, raw-JSON browser extension, or placeholder substitution.
 * Other fields use JSON.stringify's escaping; untrusted strings cannot inject JSON.
 */
export function serializeCvdr(receipt: CvdrData): string {
  historicalCommitment(receipt);
  const wire = buildCvdrExport(receipt);
  return "{\n" + Object.entries(wire).map(([key, value]) => {
    let encoded: string | undefined;
    if (typeof value === "bigint") {
      if (value < 0n || value > 18446744073709551615n) throw new Error(`${key} outside u64`);
      encoded = value.toString(10);
    } else {
      if ((key === "timestamp" || key === "deletion_seq") && receipt.protocol_version === "mktd02-v5") {
        throw new Error(`${key} must remain bigint until serialization`);
      }
      encoded = JSON.stringify(value);
    }
    if (encoded === undefined) throw new Error(`Missing receipt field: ${key}`);
    return `  ${JSON.stringify(key)}: ${encoded}`;
  }).join(",\n") + "\n}";
}
