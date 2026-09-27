import { describe, expect, it } from "vitest";
import { buildCvdrExport, isReceiptFinalized, mapReceiptToCvdr, unwrapOptText } from "./cvdr";

const base = {
  protocol_version: "mktd02-v5",
  receipt_id: "aa".repeat(32),
  canister_id: "rrkah-fqaaa-aaaaa-aaaaq-cai",
  record_id: new Uint8Array(32).fill(7),
  pre_state_hash: "11".repeat(32),
  post_state_hash: "22".repeat(32),
  tombstone_hash: "33".repeat(32),
  deletion_event_hash: "44".repeat(32),
  certified_commitment: [],
  timestamp: 1n,
  deletion_seq: 1n,
};

describe("unwrapOptText", () => {
  it("unwraps opt text and plain text, and treats empty opt as absent", () => {
    expect(unwrapOptText(["x"])).toBe("x");
    expect(unwrapOptText("x")).toBe("x");
    expect(unwrapOptText([])).toBeUndefined();
    expect(unwrapOptText(undefined)).toBeUndefined();
  });
});

describe("pending receipt with absent finalisation fields", () => {
  const pending = {
    ...base,
    module_hash: [],
    trust_root_key_id: [],
    bls_certificate: [],
    module_hash_certificate: [],
  };

  it("maps without placeholders and is not finalized", () => {
    const cvdr = mapReceiptToCvdr(pending);
    expect(cvdr.module_hash).toBeUndefined();
    expect(cvdr.trust_root_key_id).toBeUndefined();
    expect(cvdr.bls_certificate).toBeNull();
    expect(isReceiptFinalized(pending)).toBe(false);
  });

  it("omits the absent keys from the export", () => {
    const wire = buildCvdrExport(mapReceiptToCvdr(pending));
    expect("module_hash" in wire).toBe(false);
    expect("trust_root_key_id" in wire).toBe(false);
  });
});

describe("historical v5 receipt with opt-wrapped fields", () => {
  it("keeps module_hash and an empty pending trust_root_key_id unchanged", () => {
    const cvdr = mapReceiptToCvdr({
      ...base,
      module_hash: ["55".repeat(32)],
      trust_root_key_id: [""],
      bls_certificate: [],
      module_hash_certificate: [],
    });
    const wire = buildCvdrExport(cvdr);
    expect(wire.module_hash).toBe("55".repeat(32));
    expect(wire.trust_root_key_id).toBe("");
  });
});
