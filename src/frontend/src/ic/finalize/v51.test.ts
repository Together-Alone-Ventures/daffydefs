// mktd02-v5.1 browser handling: the pending receipt carries no module_hash or
// trust_root_key_id, the guard must not require or compare module_hash, and
// the export dispatches v5.1 exactly like the v5 direct-certification line.

import { describe, expect, it } from "vitest";
import { Principal } from "@dfinity/principal";
import { evaluateGuard, guardPermitsFinalize } from "./guard";
import { TEST_CANISTER, hash32, syntheticTree } from "./guard.fixtures";
import {
  PROTOCOL_V5_1,
  buildCvdrExport,
  isDirectCertification,
  isReceiptFinalized,
  mapReceiptToCvdr,
  receiptCertifiedData,
  serializeCvdr,
} from "./cvdr";
import { authorLabel, truncatePrincipal } from "../author";

const T_COMMIT = 1_700_000_000_000_000_000n;
const T_MODULE = T_COMMIT + 10n * 1_000_000_000n;
const EVENT = hash32(0xab);

describe("guard with no pending module_hash (v5.1)", () => {
  const inputs = {
    canisterId: TEST_CANISTER,
    receiptId: "a".repeat(64),
    expectedModuleHash: null,
    expectedCertifiedData: EVENT,
    moduleHashTree: syntheticTree({ moduleHash: hash32(0x33), timeNs: T_MODULE }),
    phaseBTree: syntheticTree({ certifiedData: EVENT, timeNs: T_COMMIT }),
    phaseBTrustOk: true,
    phaseBTrustDetail: "ok",
    moduleHashCertificateBytes: 1576,
    phaseBCertificateBytes: 1024,
  };

  it("passes: absence is not a failure and nothing is compared", () => {
    const report = evaluateGuard(inputs);
    expect(report.guardStatus).toBe("PASS");
    expect(guardPermitsFinalize(report)).toBe(true);
    const g2 = report.checks.find((c) => c.id === "G2_module_hash_value");
    expect(g2?.passed).toBe(true);
    expect(g2?.detail).toMatch(/preflight only/);
    expect(report.certifiedModuleHash).toBe("33".repeat(32));
  });

  it("still fails when the certified leaf itself is missing", () => {
    const report = evaluateGuard({
      ...inputs,
      moduleHashTree: syntheticTree({ timeNs: T_MODULE, pruneModuleHash: true }),
    });
    expect(report.guardStatus).toBe("FAIL");
  });
});

describe("v5.1 receipt dispatch and export", () => {
  const pending = {
    protocol_version: PROTOCOL_V5_1,
    receipt_id: "aa".repeat(32),
    canister_id: "rrkah-fqaaa-aaaaa-aaaaq-cai",
    record_id: new Uint8Array(32).fill(7),
    pre_state_hash: "11".repeat(32),
    post_state_hash: "22".repeat(32),
    tombstone_hash: "33".repeat(32),
    deletion_event_hash: "44".repeat(32),
    certified_commitment: [],
    module_hash: [],
    timestamp: 5n,
    deletion_seq: 1n,
    bls_certificate: [],
    trust_root_key_id: [],
    module_hash_certificate: [],
  };

  it("matches versions exactly", () => {
    expect(isDirectCertification("mktd02-v5.1")).toBe(true);
    expect(isDirectCertification("mktd02-v5")).toBe(true);
    expect(isDirectCertification("mktd02-v5.10")).toBe(false);
    expect(isDirectCertification("mktd02-v5.1 ")).toBe(false);
  });

  it("certifies deletion_event_hash and is not finalized while pending", () => {
    expect(receiptCertifiedData(pending)).toBe("44".repeat(32));
    expect(isReceiptFinalized(pending)).toBe(false);
  });

  it("exports without commitment or absent fields, with numeric counters", () => {
    const cvdr = mapReceiptToCvdr(pending);
    const wire = buildCvdrExport(cvdr);
    expect("certified_commitment" in wire).toBe(false);
    expect("module_hash" in wire).toBe(false);
    expect("trust_root_key_id" in wire).toBe(false);
    const text = serializeCvdr(cvdr);
    expect(text).toContain('"timestamp": 5');
    expect(text).not.toContain("null,\n  \"trust_root_key_id\"");
  });
});

describe("author labels", () => {
  const p = Principal.fromText("rrkah-fqaaa-aaaaa-aaaaq-cai");

  it("labels the signed-in user and truncates everyone else", () => {
    expect(authorLabel(p, p.toText())).toBe("you");
    expect(authorLabel(p, null)).toBe(truncatePrincipal(p));
    expect(authorLabel(p, "aaaaa-aa")).toBe("rrkah...cai");
  });
});
