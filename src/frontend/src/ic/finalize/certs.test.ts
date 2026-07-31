// ============================================================
// Delegation canister-range vectors — both IC layouts
// ============================================================
//
// checkDelegationRange never verifies signatures, so a synthetic certificate is
// enough to pin its behaviour: it only CBOR-decodes and walks labelled paths.
// That lets both layouts be covered offline.
//
// The shapes and the range encoding below were taken from real mainnet
// certificates on subnet jtdsg-…-nqe:
//
//   old: /subnet/<subnet_id>/canister_ranges      -> CBOR [[start, end], ...]
//   new: /canister_ranges/<subnet_id>/<shard>     -> CBOR [[start, end], ...]
//
// Certificates archived in the W5 ceremony receipt use the new layout, which
// agent-js 2.4.1's own check_canister_ranges cannot read.

import { describe, expect, it } from "vitest";
import { Cbor } from "@dfinity/agent";
import { Principal } from "@dfinity/principal";
import { checkDelegationRange } from "./certs";
import { fork, labeled, leaf } from "./guard.fixtures";

const SUBNET = Principal.fromText(
  "jtdsg-3h6gi-hs7o5-z2soi-43w3z-soyl3-ajnp3-ekni5-sw553-5kw67-nqe"
);
const IN_RANGE = Principal.fromText("y5izv-byaaa-aaaaj-qsdfq-cai");
const OUT_OF_RANGE = Principal.fromText("rdmx6-jaaaa-aaaaa-aaadq-cai");

// The real range witnessed for this subnet.
const RANGE_START = Uint8Array.from([0, 0, 0, 0, 1, 0x30, 0, 0, 1, 1]);
const RANGE_END = Uint8Array.from([0, 0, 0, 0, 1, 0x3f, 0xff, 0xff, 1, 1]);

const rangesLeaf = (): Uint8Array =>
  new Uint8Array(Cbor.encode([[RANGE_START, RANGE_END]]) as ArrayBuffer);

/** Wrap a delegation tree into a certificate blob shaped like a real one. */
function certificateWithDelegation(delegationTree: unknown): Uint8Array {
  const delegationCert = Cbor.encode({
    tree: delegationTree,
    signature: new Uint8Array(0),
  });
  return new Uint8Array(
    Cbor.encode({
      tree: [0],
      signature: new Uint8Array(0),
      delegation: {
        subnet_id: SUBNET.toUint8Array(),
        certificate: new Uint8Array(delegationCert as ArrayBuffer),
      },
    }) as ArrayBuffer
  );
}

const oldLayout = () =>
  certificateWithDelegation(
    labeled(
      "subnet",
      labeled(SUBNET.toUint8Array(), labeled("canister_ranges", leaf(rangesLeaf())))
    )
  );

const newLayout = () =>
  certificateWithDelegation(
    labeled(
      "canister_ranges",
      labeled(
        SUBNET.toUint8Array(),
        labeled(RANGE_START, leaf(rangesLeaf()))
      )
    )
  );

/** New layout with the ranges split across two shards, only the second matching. */
const newLayoutSharded = () =>
  certificateWithDelegation(
    labeled(
      "canister_ranges",
      labeled(
        SUBNET.toUint8Array(),
        fork(
          labeled(
            Uint8Array.from([0, 0, 0, 0, 1, 0x10, 0, 0, 1, 1]),
            leaf(
              new Uint8Array(
                Cbor.encode([
                  [
                    Uint8Array.from([0, 0, 0, 0, 1, 0x10, 0, 0, 1, 1]),
                    Uint8Array.from([0, 0, 0, 0, 1, 0x1f, 0xff, 0xff, 1, 1]),
                  ],
                ]) as ArrayBuffer
              )
            )
          ),
          labeled(RANGE_START, leaf(rangesLeaf()))
        )
      )
    )
  );

describe("checkDelegationRange", () => {
  it("accepts the old /subnet/<id>/canister_ranges layout", () => {
    const res = checkDelegationRange(oldLayout(), IN_RANGE);
    expect(res.ok).toBe(true);
    expect(res.detail).toContain("/subnet/<id>/canister_ranges");
  });

  it("accepts the new top-level /canister_ranges/<id> layout", () => {
    const res = checkDelegationRange(newLayout(), IN_RANGE);
    expect(res.ok).toBe(true);
    expect(res.detail).toContain("/canister_ranges/<id>");
  });

  it("searches every shard in the new layout", () => {
    const res = checkDelegationRange(newLayoutSharded(), IN_RANGE);
    expect(res.ok).toBe(true);
  });

  it("rejects a canister outside the subnet's ranges — old layout", () => {
    const res = checkDelegationRange(oldLayout(), OUT_OF_RANGE);
    expect(res.ok).toBe(false);
    expect(res.detail).toMatch(/not in range of delegations/);
  });

  it("rejects a canister outside the subnet's ranges — new layout", () => {
    const res = checkDelegationRange(newLayout(), OUT_OF_RANGE);
    expect(res.ok).toBe(false);
  });

  it("fails closed when neither layout is present", () => {
    const res = checkDelegationRange(
      certificateWithDelegation(labeled("time", leaf(Uint8Array.from([1])))),
      IN_RANGE
    );
    expect(res.ok).toBe(false);
    expect(res.detail).toMatch(/could not find canister ranges/i);
  });

  it("treats an undelegated certificate as unrestricted", () => {
    const bytes = new Uint8Array(
      Cbor.encode({ tree: [0], signature: new Uint8Array(0) }) as ArrayBuffer
    );
    const res = checkDelegationRange(bytes, IN_RANGE);
    expect(res.ok).toBe(true);
    expect(res.detail).toMatch(/no delegation/);
  });
});
