import { Children, isValidElement, type ReactNode } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import DeletionReceipt from "./DeletionReceipt";
import { serializeCvdr, type CvdrData } from "../ic/finalize/cvdr";

// Exercise the component's actual button handlers without adding a DOM dependency.
// Only state updates are stubbed; both export paths and the serializer are real.
vi.mock("react", async (importOriginal) => ({
  ...await importOriginal<typeof import("react")>(),
  useState: () => [false, vi.fn()],
}));

const receipt: CvdrData = {
  protocol_version: "mktd02-v5",
  receipt_id: "01".repeat(32),
  canister_id: "aaaaa-aa",
  record_id: "",
  pre_state_hash: "02".repeat(32),
  post_state_hash: "03".repeat(32),
  tombstone_hash: "04".repeat(32),
  deletion_event_hash: "05".repeat(32),
  module_hash: "06".repeat(32),
  timestamp: 18446744073709551615n,
  deletion_seq: 9007199254740993n,
  bls_certificate: new Uint8Array([1, 2]),
  module_hash_certificate: new Uint8Array([3, 4]),
  trust_root_key_id: "mainnet",
};

function button(node: ReactNode, label: string): (() => unknown) | undefined {
  for (const child of Children.toArray(node)) {
    if (!isValidElement<{ children?: ReactNode; onClick?: () => unknown }>(child)) continue;
    if (child.type === "button" && child.props.children === label) return child.props.onClick;
    const found = button(child.props.children, label);
    if (found) return found;
  }
}

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("receipt export buttons", () => {
  it("emits exactly the v5 wire fields without presentation fields", () => {
    const text = serializeCvdr(receipt);
    expect(text).not.toContain("timestamp_iso");
    expect(Object.keys(JSON.parse(text)).sort()).toEqual([
      "protocol_version", "receipt_id", "canister_id", "record_id",
      "pre_state_hash", "post_state_hash", "tombstone_hash", "deletion_event_hash",
      "module_hash", "timestamp", "deletion_seq", "bls_certificate",
      "trust_root_key_id", "module_hash_certificate",
    ].sort());
  });

  it.each(["timestamp", "deletion_seq"] as const)("preserves exact u64 numbers for %s", (field) => {
    for (const value of [0n, 9007199254740993n, 18446744073709551615n]) {
      const text = serializeCvdr({ ...receipt, [field]: value });
      expect(text).toContain(`"${field}": ${value},`);
      expect(text).not.toContain(`"${field}": "`);
    }
  });

  it.each([false, true])("copies exact download JSON above 2^53 (clipboard fallback=%s)", async (fallback) => {
    vi.useFakeTimers();
    const writeText = fallback
      ? vi.fn().mockRejectedValue(new Error("clipboard unavailable"))
      : vi.fn().mockResolvedValue(undefined);
    vi.stubGlobal("navigator", { clipboard: { writeText } });
    const textarea = { value: "", select: vi.fn() };
    const anchor = { href: "", download: "", click: vi.fn() };
    const execCommand = vi.fn();
    vi.stubGlobal("document", {
      createElement: (tag: string) => tag === "textarea" ? textarea : anchor,
      body: { appendChild: vi.fn(), removeChild: vi.fn() },
      execCommand,
    });
    let downloaded: Blob | undefined;
    vi.spyOn(URL, "createObjectURL").mockImplementation((blob) => {
      downloaded = blob as Blob;
      return "blob:receipt";
    });
    vi.spyOn(URL, "revokeObjectURL").mockImplementation(() => {});
    const view = DeletionReceipt({
      receipt, profileCanisterId: receipt.canister_id,
      finalizationStatus: "finalized", onDone: vi.fn(),
    });
    const copy = button(view, "Copy to Clipboard");
    const download = button(view, "Download Receipt (JSON)");
    expect(copy).toBeTypeOf("function");
    expect(download).toBeTypeOf("function");
    await expect(copy!()).resolves.toBeUndefined();
    expect(() => download!()).not.toThrow();
    const text = fallback ? textarea.value : writeText.mock.calls[0][0];
    expect(text).toBe(serializeCvdr(receipt));
    expect(text).toBe(await downloaded!.text());
    expect(text).toMatch(/"timestamp": 18446744073709551615[,\n]/);
    expect(text).toMatch(/"deletion_seq": 9007199254740993[,\n]/);
    expect(text).not.toMatch(/"(?:timestamp|deletion_seq)": "/);
    // Parsing only checks valid JSON; numeric precision is asserted on raw text above.
    expect(() => JSON.parse(text)).not.toThrow();
    expect(anchor.click).toHaveBeenCalledOnce();
    if (fallback) expect(execCommand).toHaveBeenCalledWith("copy");
  });

  it.each(["timestamp", "deletion_seq"] as const)("retains the u64 bound for %s", (field) => {
    for (const value of [-1n, 18446744073709551616n]) {
      expect(() => serializeCvdr({ ...receipt, [field]: value })).toThrow(`${field} outside u64`);
    }
  });
});
