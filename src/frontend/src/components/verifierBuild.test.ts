import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { SERVED_WASM_SHA256, V3B_INSTRUCTIONS_URL } from "./verifierBuild";

describe("Quick Verify build identity", () => {
  it("displayed WASM SHA-256 equals the served mktd02_verify_bg.wasm", () => {
    const served = readFileSync(resolve(__dirname, "../../public/cvdr-wasm/mktd02_verify_bg.wasm"));
    expect(createHash("sha256").update(served).digest("hex")).toBe(SERVED_WASM_SHA256);
  });

  it("V3B link points at the Demo Pack V3B section", () => {
    const demoPack = readFileSync(resolve(__dirname, "../../../../docs/DEMO_PACK.md"), "utf8");
    expect(demoPack).toContain("## C. Optional V3B: rebuild the profile WASM");
    expect(V3B_INSTRUCTIONS_URL.endsWith("/docs/DEMO_PACK.md#c-optional-v3b-rebuild-the-profile-wasm")).toBe(true);
  });
});
