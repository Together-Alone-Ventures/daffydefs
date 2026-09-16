import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import FinalizationProgress from "./FinalizationProgress";
import DeletionReceipt from "./DeletionReceipt";
import type { CvdrData } from "../ic/finalize/cvdr";

describe("finalization progress", () => {
  it("shows the spinner beside the waiting wording", () => {
    const html = renderToStaticMarkup(<FinalizationProgress status="finalizing" />);
    expect(html).toContain('class="finalization-spinner"');
    expect(html).toContain('role="status"');
    expect(html).toContain("Preparing your Deletion Receipt");
    expect(html).toContain("close this window.");
  });

  it.each(["idle", "pending", "blocked", "finalized"] as const)("removes the indicator in %s state", (status) => {
    expect(renderToStaticMarkup(<FinalizationProgress status={status} />)).toBe("");
  });

  it("shows the finalized receipt without a progress indicator", () => {
    const receipt: CvdrData = {
      protocol_version: "mktd02-v5", receipt_id: "01".repeat(32),
      canister_id: "aaaaa-aa", record_id: "", pre_state_hash: "02".repeat(32),
      post_state_hash: "03".repeat(32), tombstone_hash: "04".repeat(32),
      deletion_event_hash: "05".repeat(32), module_hash: "06".repeat(32),
      timestamp: 1n, deletion_seq: 1n, bls_certificate: new Uint8Array([1]),
      module_hash_certificate: new Uint8Array([2]), trust_root_key_id: "mainnet",
    };
    const html = renderToStaticMarkup(<>
      <FinalizationProgress status="finalized" />
      <DeletionReceipt receipt={receipt} profileCanisterId="aaaaa-aa"
        finalizationStatus="finalized" onDone={() => {}} />
    </>);
    expect(html).toContain("Deletion complete — receipt ready");
    expect(html).not.toContain("finalization-spinner");
  });
});
