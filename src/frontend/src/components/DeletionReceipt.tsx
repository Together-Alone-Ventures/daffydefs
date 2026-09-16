import { useState } from "react";
import {
  serializeCvdr,
  cvdrFileName,
  downloadCvdr,
  exportCompleteness,
  formatTimestampIso,
  type CvdrData,
} from "../ic/finalize/cvdr";
import type { GuardReport } from "../ic/finalize/guard";

export type { CvdrData };

interface DeletionReceiptProps {
  receipt: CvdrData;
  profileCanisterId: string;
  finalizationStatus?: "idle" | "finalizing" | "finalized" | "pending" | "blocked";
  guard?: GuardReport | null;
  onDone: () => void;
}

export default function DeletionReceipt({
  receipt,
  profileCanisterId,
  finalizationStatus = "idle",
  guard = null,
  onDone,
}: DeletionReceiptProps) {
  const [copied, setCopied] = useState(false);

  const completeness = exportCompleteness(receipt);

  const handleCopy = async () => {
    const json = serializeCvdr(receipt);
    try {
      await navigator.clipboard.writeText(json);
    } catch {
      // Fallback for browsers without the async clipboard API
      const textArea = document.createElement("textarea");
      textArea.value = json;
      document.body.appendChild(textArea);
      textArea.select();
      document.execCommand("copy");
      document.body.removeChild(textArea);
    }
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const certStatus = (
    present: boolean,
    bytes: Array<number> | Uint8Array | null | undefined
  ): string => {
    if (finalizationStatus === "finalizing") return "Finalization in progress";
    if (present && bytes) return `${Array.from(bytes).length} bytes`;
    if (finalizationStatus === "pending") return "Pending finalization";
    return "Not finalized yet";
  };

  // Deletion-done language is reserved for the Finalized state. Until the
  // receipt-first confirmation lands, the receipt on screen is still being
  // assembled and must not be presented as a completed artefact.
  const isFinalized = finalizationStatus === "finalized";

  const heading = isFinalized
    ? "Deletion complete — receipt ready"
    : finalizationStatus === "pending"
      ? "Still finalising"
      : finalizationStatus === "blocked"
        ? "Finalisation withheld"
        : "Preparing your Deletion Receipt";

  const intro = isFinalized
    ? "DaffyDefs has completed its deletion flow. This Cryptographically Verifiable Deletion Receipt (CVDR) lets you independently verify the certified receipt evidence and the code identity attested at finalisation time."
    : finalizationStatus === "pending"
      ? "Deletion event evidence has been recorded. The certificates that complete the receipt are still being attached — this will finish automatically next time you sign in."
      : "Deletion event evidence has been recorded. The certificates that complete the receipt are being collected and verified now.";

  return (
    <div className="card">
      <h2 style={isFinalized ? { color: "#4ade80" } : undefined}>{heading}</h2>

      {!isFinalized && finalizationStatus !== "pending" && (
        <p style={{ margin: "0 0 1rem", fontWeight: 600 }}>
          Please don't close this window.
        </p>
      )}

      <p style={{ marginBottom: "1rem", color: "#94a3b8" }}>{intro}</p>

      {/* Export completeness — a finalized receipt carries BOTH certificates.
          Downloading one that is missing either would verify as unattested. */}
      {finalizationStatus === "finalized" && !completeness.complete && (
        <div className="card" style={{ borderColor: "#f59e0b", marginBottom: "1rem" }}>
          <p style={{ margin: 0, fontWeight: 600, color: "#f59e0b" }}>
            Incomplete receipt — missing{" "}
            {[
              !completeness.blsCertificate && "bls_certificate",
              !completeness.moduleHashCertificate && "module_hash_certificate",
            ]
              .filter(Boolean)
              .join(" and ")}
            . Verification will not report full attestation.
          </p>
        </div>
      )}

      {finalizationStatus === "blocked" && guard && (
        <div className="card" style={{ borderColor: "#ef4444", marginBottom: "1rem" }}>
          <p style={{ margin: 0, fontWeight: 600, color: "#ef4444" }}>
            Finalization withheld — pre-finalize guard returned {guard.guardStatus}.
          </p>
          <ul style={{ margin: "0.5rem 0 0", paddingLeft: "1.25rem" }}>
            {guard.checks
              .filter((c) => !c.passed)
              .map((c) => (
                <li key={c.id} className="mono" style={{ fontSize: "0.7rem" }}>
                  {c.id}: {c.detail}
                </li>
              ))}
          </ul>
        </div>
      )}

      <div className="receipt-fields">
        <div className="profile-field">
          <span className="field-label">Receipt ID</span>
          <span className="field-value mono" style={{ fontSize: "0.75rem", wordBreak: "break-all" }}>
            {receipt.receipt_id}
          </span>
        </div>

        <div className="profile-field">
          <span className="field-label">Deleted At</span>
          <span className="field-value">{formatTimestampIso(receipt.timestamp)}</span>
        </div>

        <div className="profile-field">
          <span className="field-label">Profile Canister</span>
          <span className="field-value mono">{profileCanisterId}</span>
        </div>

        <div className="profile-field">
          <span className="field-label">Protocol Version</span>
          <span className="field-value">{receipt.protocol_version}</span>
        </div>

        <hr style={{ borderColor: "#334155", margin: "0.75rem 0" }} />

        <div className="profile-field">
          <span className="field-label">Pre-State Hash</span>
          <span className="field-value mono" style={{ fontSize: "0.7rem", wordBreak: "break-all" }}>
            {receipt.pre_state_hash}
          </span>
        </div>

        <div className="profile-field">
          <span className="field-label">Post-State Hash</span>
          <span className="field-value mono" style={{ fontSize: "0.7rem", wordBreak: "break-all" }}>
            {receipt.post_state_hash}
          </span>
        </div>

        <div className="profile-field">
          <span className="field-label">Tombstone Hash</span>
          <span className="field-value mono" style={{ fontSize: "0.7rem", wordBreak: "break-all" }}>
            {receipt.tombstone_hash}
          </span>
        </div>

        <div className="profile-field">
          <span className="field-label">Deletion Event Hash</span>
          <span className="field-value mono" style={{ fontSize: "0.7rem", wordBreak: "break-all" }}>
            {receipt.deletion_event_hash}
          </span>
        </div>

        {receipt.protocol_version !== "mktd02-v5" && <div className="profile-field">
          <span className="field-label">Certified Commitment</span>
          <span className="field-value mono" style={{ fontSize: "0.7rem", wordBreak: "break-all" }}>
            {receipt.certified_commitment}
          </span>
        </div>}

        <div className="profile-field">
          <span className="field-label">Module Hash</span>
          <span className="field-value mono" style={{ fontSize: "0.7rem", wordBreak: "break-all" }}>
            {receipt.module_hash}
          </span>
        </div>

        <div className="profile-field">
          <span className="field-label">Deletion Seq</span>
          <span className="field-value mono">{receipt.deletion_seq.toString()}</span>
        </div>

        <div className="profile-field">
          <span className="field-label">Trust Root Key ID</span>
          <span className="field-value mono" style={{ fontSize: "0.75rem", wordBreak: "break-all" }}>
            {receipt.trust_root_key_id}
          </span>
        </div>

        <div className="profile-field">
          <span className="field-label">BLS Certificate</span>
          <span className="field-value mono" style={{ fontSize: "0.75rem", wordBreak: "break-all" }}>
            {certStatus(completeness.blsCertificate, receipt.bls_certificate)}
          </span>
        </div>

        <div className="profile-field">
          <span className="field-label">Module Hash Certificate</span>
          <span className="field-value mono" style={{ fontSize: "0.75rem", wordBreak: "break-all" }}>
            {certStatus(completeness.moduleHashCertificate, receipt.module_hash_certificate)}
          </span>
        </div>
      </div>

      {/* Export affordances are withheld until Finalized. A receipt exported
          mid-flight is missing a certificate and would not verify as attested,
          so offering it as a normal download invites a worthless file being
          kept as proof. The pending (lazy-repair) state keeps a secondary,
          explicitly-labelled escape hatch; every other state offers none.
          Copy is gated identically — it emits the same bytes as Download. */}
      <div className="button-row" style={{ marginTop: "1.5rem" }}>
        {isFinalized && (
          <>
            <button className="button button-primary" onClick={() => downloadCvdr(receipt)}>
              Download Receipt (JSON)
            </button>
            <button className="button button-secondary" onClick={handleCopy}>
              {copied ? "Copied!" : "Copy to Clipboard"}
            </button>
          </>
        )}
        {finalizationStatus === "pending" && (
          <button className="button button-secondary" onClick={() => downloadCvdr(receipt)}>
            Download incomplete copy
          </button>
        )}
        <button className="button button-secondary" onClick={onDone}>
          Done
        </button>
      </div>

      {isFinalized && (
        <p className="muted" style={{ fontSize: "0.75rem", marginTop: "0.5rem" }}>
          Saves as {cvdrFileName(receipt)}
        </p>
      )}
      {finalizationStatus === "pending" && (
        <p className="muted" style={{ fontSize: "0.75rem", marginTop: "0.5rem" }}>
          This copy is incomplete — it is missing a certificate and will not
          verify as attested. Sign in again to finish the receipt, then download
          the complete file.
        </p>
      )}
    </div>
  );
}
