import { useState } from "react";
import {
  buildCvdrExport,
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
    const json = JSON.stringify(buildCvdrExport(receipt), null, 2);
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

  return (
    <div className="card">
      <h2 style={{ color: "#4ade80" }}>Profile Deleted — Deletion Receipt</h2>

      <p style={{ marginBottom: "1rem", color: "#94a3b8" }}>
        Your personal data has been cryptographically tombstoned. This
        Cryptographically Verifiable Deletion Receipt (CVDR) is your proof that
        the deletion took place. You can independently verify it at any time
        using the hashes below and the ICP subnet's public key.
      </p>

      {/* Export completeness — a finalized v4 receipt carries BOTH certificates.
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

        <div className="profile-field">
          <span className="field-label">Certified Commitment</span>
          <span className="field-value mono" style={{ fontSize: "0.7rem", wordBreak: "break-all" }}>
            {receipt.certified_commitment}
          </span>
        </div>

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

      <div className="button-row" style={{ marginTop: "1.5rem" }}>
        <button className="button button-primary" onClick={() => downloadCvdr(receipt)}>
          Download Receipt (JSON)
        </button>
        <button className="button button-secondary" onClick={handleCopy}>
          {copied ? "Copied!" : "Copy to Clipboard"}
        </button>
        <button className="button button-secondary" onClick={onDone}>
          Done
        </button>
      </div>

      <p className="muted" style={{ fontSize: "0.75rem", marginTop: "0.5rem" }}>
        Saves as {cvdrFileName(receipt)}
      </p>
    </div>
  );
}
