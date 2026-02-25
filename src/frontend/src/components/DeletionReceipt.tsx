import { useState } from "react";

export interface CvdrData {
  receipt_id: string;
  canister_id: string;
  subnet_id: string;
  commit_mode: string;
  pre_state_hash: string;
  post_state_hash: string;
  tombstone_hash: string;
  deletion_event_hash: string;
  certified_commitment: string;
  manifest_hash: string;
  module_hash: string;
  timestamp: bigint;
  nonce: bigint;
}

interface DeletionReceiptProps {
  receipt: CvdrData;
  profileCanisterId: string;
  onDone: () => void;
}

export default function DeletionReceipt({
  receipt,
  profileCanisterId,
  onDone,
}: DeletionReceiptProps) {
  const [copied, setCopied] = useState(false);

  const formatTimestamp = (ns: bigint): string => {
    try {
      const ms = Number(ns) / 1_000_000;
      return new Date(ms).toISOString();
    } catch {
      return ns.toString();
    }
  };

  const receiptJson = {
    receipt_id: receipt.receipt_id,
    canister_id: receipt.canister_id,
    subnet_id: receipt.subnet_id,
    profile_canister: profileCanisterId,
    commit_mode: receipt.commit_mode,
    pre_state_hash: receipt.pre_state_hash,
    post_state_hash: receipt.post_state_hash,
    tombstone_hash: receipt.tombstone_hash,
    deletion_event_hash: receipt.deletion_event_hash,
    certified_commitment: receipt.certified_commitment,
    manifest_hash: receipt.manifest_hash,
    module_hash: receipt.module_hash,
    timestamp: receipt.timestamp.toString(),
    timestamp_iso: formatTimestamp(receipt.timestamp),
    nonce: receipt.nonce.toString(),
  };

  const handleDownload = () => {
    const blob = new Blob([JSON.stringify(receiptJson, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `deletion-receipt-${receipt.receipt_id.slice(0, 8)}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(JSON.stringify(receiptJson, null, 2));
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // Fallback for browsers that don't support clipboard API
      const textArea = document.createElement("textarea");
      textArea.value = JSON.stringify(receiptJson, null, 2);
      document.body.appendChild(textArea);
      textArea.select();
      document.execCommand("copy");
      document.body.removeChild(textArea);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
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

      <div className="receipt-fields">
        <div className="profile-field">
          <span className="field-label">Receipt ID</span>
          <span className="field-value mono" style={{ fontSize: "0.75rem", wordBreak: "break-all" }}>
            {receipt.receipt_id}
          </span>
        </div>

        <div className="profile-field">
          <span className="field-label">Deleted At</span>
          <span className="field-value">
            {formatTimestamp(receipt.timestamp)}
          </span>
        </div>

        <div className="profile-field">
          <span className="field-label">Profile Canister</span>
          <span className="field-value mono">{profileCanisterId}</span>
        </div>

        <div className="profile-field">
          <span className="field-label">Subnet</span>
          <span className="field-value mono" style={{ fontSize: "0.8rem" }}>
            {receipt.subnet_id}
          </span>
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
          <span className="field-label">Manifest Hash</span>
          <span className="field-value mono" style={{ fontSize: "0.7rem", wordBreak: "break-all" }}>
            {receipt.manifest_hash}
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
          <span className="field-label">Commit Mode</span>
          <span className="field-value">{receipt.commit_mode}</span>
        </div>

        <div className="profile-field">
          <span className="field-label">Nonce</span>
          <span className="field-value mono">{receipt.nonce.toString()}</span>
        </div>
      </div>

      <div className="button-row" style={{ marginTop: "1.5rem" }}>
        <button className="button button-primary" onClick={handleDownload}>
          Download Receipt (JSON)
        </button>
        <button className="button button-secondary" onClick={handleCopy}>
          {copied ? "Copied!" : "Copy to Clipboard"}
        </button>
        <button className="button button-secondary" onClick={onDone}>
          Done
        </button>
      </div>
    </div>
  );
}
