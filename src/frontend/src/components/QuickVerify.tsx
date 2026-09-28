import { ChangeEvent, useState } from "react";
import { SERVED_WASM_SHA256, V3B_INSTRUCTIONS_URL, VERIFIER_SOURCE_LABEL } from "./verifierBuild";

type Facts = {
  validity?: { validity?: string; reason?: string };
  checks?: Record<string, { outcome?: string; established?: string; error?: string; reason?: string }>;
  receipt_id?: string;
  canister_id?: string;
  receipt_state?: string;
  timing?: Array<{ verdict?: string }>;
  trust_root_used?: { id?: string; key_id?: string };
  trust_root_mismatch?: unknown;
};

export default function QuickVerify() {
  const [text, setText] = useState("");
  const [facts, setFacts] = useState<Facts | null>(null);
  const [error, setError] = useState("");
  const [receipt, setReceipt] = useState<Record<string, unknown> | null>(null);
  const readFile = (event: ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;
    void file.text().then(setText);
  };
  const verify = async () => {
    setError(""); setFacts(null); setReceipt(null);
    try {
      const parsed = JSON.parse(text) as Record<string, unknown>;
      const moduleUrl = "/cvdr-wasm/mktd02_verify.js";
      const wasm = await import(/* @vite-ignore */ moduleUrl);
      await wasm.default();
      const output = wasm.verify_cvdr(new TextEncoder().encode(text), "browser:paste-or-file");
      setFacts(JSON.parse(output));
      setReceipt(parsed);
    } catch (e) { setError(String(e)); }
  };
  const row = (name: string, key: string, wording?: string) => {
    const check = facts?.checks?.[key];
    return <li><strong>{name}</strong>: {check?.outcome?.toUpperCase() ?? "NOT RUN"}{wording ? ` — ${wording}` : ""}{check?.error ? ` (${check.error})` : ""}{check?.reason ? ` (${check.reason})` : ""}</li>;
  };
  const delayed = facts?.timing?.some(item => item.verdict === "DELAY_EXCEEDED");
  return <main className="app quick-verify"><header className="header"><h1>Quick Verify</h1><p className="subtitle">MKTd02 deletion receipt verifier</p><p className="field-value mono">Verifier source: {VERIFIER_SOURCE_LABEL}</p><p className="field-value mono hash-value">Served WASM SHA-256: {SERVED_WASM_SHA256}</p></header>
    <section className="card"><p><strong>Local-only:</strong> your receipt is verified in this browser; it is never uploaded.</p>
      <input type="file" accept="application/json,.json" onChange={readFile} />
      <textarea aria-label="Receipt JSON" rows={12} value={text} onChange={e => setText(e.target.value)} placeholder="Paste receipt JSON" />
      <button className="button" disabled={!text} onClick={verify}>Verify locally</button></section>
    {error && <section className="card"><strong>Verification error:</strong> {error}</section>}
    {facts && <section className="card"><h2>Overall: {facts.validity?.validity ?? "FAIL"}</h2><ul className="verify-results">
      {row("V1", "v1")}{row("V2", "v2")}
      <li><strong>V3A — Subnet-attested module identity (finalisation window)</strong>: {facts.checks?.v3a?.outcome?.toUpperCase() ?? "NOT RUN"}{facts.checks?.v3a?.error ? ` (${facts.checks.v3a.error})` : ""}<div className="hash-value">Module hash: {String(receipt?.module_hash ?? "not available")}</div></li>
      <li><strong>V3B — Source/build provenance</strong>: not checked here → <a href={V3B_INSTRUCTIONS_URL} target="_blank" rel="noopener noreferrer">see Step C</a></li>
    </ul><p><strong>Trust root: ICP mainnet</strong></p>
      {Boolean(facts.trust_root_mismatch) && <p className="field-hint">Warning: receipt root label differs from the ICP mainnet root used; this label is informational.</p>}
      <p className="hash-value">Receipt ID: {facts.receipt_id ?? String(receipt?.receipt_id ?? "not available")}</p>
      <p className="hash-value">Canister ID: {facts.canister_id ?? String(receipt?.canister_id ?? "not available")}</p>
      {facts.receipt_state === "Pending" && <p>Pending receipt: INCOMPLETE until finalisation evidence is present.</p>}
      {facts.receipt_state === "InvalidIncompleteFinalization" && <p>Incomplete finalisation: FAIL.</p>}
      {delayed && <p>DELAY_EXCEEDED: timing modifier only; it does not change validity.</p>}
    </section>}
  </main>;
}
