import { ChangeEvent, useState } from "react";

type Facts = {
  validity?: { validity?: string; reason?: string };
  checks?: Record<string, { outcome?: string; established?: string; error?: string; reason?: string }>;
  trust_root_used?: { key_id?: string };
  trust_root_mismatch?: unknown;
};

export default function QuickVerify() {
  const [text, setText] = useState("");
  const [facts, setFacts] = useState<Facts | null>(null);
  const [error, setError] = useState("");
  const readFile = (event: ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;
    void file.text().then(setText);
  };
  const verify = async () => {
    setError(""); setFacts(null);
    try {
      JSON.parse(text);
      const moduleUrl = "/cvdr-wasm/mktd02_verify.js";
      const wasm = await import(/* @vite-ignore */ moduleUrl);
      await wasm.default();
      const output = wasm.verify_cvdr(new TextEncoder().encode(text), "browser:paste-or-file");
      setFacts(JSON.parse(output));
    } catch (e) { setError(String(e)); }
  };
  const row = (name: string, key: string, wording?: string) => {
    const check = facts?.checks?.[key];
    return <li><strong>{name}</strong>: {check?.outcome?.toUpperCase() ?? "NOT RUN"}{wording ? ` — ${wording}` : ""}{check?.error ? ` (${check.error})` : ""}{check?.reason ? ` (${check.reason})` : ""}</li>;
  };
  return <main className="app"><header className="header"><h1>Quick Verify</h1><p className="subtitle">MKTd02 deletion receipt verifier</p><p className="field-value mono">Verifier commit: 1ff2149 · WASM SHA-256: d925b72cebf781d212e0199ef47b64dfddef2b8880ccd3c25fb021d9e607c50f</p></header>
    <section className="card"><p><strong>Local-only:</strong> your receipt is verified in this browser; it is never uploaded.</p>
      <input type="file" accept="application/json,.json" onChange={readFile} />
      <textarea aria-label="Receipt JSON" rows={12} value={text} onChange={e => setText(e.target.value)} placeholder="Paste receipt JSON" />
      <button className="button" disabled={!text} onClick={verify}>Verify locally</button></section>
    {error && <section className="card"><strong>Verification error:</strong> {error}</section>}
    {facts && <section className="card"><h2>Overall: {facts.validity?.validity ?? "FAIL"}</h2><ul>
      {row("V1", "v1")}{row("V2", "v2")}{row("V3A", "v3a", "subnet-attested module identity")}{row("V3B", "v3b", "NOT RUN — optional provenance")}
    </ul><p>Trust root used: {facts.trust_root_used?.key_id ?? "mainnet"}</p>
      <p>Receipt root label: {facts.trust_root_mismatch ? "mismatch (informational; root selection is local)" : "matches / not supplied"}</p>
      <p>Pending receipts are INCOMPLETE; mixed finalisation is FAIL. DELAY_EXCEEDED is a non-gating timing modifier.</p>
      <p>Module hash is assessed by V3A. <a href="https://internetcomputer.org/docs/references/ic-interface-spec">Step D: IC certificate evidence</a></p>
    </section>}
  </main>;
}
