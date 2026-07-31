// F3 must set FINALIZER_BASE_URL to the deployed zd-finalizer-service origin.
// The service CORS allowlist must include the deployed DaffyDefs frontend origin.
export const FINALIZER_BASE_URL = (process.env.FINALIZER_BASE_URL || "").replace(/\/+$/, "");

export const FINALIZER_DEPLOYMENT = "daffydefs-mainnet";

export interface FinalizationJob {
  job_id: string;
  status: "pending" | "finalized" | "failed";
}

export async function submitFinalization(
  targetCanisterId: string,
  receiptId: string,
  signal?: AbortSignal,
): Promise<FinalizationJob> {
  if (!FINALIZER_BASE_URL) {
    throw new Error("Finaliser service is not configured");
  }

  const response = await fetch(`${FINALIZER_BASE_URL}/v1/finalizations`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    signal,
    body: JSON.stringify({
      deployment: FINALIZER_DEPLOYMENT,
      target_canister_id: targetCanisterId,
      receipt_id: receiptId,
    }),
  });

  if (response.status !== 200 && response.status !== 202) {
    throw new Error(`Finaliser submission failed (${response.status})`);
  }
  return response.json() as Promise<FinalizationJob>;
}

export async function getFinalization(
  jobId: string,
  signal?: AbortSignal,
): Promise<FinalizationJob> {
  const response = await fetch(
    `${FINALIZER_BASE_URL}/v1/finalizations/${encodeURIComponent(jobId)}`,
    { signal },
  );
  if (!response.ok) {
    throw new Error(`Finaliser status request failed (${response.status})`);
  }
  return response.json() as Promise<FinalizationJob>;
}
