interface FinalizationProgressProps {
  status: "idle" | "finalizing" | "finalized" | "pending" | "blocked";
}

export default function FinalizationProgress({ status }: FinalizationProgressProps) {
  if (status !== "finalizing") return null;

  return (
    <div className="card" role="status">
      <p className="finalization-progress" style={{ margin: 0, fontWeight: 600 }}>
        <span className="finalization-spinner" aria-hidden="true" />
        Preparing your Deletion Receipt — please don't close this window.
      </p>
    </div>
  );
}
