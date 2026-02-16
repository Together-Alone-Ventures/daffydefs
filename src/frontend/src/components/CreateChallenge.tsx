import { useState } from "react";
import { isOk, getError } from "../ic/agent";

interface CreateChallengeProps {
  boardActor: any;
  onCreated: (challengeId: bigint) => void;
  onCancel: () => void;
}

export default function CreateChallenge({
  boardActor,
  onCreated,
  onCancel,
}: CreateChallengeProps) {
  const [word, setWord] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const isValid = /^[A-Za-z]{3,20}$/.test(word);

  const handleSubmit = async () => {
    if (!isValid) return;
    setLoading(true);
    setError(null);

    try {
      const result = await boardActor.create_challenge(word);
      if (isOk(result)) {
        onCreated((result as any).Ok as bigint);
      } else {
        setError(getError(result));
      }
    } catch (e: any) {
      setError(`Failed to create challenge: ${e.message || e}`);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="card">
      <h2>Post a New Word</h2>
      <p className="muted">
        Coin a nonsense word and see what definitions people come up with.
      </p>

      <div className="form-group">
        <label>Word (3–20 alphabetic characters, no spaces)</label>
        <input
          type="text"
          value={word}
          onChange={(e) => setWord(e.target.value)}
          placeholder="e.g. Tungunning"
          maxLength={20}
          disabled={loading}
          autoFocus
        />
        {word.length > 0 && !isValid && (
          <p className="field-hint">
            Letters only (A–Z), 3–20 characters, no spaces or hyphens.
          </p>
        )}
      </div>

      {error && <p className="error">{error}</p>}

      <div className="button-row">
        <button
          className="button button-primary"
          onClick={handleSubmit}
          disabled={!isValid || loading}
        >
          {loading ? "Posting..." : "Post Challenge"}
        </button>
        <button
          className="button button-secondary"
          onClick={onCancel}
          disabled={loading}
        >
          Cancel
        </button>
      </div>
    </div>
  );
}
