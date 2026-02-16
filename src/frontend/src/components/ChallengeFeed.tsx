import { useState, useEffect } from "react";
import { Principal } from "@dfinity/principal";
import { HttpAgent } from "@dfinity/agent";
import { batchResolveDisplayNames, truncatePrincipal } from "../ic/resolve";

interface Challenge {
  id: bigint;
  word: string;
  author: Principal;
  created_at: bigint;
  comment_count: bigint;
}

interface ChallengeFeedProps {
  boardActor: any;
  factoryActor: any | null;
  agent: HttpAgent | null;
  isAuthenticated: boolean;
  myPrincipal: string | null;
  onSelectChallenge: (id: bigint) => void;
  onCreateChallenge: () => void;
  onShowProfile: () => void;
}

function timeAgo(nanos: bigint): string {
  const ms = Number(nanos / 1_000_000n);
  const seconds = Math.floor((Date.now() - ms) / 1000);
  if (seconds < 60) return "just now";
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}

export default function ChallengeFeed({
  boardActor,
  factoryActor,
  agent,
  isAuthenticated,
  myPrincipal,
  onSelectChallenge,
  onCreateChallenge,
  onShowProfile,
}: ChallengeFeedProps) {
  const [challenges, setChallenges] = useState<Challenge[]>([]);
  const [nameMap, setNameMap] = useState<Map<string, string>>(new Map());
  const [nextCursor, setNextCursor] = useState<bigint | null>(null);
  const [loading, setLoading] = useState(true);
  const [loadingMore, setLoadingMore] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const loadChallenges = async (cursor: bigint | null, append: boolean) => {
    try {
      const result = await boardActor.list_challenges(
        cursor !== null ? [cursor] : [],
        [20]
      );

      const newChallenges: Challenge[] = result.challenges;
      const allChallenges = append
        ? [...challenges, ...newChallenges]
        : newChallenges;

      setChallenges(allChallenges);
      setNextCursor(
        result.next_cursor.length > 0 ? result.next_cursor[0] : null
      );

      // Resolve display names if authenticated
      if (isAuthenticated && factoryActor && agent) {
        const authors = allChallenges.map((c: Challenge) => c.author);
        const names = await batchResolveDisplayNames(
          authors,
          factoryActor,
          agent
        );
        setNameMap((prev) => new Map([...prev, ...names]));
      }
    } catch (e: any) {
      setError(`Failed to load challenges: ${e.message || e}`);
    }
  };

  useEffect(() => {
    setLoading(true);
    loadChallenges(null, false).finally(() => setLoading(false));
  }, []);

  const handleLoadMore = async () => {
    if (!nextCursor) return;
    setLoadingMore(true);
    await loadChallenges(nextCursor, true);
    setLoadingMore(false);
  };

  const getAuthorName = (author: Principal): string => {
    if (!isAuthenticated) return truncatePrincipal(author);
    return nameMap.get(author.toText()) || truncatePrincipal(author);
  };

  if (loading) {
    return (
      <div className="center-message">
        <div className="spinner" />
        <p>Loading challenges...</p>
      </div>
    );
  }

  return (
    <div>
      <div className="feed-header">
        <h2>Challenges</h2>
        <div className="feed-actions">
          {isAuthenticated && (
            <>
              <button
                className="button button-primary button-sm"
                onClick={onCreateChallenge}
              >
                + New Word
              </button>
              <button
                className="button button-secondary button-sm"
                onClick={onShowProfile}
              >
                Profile
              </button>
            </>
          )}
        </div>
      </div>

      {error && <p className="error">{error}</p>}

      {challenges.length === 0 ? (
        <div className="placeholder">
          <p>No challenges yet. Be the first to post a daffy word!</p>
        </div>
      ) : (
        <div className="challenge-list">
          {challenges.map((c) => (
            <div
              key={Number(c.id)}
              className="challenge-card"
              onClick={() => onSelectChallenge(c.id)}
            >
              <div className="challenge-word">{c.word}</div>
              <div className="challenge-meta">
                <span className="challenge-author">
                  by {getAuthorName(c.author)}
                </span>
                <span className="challenge-time">{timeAgo(c.created_at)}</span>
              </div>
              <div className="challenge-comments">
                {Number(c.comment_count)} definition
                {Number(c.comment_count) !== 1 ? "s" : ""}
              </div>
            </div>
          ))}
        </div>
      )}

      {nextCursor !== null && (
        <div className="load-more">
          <button
            className="button button-secondary"
            onClick={handleLoadMore}
            disabled={loadingMore}
          >
            {loadingMore ? "Loading..." : "Load More"}
          </button>
        </div>
      )}
    </div>
  );
}
