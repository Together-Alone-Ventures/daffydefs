import { useState, useEffect } from "react";
import { Principal } from "@dfinity/principal";
import { HttpAgent } from "@dfinity/agent";
import { isOk, getError } from "../ic/agent";
import {
  batchResolveDisplayNames,
  truncatePrincipal,
} from "../ic/resolve";

interface Comment {
  id: bigint;
  challenge_id: bigint;
  author: Principal;
  text: string;
  created_at: bigint;
  like_count: bigint;
  liked_by_caller: boolean;
}

interface ChallengeData {
  id: bigint;
  word: string;
  author: Principal;
  created_at: bigint;
  comments: Comment[];
}

interface ChallengeDetailProps {
  challengeId: bigint;
  boardActor: any;
  factoryActor: any | null;
  agent: HttpAgent | null;
  isAuthenticated: boolean;
  myPrincipal: string | null;
  onBack: () => void;
}

function timeAgo(nanos: bigint): string {
  const ms = Number(nanos / 1_000_000n);
  const seconds = Math.floor((Date.now() - ms) / 1000);
  if (seconds < 60) return "just now";
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}

export default function ChallengeDetail({
  challengeId,
  boardActor,
  factoryActor,
  agent,
  isAuthenticated,
  myPrincipal,
  onBack,
}: ChallengeDetailProps) {
  const [challenge, setChallenge] = useState<ChallengeData | null>(null);
  const [nameMap, setNameMap] = useState<Map<string, string>>(new Map());
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Comment form
  const [commentText, setCommentText] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [submitError, setSubmitError] = useState<string | null>(null);

  // Like loading state (track which comment IDs are being toggled)
  const [likingComments, setLikingComments] = useState<Set<number>>(new Set());

  const loadChallenge = async () => {
    try {
      const result = await boardActor.get_challenge(challengeId);
      if (isOk(result)) {
        const data = (result as any).Ok as ChallengeData;
        setChallenge(data);

        // Resolve display names
        if (isAuthenticated && factoryActor && agent) {
          const authors = [
            data.author,
            ...data.comments.map((c: Comment) => c.author),
          ];
          const names = await batchResolveDisplayNames(
            authors,
            factoryActor,
            agent
          );
          setNameMap(names);
        }
      } else {
        setError(getError(result));
      }
    } catch (e: any) {
      setError(`Failed to load challenge: ${e.message || e}`);
    }
  };

  useEffect(() => {
    setLoading(true);
    loadChallenge().finally(() => setLoading(false));
  }, [challengeId]);

  const getAuthorName = (author: Principal): string => {
    if (!isAuthenticated) return truncatePrincipal(author);
    return nameMap.get(author.toText()) || truncatePrincipal(author);
  };

  const isMyChallenge =
    challenge && myPrincipal
      ? challenge.author.toText() === myPrincipal
      : false;

  const handleAddComment = async () => {
    if (!commentText.trim()) return;
    setSubmitting(true);
    setSubmitError(null);

    try {
      const result = await boardActor.add_comment(
        challengeId,
        commentText.trim()
      );
      if (isOk(result)) {
        setCommentText("");
        // Reload to get updated comments
        await loadChallenge();
      } else {
        setSubmitError(getError(result));
      }
    } catch (e: any) {
      setSubmitError(`Failed to add comment: ${e.message || e}`);
    } finally {
      setSubmitting(false);
    }
  };

  const handleToggleLike = async (commentId: bigint) => {
    const numId = Number(commentId);
    if (likingComments.has(numId)) return;

    setLikingComments((prev) => new Set([...prev, numId]));

    try {
      const result = await boardActor.toggle_like(commentId);
      if (isOk(result)) {
        // Update the comment's like count and liked state in place
        setChallenge((prev) => {
          if (!prev) return prev;
          return {
            ...prev,
            comments: prev.comments.map((c: Comment) => {
              if (Number(c.id) === numId) {
                return {
                  ...c,
                  like_count: (result as any).Ok as bigint,
                  liked_by_caller: !c.liked_by_caller,
                };
              }
              return c;
            }),
          };
        });
      }
    } catch (e) {
      // Silently fail on like errors
    } finally {
      setLikingComments((prev) => {
        const next = new Set(prev);
        next.delete(numId);
        return next;
      });
    }
  };

  if (loading) {
    return (
      <div className="center-message">
        <div className="spinner" />
        <p>Loading challenge...</p>
      </div>
    );
  }

  if (error || !challenge) {
    return (
      <div className="card">
        <p className="error">{error || "Challenge not found"}</p>
        <button className="button button-secondary" onClick={onBack}>
          Back to Feed
        </button>
      </div>
    );
  }

  return (
    <div>
      <button className="button-link back-link" onClick={onBack}>
        &larr; Back to Feed
      </button>

      {/* Challenge header */}
      <div className="card challenge-detail-card">
        <div className="challenge-word-large">{challenge.word}</div>
        <div className="challenge-meta">
          <span className="challenge-author">
            Posted by {getAuthorName(challenge.author)}
          </span>
          <span className="challenge-time">
            {timeAgo(challenge.created_at)}
          </span>
        </div>
      </div>

      {/* Add definition form */}
      {isAuthenticated && !isMyChallenge && (
        <div className="card">
          <h3>Add Your Definition</h3>
          <div className="form-group">
            <textarea
              value={commentText}
              onChange={(e) => setCommentText(e.target.value)}
              placeholder="What does this word mean to you?"
              maxLength={500}
              rows={3}
              disabled={submitting}
            />
            <span className="char-count">
              {commentText.length}/500
            </span>
          </div>
          {submitError && <p className="error">{submitError}</p>}
          <button
            className="button button-primary button-sm"
            onClick={handleAddComment}
            disabled={!commentText.trim() || submitting}
          >
            {submitting ? "Posting..." : "Post Definition"}
          </button>
        </div>
      )}

      {isAuthenticated && isMyChallenge && (
        <div className="card muted-card">
          <p className="muted">This is your challenge — you can't add a definition to your own word.</p>
        </div>
      )}

      {!isAuthenticated && (
        <div className="card muted-card">
          <p className="muted">Sign in to add definitions and like your favourites.</p>
        </div>
      )}

      {/* Comments / Definitions */}
      <div className="definitions-section">
        <h3 className="section-title">
          Definitions ({challenge.comments.length})
        </h3>

        {challenge.comments.length === 0 ? (
          <div className="placeholder">
            <p>No definitions yet. Be the first!</p>
          </div>
        ) : (
          <div className="comment-list">
            {challenge.comments.map((c: Comment) => (
              <div key={Number(c.id)} className="comment-card">
                <div className="comment-text">{c.text}</div>
                <div className="comment-footer">
                  <span className="comment-author">
                    {getAuthorName(c.author)}
                  </span>
                  <span className="comment-time">
                    {timeAgo(c.created_at)}
                  </span>
                  <button
                    className={`like-button ${c.liked_by_caller ? "liked" : ""}`}
                    onClick={() =>
                      isAuthenticated && handleToggleLike(c.id)
                    }
                    disabled={
                      !isAuthenticated ||
                      likingComments.has(Number(c.id))
                    }
                  >
                    {c.liked_by_caller ? "❤️" : "🤍"}{" "}
                    {Number(c.like_count)}
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
