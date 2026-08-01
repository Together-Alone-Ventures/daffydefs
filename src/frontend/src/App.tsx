import { useState, useEffect, useCallback, useRef } from "react";
import { AuthClient } from "@dfinity/auth-client";
import { HttpAgent } from "@dfinity/agent";
import { Principal } from "@dfinity/principal";
import {
  createAgent,
  createFactoryActor,
  createBoardActor,
  createProfileActor,
  getAnonymousAgent,
  isOk,
  getError,
  II_URL,
  isLocal,
} from "./ic/agent";
import { clearNameCache } from "./ic/resolve";
import { finalizePendingReceipt, type FinalizeStage } from "./ic/finalize/flow";
import { isReceiptFinalized, mapReceiptToCvdr } from "./ic/finalize/cvdr";
import type { GuardReport } from "./ic/finalize/guard";
import ProfileSetup from "./components/ProfileSetup";
import ProfileView from "./components/ProfileView";
import ChallengeFeed from "./components/ChallengeFeed";
import CreateChallenge from "./components/CreateChallenge";
import ChallengeDetail from "./components/ChallengeDetail";
import DeletionReceipt from "./components/DeletionReceipt";
import { CvdrData } from "./components/DeletionReceipt";
import "./App.css";

// ============================================================
// App state types
// ============================================================

type Screen =
  | "loading"
  | "unauthenticated-feed"  // browsing feed without auth
  | "feed"                  // authenticated feed
  | "initializing"          // authenticated, loading profile canister
  | "profile-setup"         // has canister but no profile data yet
  | "profile-view"          // viewing/editing profile
  | "profile-deleted"       // profile was deleted, offer rejoin
  | "create-challenge"      // posting a new word
  | "challenge-detail"      // viewing a challenge + comments
  | "deletion-receipt"
  | "error";

interface ProfileData {
  owner: string;
  email: string;
  birthdate: string;
  gender: string;
  display_name: string;
}

type FinalizationStatus = "idle" | "finalizing" | "finalized" | "pending" | "blocked";

/** Map a flow stage onto the coarse status the receipt component renders. */
function statusForStage(stage: FinalizeStage): FinalizationStatus {
  switch (stage) {
    case "finalized":
      return "finalized";
    case "guard-blocked":
      return "blocked";
    case "idle":
      return "idle";
    case "failed":
      return "pending";
    default:
      return "finalizing";
  }
}

// ============================================================
// App Component
// ============================================================

function App() {
  const [authClient, setAuthClient] = useState<AuthClient | null>(null);
  const [agent, setAgent] = useState<HttpAgent | null>(null);
  const [principal, setPrincipal] = useState<string | null>(null);
  const [screen, setScreen] = useState<Screen>("loading");
  const [error, setError] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [actionLoading, setActionLoading] = useState(false);
  const [cvdrData, setCvdrData] = useState<CvdrData | null>(null);
  const [deletionReceiptId, setDeletionReceiptId] = useState<string | null>(null);
  const [finalizationStatus, setFinalizationStatus] = useState<FinalizationStatus>("idle");
  const [guardReport, setGuardReport] = useState<GuardReport | null>(null);

  // Profile state
  const [profileCanisterId, setProfileCanisterId] = useState<string | null>(null);
  const [profileData, setProfileData] = useState<ProfileData | null>(null);

  // Actors
  const [factoryActor, setFactoryActor] = useState<any>(null);
  const [boardActor, setBoardActor] = useState<any>(null);
  const [profileActor, setProfileActor] = useState<any>(null);

  // Navigation state
  const [selectedChallengeId, setSelectedChallengeId] = useState<bigint | null>(null);

  // Mount-race safety: every async finalisation result is dropped if the
  // component has since unmounted, and the in-flight controller is aborted so a
  // half-finished run does not keep polling after the user has navigated away.
  const mountedRef = useRef(true);
  const finalizeAbortRef = useRef<AbortController | null>(null);

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
      finalizeAbortRef.current?.abort();
    };
  }, []);

  /**
   * Run the browser finalisation path for a pending receipt.
   *
   * Deliberately never triggers Phase A. Called both immediately after a
   * deletion and, on a later visit, as lazy repair — in the repair case the user
   * must not be asked to re-authorise a deletion they already authorised.
   *
   * Double submission is prevented inside finalizePendingReceipt, which
   * deduplicates on canister+receipt and re-reads the receipt before every
   * submit attempt.
   */
  const runFinalization = useCallback(
    async (receiptId?: string) => {
      if (!profileActor || !factoryActor || !profileCanisterId) return;

      finalizeAbortRef.current?.abort();
      const controller = new AbortController();
      finalizeAbortRef.current = controller;

      setFinalizationStatus("finalizing");

      try {
        const anonAgent = await getAnonymousAgent();
        const outcome = await finalizePendingReceipt({
          profileActor,
          factoryActor,
          anonAgent,
          profileCanisterId,
          receiptId,
          signal: controller.signal,
          onStage: (stage) => {
            if (!mountedRef.current || controller.signal.aborted) return;
            setFinalizationStatus(statusForStage(stage));
          },
        });

        if (!mountedRef.current || controller.signal.aborted) return;

        if (outcome.receipt) setCvdrData(outcome.receipt);
        setGuardReport(outcome.guard);

        switch (outcome.status) {
          case "finalized":
          case "already-finalized":
            setFinalizationStatus("finalized");
            break;
          case "guard-blocked":
            setFinalizationStatus("blocked");
            break;
          case "not-pending":
            setFinalizationStatus("idle");
            break;
          default:
            setFinalizationStatus("pending");
            if (outcome.error) {
              console.warn("[finalize] did not complete:", outcome.error);
            }
        }
      } catch (e) {
        if (!mountedRef.current || controller.signal.aborted) return;
        setFinalizationStatus("pending");
        console.warn("[finalize] error:", e);
      }
    },
    [factoryActor, profileActor, profileCanisterId]
  );

  // ----------------------------------------------------------
  // Initialize auth client on mount
  // ----------------------------------------------------------
  useEffect(() => {
    AuthClient.create().then(async (client) => {
      setAuthClient(client);

      const authenticated = await client.isAuthenticated();
      if (authenticated) {
        await handleAuthenticated(client);
      } else {
        // Create anonymous agent for browsing the feed
        try {
          const anonAgent = await HttpAgent.create({
            host: isLocal ? "http://127.0.0.1:4943" : "https://icp-api.io",
          });
          if (isLocal) await anonAgent.fetchRootKey();
          setAgent(anonAgent);
          const board = createBoardActor(anonAgent);
          setBoardActor(board);
        } catch (e) {
          // If anonymous agent fails, still show the page
        }
        setScreen("unauthenticated-feed");
      }
    });
  }, []);

  // ----------------------------------------------------------
  // Lazy repair
  // ----------------------------------------------------------
  //
  // On any authenticated visit, if the canister reports a pending finalisation,
  // resume it. This is what makes a tab-close mid-deletion recoverable: Phase A
  // already happened and is durable, so the repair only ever completes B→C,
  // through mktd_is_pending / mktd_get_certificate / mktd_get_receipt only.
  // No deletion is re-triggered and no re-authorisation is requested.
  //
  // It never unmaps — see the coded invariant in ic/factory.did.ts. Unmapping a
  // still-pending receipt would strand it permanently unfinalisable.
  //
  // The effect deliberately does not depend on runFinalization — re-firing on
  // every render used to launch a second finalisation that raced the first.
  // Double-submit safety no longer relies on that omission (finalizePendingReceipt
  // deduplicates), but the effect stays narrow so repair runs once per session.
  useEffect(() => {
    if (!profileActor || !profileCanisterId || !factoryActor) return;

    let cancelled = false;
    const repairIfPending = async () => {
      try {
        const isPending = await profileActor.mktd_is_pending();
        if (cancelled || !isPending) return;
        setScreen("deletion-receipt");
        await runFinalization();
      } catch {
        if (!cancelled) setFinalizationStatus("pending");
      }
    };

    void repairIfPending();
    return () => {
      cancelled = true;
    };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [profileActor, profileCanisterId, factoryActor]);

  // ----------------------------------------------------------
  // Post-authentication setup
  // ----------------------------------------------------------
  const handleAuthenticated = useCallback(async (client: AuthClient) => {
    try {
      const identity = client.getIdentity();
      const principalText = identity.getPrincipal().toText();
      setPrincipal(principalText);
      setScreen("initializing");

      const newAgent = await createAgent(identity);
      setAgent(newAgent);

      // Create actors
      const factory = createFactoryActor(newAgent);
      setFactoryActor(factory);
      const board = createBoardActor(newAgent);
      setBoardActor(board);

      // Get or create profile canister
      const result = await factory.get_or_create_profile_canister();

      if (isOk(result as any)) {
        const canisterId = (result as any).Ok as Principal;
        const canisterIdText = canisterId.toText();
        setProfileCanisterId(canisterIdText);

        const profActor = createProfileActor(newAgent, canisterId);
        setProfileActor(profActor);

        await loadProfile(profActor);
      } else {
        setError(`Factory error: ${getError(result as any)}`);
        setScreen("error");
      }
    } catch (e: any) {
      setError(`Authentication setup failed: ${e.message || e}`);
      setScreen("error");
    }
  }, []);

  // ----------------------------------------------------------
  // Load profile
  // ----------------------------------------------------------
  const loadProfile = async (actor: any) => {
    try {
      const result = await actor.get_profile();
      if (isOk(result)) {
        const info = (result as any).Ok;
        setProfileData({
          owner: info.owner.toText(),
          email: info.email,
          birthdate: info.birthdate,
          gender: info.gender,
          display_name: info.display_name,
        });
        setScreen("feed");
      } else {
        const errStr = getError(result);
        if (errStr.startsWith("ProfileNotFound")) {
          setScreen("profile-setup");
        } else if (errStr.startsWith("ProfileDeleted")) {
          setScreen("profile-deleted");
        } else {
          setError(`Profile load error: ${errStr}`);
          setScreen("error");
        }
      }
    } catch (e: any) {
      setError(`Failed to load profile: ${e.message || e}`);
      setScreen("error");
    }
  };

  // ----------------------------------------------------------
  // Actions
  // ----------------------------------------------------------

  const handleLogin = async () => {
    if (!authClient) return;
    setError(null);
    try {
      await authClient.login({
        identityProvider: II_URL,
        maxTimeToLive: BigInt(7 * 24 * 60 * 60 * 1_000_000_000),
        onSuccess: async () => {
          await handleAuthenticated(authClient);
        },
        onError: (err) => {
          setError(`Login failed: ${err}`);
        },
      });
    } catch (e: any) {
      setError(`Login error: ${e.message || e}`);
    }
  };

  const handleLogout = async () => {
    if (!authClient) return;
    await authClient.logout();
    clearNameCache();
    setPrincipal(null);
    setProfileCanisterId(null);
    setProfileData(null);
    setProfileActor(null);
    setFactoryActor(null);
    setSelectedChallengeId(null);
    setCvdrData(null);
    setGuardReport(null);
    setDeletionReceiptId(null);
    setFinalizationStatus("idle");

    // Recreate anonymous agent
    try {
      const anonAgent = await HttpAgent.create({
        host: isLocal ? "http://127.0.0.1:4943" : "https://icp-api.io",
      });
      if (isLocal) await anonAgent.fetchRootKey();
      setAgent(anonAgent);
      const board = createBoardActor(anonAgent);
      setBoardActor(board);
    } catch (e) {}

    setScreen("unauthenticated-feed");
    setError(null);
    setActionError(null);
  };

  const handleSaveProfile = async (input: {
    email: string;
    birthdate: string;
    gender: string;
    display_name: string;
  }) => {
    if (!profileActor) return;
    setActionLoading(true);
    setActionError(null);
    try {
      const result = await profileActor.upsert_profile(input);
      if (isOk(result)) {
        const info = (result as any).Ok;
        setProfileData({
          owner: info.owner.toText(),
          email: info.email,
          birthdate: info.birthdate,
          gender: info.gender,
          display_name: info.display_name,
        });
        setScreen("feed");
      } else {
        setActionError(getError(result));
      }
    } catch (e: any) {
      setActionError(`Save failed: ${e.message || e}`);
    } finally {
      setActionLoading(false);
    }
  };

  const handleDeleteProfile = async () => {
    if (!profileActor || !profileCanisterId) return;
    // Double-submit protection at the UI edge; the flow module enforces it again
    // at the call layer, which is what survives a reload rather than a re-render.
    if (actionLoading) return;

    setActionLoading(true);
    setActionError(null);
    setFinalizationStatus("idle");
    setCvdrData(null);
    setGuardReport(null);
    setDeletionReceiptId(null);

    try {
      // Phase A — the only place a deletion is ever triggered.
      const result = await profileActor.delete_profile();
      if (!isOk(result as any)) {
        setActionError(getError(result as any));
        return;
      }

      const receiptId = (result as any).Ok;
      if (typeof receiptId !== "string" || receiptId.length === 0) {
        setActionError("Delete succeeded but returned an invalid receipt ID");
        return;
      }

      setDeletionReceiptId(receiptId);
      setScreen("deletion-receipt");

      // Show whatever the receipt says immediately, so the user has their
      // hashes even if finalisation then stalls.
      try {
        const receiptResult = await profileActor.mktd_get_receipt(receiptId);
        const receipt =
          receiptResult && receiptResult.length > 0 ? receiptResult[0] : null;
        if (receipt) {
          setCvdrData(mapReceiptToCvdr(receipt));
          if (isReceiptFinalized(receipt)) {
            setFinalizationStatus("finalized");
            return;
          }
        }
      } catch {
        // Non-fatal: finalisation below re-reads the receipt anyway.
      }

      // Phase B → read_state → guard → Phase C.
      await runFinalization(receiptId);
    } catch (e: any) {
      setActionError(`Delete failed: ${e.message || e}`);
    } finally {
      setActionLoading(false);
    }
  };

  // Navigation helpers
  const goToFeed = () => {
    setSelectedChallengeId(null);
    setScreen(principal ? "feed" : "unauthenticated-feed");
  };

  const isAuthenticated = !!principal && screen !== "unauthenticated-feed";
  const showFeed = screen === "feed" || screen === "unauthenticated-feed";

  // ----------------------------------------------------------
  // Render
  // ----------------------------------------------------------

  return (
    <div className="app">
      <header className="header" onClick={goToFeed} style={{ cursor: "pointer" }}>
        <h1>DaffyDefs</h1>
        <p className="subtitle">Daffy definitions for daffy words</p>
      </header>

      {/* Session bar */}
      {principal && screen !== "loading" && (
        <div className="session-bar">
          <span className="principal-display">
            {profileData?.display_name || `${principal.slice(0, 8)}...${principal.slice(-5)}`}
          </span>
          {isLocal && <span className="network-badge">local</span>}
          <button className="button-link" onClick={handleLogout}>
            Sign Out
          </button>
        </div>
      )}

      {/* Unauthenticated session bar */}
      {!principal && screen === "unauthenticated-feed" && (
        <div className="session-bar">
          <span className="muted" style={{ fontSize: "0.85rem" }}>Browsing as guest</span>
          <button className="button-link" onClick={handleLogin} style={{ marginLeft: "auto" }}>
            Sign In
          </button>
        </div>
      )}

      <main className="main">
        {/* Loading */}
        {screen === "loading" && (
          <div className="center-message">
            <div className="spinner" />
            <p>Loading...</p>
          </div>
        )}

        {/* Initializing */}
        {screen === "initializing" && (
          <div className="center-message">
            <div className="spinner" />
            <p>Setting up your profile canister...</p>
          </div>
        )}

        {/* Feed (authenticated or guest) */}
        {showFeed && !selectedChallengeId && boardActor && (
          <ChallengeFeed
            boardActor={boardActor}
            factoryActor={factoryActor}
            agent={agent}
            isAuthenticated={isAuthenticated}
            myPrincipal={principal}
            onSelectChallenge={(id) => {
              setSelectedChallengeId(id);
              setScreen(principal ? "challenge-detail" : "challenge-detail");
            }}
            onCreateChallenge={() => setScreen("create-challenge")}
            onShowProfile={() => setScreen("profile-view")}
          />
        )}

        {/* Challenge Detail */}
        {(screen === "challenge-detail" || (showFeed && selectedChallengeId)) &&
          selectedChallengeId &&
          boardActor && (
            <ChallengeDetail
              challengeId={selectedChallengeId}
              boardActor={boardActor}
              factoryActor={factoryActor}
              agent={agent}
              isAuthenticated={isAuthenticated}
              myPrincipal={principal}
              onBack={goToFeed}
            />
          )}

        {/* Create Challenge */}
        {screen === "create-challenge" && boardActor && (
          <CreateChallenge
            boardActor={boardActor}
            onCreated={(id) => {
              setSelectedChallengeId(id);
              setScreen("challenge-detail");
            }}
            onCancel={goToFeed}
          />
        )}

        {/* Profile Setup */}
        {screen === "profile-setup" && (
          <ProfileSetup
            onSave={handleSaveProfile}
            loading={actionLoading}
            error={actionError}
          />
        )}

        {/* Profile View */}
        {screen === "profile-view" && profileData && profileCanisterId && (
          <ProfileView
            profile={profileData}
            profileCanisterId={profileCanisterId}
            onUpdate={handleSaveProfile}
            onDelete={handleDeleteProfile}
            loading={actionLoading}
            error={actionError}
          />
        )}

        {/* Deletion Receipt */}
        {screen === "deletion-receipt" && profileCanisterId && (
          <>
            {/* Deletion-done language is withheld until the receipt-first
                confirmation reports Finalized. While A→C is in flight the user
                is told work is still happening, not that it is over. */}
            <nav className="top-bar">
              <span className="username">
                {finalizationStatus === "finalized"
                  ? "Account Deleted"
                  : "Finalising Deletion"}
              </span>
            </nav>
            {/* FIX 5: was a nested <main>, changed to <div> */}
            <div className="main-content">
              {!cvdrData && (
                <div className="card">
                  <h2>Preparing your Deletion Receipt</h2>
                  <p style={{ margin: 0, fontWeight: 600 }}>
                    Please don't close this window.
                  </p>
                  <p className="muted">
                    Collecting and verifying certificates
                    {deletionReceiptId ? ` (${deletionReceiptId})` : ""}...
                  </p>
                </div>
              )}
              {finalizationStatus === "finalizing" && (
                <div className="card">
                  <p style={{ margin: 0, fontWeight: 600 }}>
                    Preparing your Deletion Receipt — please don't close this window.
                  </p>
                </div>
              )}
              {finalizationStatus === "finalized" && (
                <p className="muted">Deletion complete — receipt ready.</p>
              )}
              {finalizationStatus === "pending" && (
                <div className="card">
                  <p style={{ margin: 0, fontWeight: 600 }}>
                    Still finalising — you can safely close this window; your
                    receipt will complete next time you sign in.
                  </p>
                  <div className="button-row" style={{ marginTop: "0.75rem" }}>
                    <button
                      className="button button-secondary"
                      onClick={() => void runFinalization(deletionReceiptId ?? undefined)}
                    >
                      Try again now
                    </button>
                  </div>
                </div>
              )}
              {cvdrData && (
                <DeletionReceipt
                  receipt={cvdrData}
                  profileCanisterId={profileCanisterId}
                  finalizationStatus={finalizationStatus}
                  guard={guardReport}
                  onDone={() => {
                    setProfileData(null);
                    setProfileActor(null);
                    setProfileCanisterId(null);
                    setCvdrData(null);
                    setGuardReport(null);
                    setDeletionReceiptId(null);
                    setFinalizationStatus("idle");
                    setScreen("profile-deleted");
                  }}
                />
              )}
            </div>
          </>
        )}

        {/* Profile Deleted */}
        {screen === "profile-deleted" && (
          <div className="card">
            <h2>Profile Deleted</h2>
            <p className="muted">
              Your personal data has been cryptographically deleted. Your deletion receipt remains accessible for verification. To use DaffyDefs again, sign up with a new Internet Identity.
            </p>
            <div className="button-row">
              <button className="button button-secondary" onClick={handleLogout}>
                Sign Out
              </button>
            </div>
          </div>
        )}

        {/* Error */}
        {screen === "error" && (
          <div className="card">
            <h2>Something went wrong</h2>
            <p className="error">{error}</p>
            <div className="button-row">
              <button className="button button-secondary" onClick={handleLogout}>
                Sign Out & Retry
              </button>
            </div>
          </div>
        )}
      </main>

      <footer className="footer">
        <p>DaffyDefs v0.2.0 — Phase 3b</p>
      </footer>
    </div>
  );
}

export default App;
