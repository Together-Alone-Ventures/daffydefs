import { useState, useEffect, useCallback } from "react";
import { AuthClient } from "@dfinity/auth-client";
import { HttpAgent } from "@dfinity/agent";
import { Principal } from "@dfinity/principal";
import {
  createAgent,
  createFactoryActor,
  createBoardActor,
  createProfileActor,
  isOk,
  getError,
  II_URL,
  isLocal,
} from "./ic/agent";
import { clearNameCache } from "./ic/resolve";
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

type FinalizationStatus = "idle" | "finalizing" | "finalized" | "pending";

// ============================================================
// Helper: treat a receipt as finalized if BLS cert is present
// ============================================================

const isReceiptFinalized = (r: any): boolean =>
  !!(
    r &&
    r.bls_certificate &&
    r.bls_certificate.length > 0 &&
    r.trust_root_key_id &&
    String(r.trust_root_key_id).length > 0
  );

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

  // Profile state
  const [profileCanisterId, setProfileCanisterId] = useState<string | null>(null);
  const [profileData, setProfileData] = useState<ProfileData | null>(null);

  // Actors
  const [factoryActor, setFactoryActor] = useState<any>(null);
  const [boardActor, setBoardActor] = useState<any>(null);
  const [profileActor, setProfileActor] = useState<any>(null);

  // Navigation state
  const [selectedChallengeId, setSelectedChallengeId] = useState<bigint | null>(null);

  const mapReceiptToCvdr = useCallback((r: any): CvdrData => {
    const bytesToHex = (bytes: Array<number> | Uint8Array): string =>
      Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
    const recordIdRaw = r.record_id && r.record_id.length > 0 ? r.record_id : null;
    return {
      protocol_version: r.protocol_version,
      receipt_id: r.receipt_id,
      canister_id: r.canister_id.toText(),
      record_id: recordIdRaw ? bytesToHex(recordIdRaw) : "",
      pre_state_hash: r.pre_state_hash,
      post_state_hash: r.post_state_hash,
      tombstone_hash: r.tombstone_hash,
      deletion_event_hash: r.deletion_event_hash,
      certified_commitment: r.certified_commitment,
      module_hash: r.module_hash,
      timestamp: r.timestamp,
      deletion_seq: r.deletion_seq,
      bls_certificate:
        r.bls_certificate && r.bls_certificate.length > 0 ? r.bls_certificate[0] : null,
      trust_root_key_id: r.trust_root_key_id,
    };
  }, []);

  const finalizeReceiptInBackground = useCallback(async (receiptId: string) => {
    if (!profileActor || !profileCanisterId) return;

    // FIX 3: Short-circuit if receipt is already finalized — prevents
    // a second background call from driving status back to "pending".
    try {
      const existingReceipt = await profileActor.mktd_get_receipt(receiptId);
      const existing = existingReceipt && existingReceipt.length > 0 ? existingReceipt[0] : null;
      if (existing && isReceiptFinalized(existing)) {
        setCvdrData(mapReceiptToCvdr(existing));
        setFinalizationStatus("finalized");
        return;
      }
    } catch {
      // continue into normal retry path
    }

    // Phase C (finalization) is NOT performed in the browser. Under Plan v2.1 A4
    // the browser may TRIGGER Phase A (deletion) but never SUBMITS Phase C: the
    // finalize inputs include a subnet read_state certificate over
    // /canister/<id>/module_hash that is fetched off-canister by the operator's
    // verification tooling, which the browser cannot produce. This path is
    // therefore display-only — "finalized" if the operator has already finalized
    // (checked above), otherwise the transitional pending-finalization state.
    setFinalizationStatus("pending");
  }, [mapReceiptToCvdr, profileActor, profileCanisterId]);

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

  useEffect(() => {
    if (profileActor && profileCanisterId) {
      const recoverPendingFinalization = async () => {
        try {
          const isPending = await profileActor.mktd_is_pending();
          if (!isPending) return;

          const certResult = await profileActor.mktd_get_certificate();
          const cert = certResult && certResult.length > 0 ? certResult[0] : null;
          if (cert?.receipt_id) {
            void finalizeReceiptInBackground(cert.receipt_id);
          } else {
            setFinalizationStatus("pending");
          }
        } catch {
          setFinalizationStatus("pending");
        }
      };

      void recoverPendingFinalization();
    }
    // NOTE: finalizeReceiptInBackground intentionally omitted from deps here.
    // Including it caused the effect to re-fire on every render during the
    // deletion flow, launching a second background finalization that raced
    // the first and drove status back to "pending".
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [profileActor, profileCanisterId]);

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
    setActionLoading(true);
    setActionError(null);
    setFinalizationStatus("idle");
    setCvdrData(null);
    setDeletionReceiptId(null);

    try {
      const result = await profileActor.delete_profile();
      console.info("[delete-flow] delete_profile raw result", result);
      if (isOk(result as any)) {
        const receiptIdRaw = (result as any).Ok;
        if (typeof receiptIdRaw !== "string" || receiptIdRaw.length === 0) {
          setActionError("Delete succeeded but returned an invalid receipt ID");
          return;
        }

        const receiptId = receiptIdRaw;
        console.info("[delete-flow] extracted receiptId", receiptId);
        setDeletionReceiptId(receiptId);
        setScreen("deletion-receipt");

        // FIX 1 + FIX 2: Only launch background finalization if the receipt
        // is not already finalized. If it is, set "finalized" immediately and
        // return — do not hand off to the background function at all.
        const receiptResult = await profileActor.mktd_get_receipt(receiptId);
        console.info("[delete-flow] initial mktd_get_receipt raw result", receiptResult);

        if (receiptResult && receiptResult.length > 0 && receiptResult[0]) {
          const receipt = receiptResult[0];
          setCvdrData(mapReceiptToCvdr(receipt));

          if (isReceiptFinalized(receipt)) {
            setFinalizationStatus("finalized");
            return;
          }

          // Receipt exists but BLS cert not yet present — kick off finalization.
          setFinalizationStatus("pending");
          void finalizeReceiptInBackground(receiptId);
        } else {
          // Receipt not yet in store — kick off finalization.
          setFinalizationStatus("pending");
          void finalizeReceiptInBackground(receiptId);
        }
      } else {
        setActionError(getError(result as any));
      }
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
            <nav className="top-bar">
              <span className="username">Account Deleted</span>
            </nav>
            {/* FIX 5: was a nested <main>, changed to <div> */}
            <div className="main-content">
              {!cvdrData && (
                <div className="card">
                  <h2 style={{ color: "#4ade80" }}>Profile Deleted — Deletion Receipt</h2>
                  <p className="muted">
                    Loading receipt
                    {deletionReceiptId ? ` (${deletionReceiptId})` : ""}...
                  </p>
                  <div className="profile-field">
                    <span className="field-label">BLS Certificate</span>
                    <span className="field-value mono">Loading...</span>
                  </div>
                </div>
              )}
              {finalizationStatus === "finalized" && (
                <p className="muted">Finalized</p>
              )}
              {finalizationStatus === "pending" && (
                <div className="card">
                  <p style={{ margin: 0, fontWeight: 600 }}>
                    Deletion recorded — finalization is completed by the operator's
                    verification tooling and will appear here once finalized.
                  </p>
                </div>
              )}
              {cvdrData && (
                <DeletionReceipt
                  receipt={cvdrData}
                  profileCanisterId={profileCanisterId}
                  finalizationStatus={finalizationStatus}
                  onDone={() => {
                    setProfileData(null);
                    setProfileActor(null);
                    setProfileCanisterId(null);
                    setCvdrData(null);
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
