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

  // Profile state
  const [profileCanisterId, setProfileCanisterId] = useState<string | null>(null);
  const [profileData, setProfileData] = useState<ProfileData | null>(null);

  // Actors
  const [factoryActor, setFactoryActor] = useState<any>(null);
  const [boardActor, setBoardActor] = useState<any>(null);
  const [profileActor, setProfileActor] = useState<any>(null);

  // Navigation state
  const [selectedChallengeId, setSelectedChallengeId] = useState<bigint | null>(null);

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
    try {
      // Call the profile canister's delete_profile (MKTd02 tombstone + receipt)
      const result = await profileActor.delete_profile();
      if (isOk(result as any)) {
        // result.Ok is the receipt_id (hex string)
        const receiptId = (result as any).Ok;

        // Fetch the full CVDR
        const receiptResult = await profileActor.mktd_get_receipt(receiptId);
        if (receiptResult && receiptResult.length > 0 && receiptResult[0]) {
          const r = receiptResult[0];
          setCvdrData({
            receipt_id: r.receipt_id,
            canister_id: r.canister_id.toText(),
            subnet_id: r.subnet_id.toText(),
            commit_mode: r.commit_mode,
            pre_state_hash: r.pre_state_hash,
            post_state_hash: r.post_state_hash,
            tombstone_hash: r.tombstone_hash,
            deletion_event_hash: r.deletion_event_hash,
            certified_commitment: r.certified_commitment,
            manifest_hash: r.manifest_hash,
            module_hash: r.module_hash,
            timestamp: r.timestamp,
            nonce: r.nonce,
          });
          setScreen("deletion-receipt");
        } else {
          // Receipt created but couldn't fetch it — still show success
          setActionError(
            `Profile deleted. Receipt ID: ${receiptId} (could not fetch full receipt)`
          );
          setScreen("profile-deleted");
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

const handleRejoin = async () => {
    if (!agent) return;
    setActionLoading(true);
    setActionError(null);
    try {
      const factoryActor = createFactoryActor(agent);

      // 1. Unmap the old tombstoned canister (CVDR preserved)
      const unmapResult = await factoryActor.unmap_deleted_profile();
      if (!isOk(unmapResult)) {
        throw new Error(getError(unmapResult));
      }

      // 2. Create fresh canister
      const createResult = await factoryActor.get_or_create_profile_canister();
      if (!isOk(createResult)) {
        throw new Error(getError(createResult));
      }

      // 3. Navigate to profile setup
      setScreen("profile-setup");
    } catch (e: any) {
      setActionError(`Rejoin failed: ${e.message || e}`);
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

      {screen === "deletion-receipt" && cvdrData && profileCanisterId && (
              <>
                <nav className="top-bar">
                  <span className="username">Account Deleted</span>
                </nav>
                <main className="main-content">
                  <DeletionReceipt
                    receipt={cvdrData}
                    profileCanisterId={profileCanisterId}
                    onDone={() => {
                      setProfileData(null);
                      setProfileActor(null);
                      setProfileCanisterId(null);
                      setCvdrData(null);
                      setScreen("profile-deleted");
                    }}
                  />
                </main>
              </>
            )}

                {/* Profile Deleted */}
        {screen === "profile-deleted" && (
          <div className="card">
            <h2>Profile Deleted</h2>
            <p className="muted">
              Your profile data has been cryptographically deleted. Your deletion receipt remains accessible for verification.
            </p>
            <div className="button-row">
              <button
                className="button button-primary"
                onClick={handleRejoin}
                disabled={actionLoading}
              >
                {actionLoading ? "Rejoining..." : "Rejoin with New Profile"}
              </button>
              <button className="button button-secondary" onClick={handleLogout}>
                Sign Out
              </button>
            </div>
            {actionError && <p className="error">{actionError}</p>}
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
