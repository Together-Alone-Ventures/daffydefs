import { useState, useEffect, useCallback } from "react";
import { AuthClient } from "@dfinity/auth-client";
import { Principal } from "@dfinity/principal";
import {
  createAgent,
  createFactoryActor,
  createProfileActor,
  isOk,
  getError,
  II_URL,
  isLocal,
} from "./ic/agent";
import ProfileSetup from "./components/ProfileSetup";
import ProfileView from "./components/ProfileView";
import "./App.css";

// ============================================================
// App state types
// ============================================================

type Screen =
  | "loading"
  | "unauthenticated"
  | "initializing"     // authenticated, loading profile canister
  | "profile-setup"    // has canister but no profile data yet
  | "profile-view"     // has active profile
  | "profile-deleted"  // profile was deleted, offer rejoin
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
  const [principal, setPrincipal] = useState<string | null>(null);
  const [screen, setScreen] = useState<Screen>("loading");
  const [error, setError] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [actionLoading, setActionLoading] = useState(false);

  // Profile state
  const [profileCanisterId, setProfileCanisterId] = useState<string | null>(null);
  const [profileData, setProfileData] = useState<ProfileData | null>(null);

  // Actors (set after auth)
  const [factoryActor, setFactoryActor] = useState<any>(null);
  const [profileActor, setProfileActor] = useState<any>(null);

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
        setScreen("unauthenticated");
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

      // Create agent
      const agent = await createAgent(identity);

      // Create factory actor
      const factory = createFactoryActor(agent);
      setFactoryActor(factory);

      // Get or create profile canister
      const result = await factory.get_or_create_profile_canister();

      if (isOk(result as any)) {
        const canisterId = (result as any).Ok as Principal;
        const canisterIdText = canisterId.toText();
        setProfileCanisterId(canisterIdText);

        // Create dynamic actor for this user's profile canister
        const profActor = createProfileActor(agent, canisterId);
        setProfileActor(profActor);

        // Load profile data
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
  // Load profile from the user's profile canister
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
        setScreen("profile-view");
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
    setPrincipal(null);
    setProfileCanisterId(null);
    setProfileData(null);
    setProfileActor(null);
    setFactoryActor(null);
    setScreen("unauthenticated");
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
        setScreen("profile-view");
      } else {
        setActionError(getError(result));
      }
    } catch (e: any) {
      setActionError(`Save failed: ${e.message || e}`);
    } finally {
      setActionLoading(false);
    }
  };

  const handleUpdateProfile = async (input: {
    email: string;
    birthdate: string;
    gender: string;
    display_name: string;
  }) => {
    await handleSaveProfile(input);
  };

  const handleDeleteProfile = async () => {
    if (!factoryActor) return;
    setActionLoading(true);
    setActionError(null);

    try {
      const result = await factoryActor.delete_profile_canister();
      if (isOk(result as any)) {
        setProfileData(null);
        setProfileActor(null);
        setProfileCanisterId(null);
        setScreen("profile-deleted");
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
    if (!authClient) return;
    setActionLoading(true);
    setActionError(null);

    try {
      await handleAuthenticated(authClient);
    } catch (e: any) {
      setActionError(`Rejoin failed: ${e.message || e}`);
    } finally {
      setActionLoading(false);
    }
  };

  // ----------------------------------------------------------
  // Render
  // ----------------------------------------------------------

  return (
    <div className="app">
      <header className="header">
        <h1>DaffyDefs</h1>
        <p className="subtitle">Daffy definitions for daffy words</p>
      </header>

      {principal && screen !== "unauthenticated" && screen !== "loading" && (
        <div className="session-bar">
          <span className="principal-display">
            {principal.slice(0, 8)}...{principal.slice(-5)}
          </span>
          {isLocal && <span className="network-badge">local</span>}
          <button className="button-link" onClick={handleLogout}>
            Sign Out
          </button>
        </div>
      )}

      <main className="main">
        {screen === "loading" && (
          <div className="center-message">
            <p>Loading...</p>
          </div>
        )}

        {screen === "unauthenticated" && (
          <div className="center-message">
            <p>Sign in to create challenges, add definitions, and like your favourites.</p>
            <button className="button button-primary" onClick={handleLogin}>
              Sign In with Internet Identity
            </button>
            {error && <p className="error">{error}</p>}
          </div>
        )}

        {screen === "initializing" && (
          <div className="center-message">
            <p>Setting up your profile canister...</p>
            <div className="spinner" />
          </div>
        )}

        {screen === "profile-setup" && (
          <ProfileSetup
            onSave={handleSaveProfile}
            loading={actionLoading}
            error={actionError}
          />
        )}

        {screen === "profile-view" && profileData && profileCanisterId && (
          <ProfileView
            profile={profileData}
            profileCanisterId={profileCanisterId}
            onUpdate={handleUpdateProfile}
            onDelete={handleDeleteProfile}
            loading={actionLoading}
            error={actionError}
          />
        )}

        {screen === "profile-deleted" && (
          <div className="card">
            <h2>Profile Deleted</h2>
            <p className="muted">
              Your profile canister has been permanently deleted. Your challenges and comments
              on the bulletin board remain but will show as "[deleted user]".
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
        <p>DaffyDefs v0.1.0 — Phase 3a</p>
      </footer>
    </div>
  );
}

export default App;
