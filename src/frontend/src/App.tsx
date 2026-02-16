import { useState, useEffect } from "react";
import { AuthClient } from "@dfinity/auth-client";
import { HttpAgent } from "@dfinity/agent";

// Environment-aware configuration
// DFX_NETWORK is injected by vite-plugin-environment from .env
const network = process.env.DFX_NETWORK || "local";
const isLocal = network === "local";

const host = isLocal ? "http://127.0.0.1:4943" : "https://icp-api.io";

// Internet Identity URL
// Local: points to the locally deployed II canister
// Mainnet: points to the real II service
const iiUrl = isLocal
  ? `http://${process.env.CANISTER_ID_INTERNET_IDENTITY}.localhost:4943`
  : "https://identity.ic0.app";

function App() {
  const [authClient, setAuthClient] = useState<AuthClient | null>(null);
  const [principal, setPrincipal] = useState<string | null>(null);
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Initialise the auth client on mount
  useEffect(() => {
    AuthClient.create().then(async (client) => {
      setAuthClient(client);

      // Check if already authenticated (session delegation still valid)
      const authenticated = await client.isAuthenticated();
      if (authenticated) {
        const identity = client.getIdentity();
        setPrincipal(identity.getPrincipal().toText());
        setIsAuthenticated(true);

        // In local dev, fetch the root key (required for local replica)
        // NEVER do this on mainnet — it's a security vulnerability
        if (isLocal) {
          const agent = new HttpAgent({ host, identity });
          await agent.fetchRootKey();
        }
      }

      setLoading(false);
    });
  }, []);

  const handleLogin = async () => {
    if (!authClient) return;

    setError(null);

    try {
      await authClient.login({
        identityProvider: iiUrl,
        maxTimeToLive: BigInt(7 * 24 * 60 * 60 * 1000_000_000), // 7 days
        onSuccess: async () => {
          const identity = authClient.getIdentity();
          setPrincipal(identity.getPrincipal().toText());
          setIsAuthenticated(true);

          if (isLocal) {
            const agent = new HttpAgent({ host, identity });
            await agent.fetchRootKey();
          }
        },
        onError: (err) => {
          setError(`Login failed: ${err}`);
        },
      });
    } catch (e) {
      setError(`Login error: ${e}`);
    }
  };

  const handleLogout = async () => {
    if (!authClient) return;

    await authClient.logout();
    setPrincipal(null);
    setIsAuthenticated(false);
  };

  if (loading) {
    return (
      <div className="app">
        <p>Loading...</p>
      </div>
    );
  }

  return (
    <div className="app">
      <header className="header">
        <h1>DaffyDefs</h1>
        <p className="subtitle">Daffy definitions for daffy words</p>
      </header>

      <main className="main">
        {isAuthenticated ? (
          <div className="authenticated">
            <div className="session-info">
              <p>
                Signed in as:{" "}
                <code className="principal">
                  {principal?.slice(0, 10)}...{principal?.slice(-5)}
                </code>
              </p>
              <p className="network-badge">
                Network: <strong>{network}</strong>
              </p>
            </div>

            <div className="placeholder">
              <p>Bulletin board coming in Phase 3...</p>
            </div>

            <button className="button button-secondary" onClick={handleLogout}>
              Sign Out
            </button>
          </div>
        ) : (
          <div className="unauthenticated">
            <p>Sign in to create challenges, add definitions, and like your favourites.</p>
            <button className="button button-primary" onClick={handleLogin}>
              Sign In with Internet Identity
            </button>
          </div>
        )}

        {error && <p className="error">{error}</p>}
      </main>

      <footer className="footer">
        <p>DaffyDefs — Scaffold v0.1.0</p>
      </footer>
    </div>
  );
}

export default App;
