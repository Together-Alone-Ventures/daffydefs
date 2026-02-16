// ============================================================
// Client-side Display Name Resolution
// ============================================================
//
// Resolves author principals to display names by:
// 1. Factory.resolve(principal) → profile canister ID
// 2. ProfileCanister.get_display_name() → display name
//
// Caches results in-memory per session.
// Deterministic mapping per build plan:
//   - Active profile → display name string
//   - ProfileNotFound / canister error → "[unknown user]"
//   - Unauthenticated → truncated principal

import { Principal } from "@dfinity/principal";
import { HttpAgent } from "@dfinity/agent";
import { createProfileActor, isOk } from "./agent";

const UNKNOWN_USER = "[unknown user]";

// Session-level cache: principal text → resolved display name
const nameCache = new Map<string, string>();

/**
 * Truncate a principal for display (unauthenticated fallback)
 */
export function truncatePrincipal(principal: string | Principal): string {
  const text = typeof principal === "string" ? principal : principal.toText();
  if (text.length <= 15) return text;
  return `${text.slice(0, 5)}...${text.slice(-3)}`;
}

/**
 * Resolve a single principal to a display name.
 * Uses cache when available.
 */
export async function resolveDisplayName(
  principal: Principal,
  factoryActor: any,
  agent: HttpAgent
): Promise<string> {
  const key = principal.toText();

  // Check cache first
  const cached = nameCache.get(key);
  if (cached !== undefined) return cached;

  try {
    // Step 1: resolve principal → profile canister ID via factory
    const resolveResult = await factoryActor.resolve(principal);

    if (!isOk(resolveResult)) {
      nameCache.set(key, UNKNOWN_USER);
      return UNKNOWN_USER;
    }

    const profileCanisterId = (resolveResult as any).Ok as Principal;

    // Step 2: get display name from the profile canister
    const profileActor = createProfileActor(agent, profileCanisterId);
    const displayNameResult = (await profileActor.get_display_name()) as [string] | [];

    if (displayNameResult.length > 0 && displayNameResult[0]) {
      nameCache.set(key, displayNameResult[0]);
      return displayNameResult[0];
    } else {
      nameCache.set(key, UNKNOWN_USER);
      return UNKNOWN_USER;
    }
  } catch (e) {
    // Network/transport error
    nameCache.set(key, UNKNOWN_USER);
    return UNKNOWN_USER;
  }
}

/**
 * Batch-resolve a list of unique principals.
 * Returns a Map<principalText, displayName>.
 */
export async function batchResolveDisplayNames(
  principals: Principal[],
  factoryActor: any,
  agent: HttpAgent
): Promise<Map<string, string>> {
  const results = new Map<string, string>();

  // Deduplicate
  const unique = [...new Set(principals.map((p) => p.toText()))];

  // Resolve in parallel (bounded concurrency)
  const BATCH_SIZE = 5;
  for (let i = 0; i < unique.length; i += BATCH_SIZE) {
    const batch = unique.slice(i, i + BATCH_SIZE);
    const promises = batch.map(async (principalText) => {
      const p = Principal.fromText(principalText);
      const name = await resolveDisplayName(p, factoryActor, agent);
      results.set(principalText, name);
    });
    await Promise.all(promises);
  }

  return results;
}

/**
 * Clear the display name cache (e.g., on logout)
 */
export function clearNameCache() {
  nameCache.clear();
}
