// ============================================================
// IC Agent Configuration & Actor Construction
// ============================================================

import { HttpAgent, Actor, type Identity } from "@dfinity/agent";
import { Principal } from "@dfinity/principal";
import { idlFactory as factoryIdl } from "./factory.did";
import { idlFactory as profileIdl } from "./profile.did";
import { idlFactory as boardIdl } from "./board.did";

const DFX_NETWORK = process.env.DFX_NETWORK || "local";
export const isLocal = DFX_NETWORK === "local";

const host = isLocal ? "http://127.0.0.1:4943" : "https://icp-api.io";

const FACTORY_CANISTER_ID = process.env.CANISTER_ID_PROFILE_FACTORY || "";
const BOARD_CANISTER_ID = process.env.CANISTER_ID_BULLETIN_BOARD || "";

export const II_URL = isLocal
  ? `http://${process.env.CANISTER_ID_INTERNET_IDENTITY}.localhost:4943`
  : "https://identity.ic0.app";

// ============================================================
// Agent creation
// ============================================================

let _agent: HttpAgent | null = null;

export async function createAgent(identity: Identity): Promise<HttpAgent> {
  const agent = await HttpAgent.create({ host, identity });
  if (isLocal) {
    await agent.fetchRootKey();
  }
  _agent = agent;
  return agent;
}

export function getAgent(): HttpAgent | null {
  return _agent;
}

let _anonAgent: HttpAgent | null = null;

/**
 * Anonymous agent, used for `read_state` of public subnet state such as
 * /canister/<id>/module_hash. Kept separate from the authenticated agent on
 * purpose: reading a module hash needs no delegated authority, so it should not
 * borrow the user's.
 */
export async function getAnonymousAgent(): Promise<HttpAgent> {
  if (_anonAgent) return _anonAgent;
  const agent = await HttpAgent.create({ host });
  if (isLocal) {
    await agent.fetchRootKey();
  }
  _anonAgent = agent;
  return agent;
}

// ============================================================
// Actor factories
// ============================================================

export function createFactoryActor(agent: HttpAgent) {
  return Actor.createActor(factoryIdl, {
    agent,
    canisterId: FACTORY_CANISTER_ID,
  });
}

export function createBoardActor(agent: HttpAgent) {
  return Actor.createActor(boardIdl, {
    agent,
    canisterId: BOARD_CANISTER_ID,
  });
}

export function createProfileActor(agent: HttpAgent, canisterId: string | Principal) {
  return Actor.createActor(profileIdl, {
    agent,
    canisterId: typeof canisterId === "string" ? canisterId : canisterId.toText(),
  });
}

// ============================================================
// Type helpers for Candid Result variants
// ============================================================

export type CandidResult<T> = { Ok: T } | { Err: CandidError };
export type CandidError = {
  [key: string]: { message: string };
};

export function isOk<T>(result: CandidResult<T>): result is { Ok: T } {
  return "Ok" in result;
}

export function getError(result: CandidResult<unknown>): string {
  if ("Err" in result) {
    const err = result.Err;
    const variant = Object.keys(err)[0];
    const msg = (err as any)[variant]?.message || "Unknown error";
    return `${variant}: ${msg}`;
  }
  return "Unknown error";
}
