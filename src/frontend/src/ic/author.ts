// ============================================================
// Author presentation
// ============================================================
//
// DD2 (docs/rulings/2026-09-27-dd2-non-identifying-record-id.md §7): the
// factory no longer resolves another user's principal to a profile canister,
// so the board labels authors only from data it already publishes: the
// author principal. No canister call is made and nothing is cached.

import { Principal } from "@dfinity/principal";

/** Short form of a principal: `abcde...xyz`. */
export function truncatePrincipal(principal: string | Principal): string {
  const text = typeof principal === "string" ? principal : principal.toText();
  if (text.length <= 15) return text;
  return `${text.slice(0, 5)}...${text.slice(-3)}`;
}

/** Author label: "you" for the signed-in user, otherwise the short principal. */
export function authorLabel(author: Principal, myPrincipal: string | null): string {
  const text = author.toText();
  if (myPrincipal !== null && text === myPrincipal) return "you";
  return truncatePrincipal(text);
}
