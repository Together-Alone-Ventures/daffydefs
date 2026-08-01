# DaffyDefs — Residual Trust Statement and Verification Procedure

DaffyDefs is a demonstration application for ICP-Delete(Leaf). It issues a
Cryptographically Verifiable Deletion Receipt (CVDR) when a user deletes their
profile. This document states what a CVDR does and does not prove, what trust
remains with the operator, and how anyone can verify a receipt independently.

## Product statement

> ICP-Delete(Leaf) requires an off-canister finalisation client, but does not
> require a separate hosted finalisation service. The normal client may be the
> application frontend; production deployments additionally provide a
> deployer-operated retry worker for liveness. The finalisation client is
> outside the CVDR trust and verification boundary.

In DaffyDefs the finalisation client is the browser. After the user confirms
deletion, the frontend completes the remaining phases: it reads the pending
certificate from the profile canister, performs an anonymous `read_state` for
that canister's `module_hash`, and submits both certificates to the factory's
finalisation proxy, which forwards them to the profile canister.

## What the receipt proves

A CVDR is a claim about on-chain state, signed by the subnet. Verification
recomputes the state-transition hashes, checks the embedded certificates against
the Internet Computer root key, and compares the certified module hash against
the published one. Those checks are performed by the verifier, from the receipt
file and live chain state — not by the application that produced it.

## Residual trust

### The finalisation client is not trusted

The browser guard (checks G1–G5b) runs before submission: it asserts the
module-hash certificate witnesses the expected path for the receipt's own
canister, that the certified module hash equals the receipt's embedded hash,
that the Phase B certificate validates under the same trust anchor and that its
delegation authorises the canister, that the certified commitment matches the
pending receipt, and that the module-hash certificate is not older than the
commitment certificate.

**This guard is client-side integrity for the honest path. It is not
enforcement.** Certificates are stored opaquely on-chain: the profile canister
does not parse them, and the factory checks only that each blob is between 1 and
4096 bytes. Nothing in the guard is re-executed by any canister, and a modified
client could skip it entirely.

The guard therefore protects against a correct client submitting inconsistent
inputs. It does not, and cannot, establish that a receipt is sound.
**Independent verification with CVDR-Verify is the sole authority on whether a
receipt is valid.** A receipt that fails verification is invalid regardless of
what the client reported at the time.

### The operator controls the canisters

The factory is the controller of every profile canister and can stop, delete or
upgrade them. Users are authorised at the application level, not by the
platform. A user cannot prevent an operator from destroying a profile canister
after deletion; what they retain is the downloaded receipt, which verifies
against chain state and the published module hash independently of whether the
canister still exists.

## Operator warnings

### `unmap_deleted_profile` strands pending receipts

The factory exposes `unmap_deleted_profile` (`src/profile_factory/src/lib.rs:513`).
It removes the principal → canister mapping **with no pending-receipt check**.

Calling it while a receipt is still pending strands that receipt permanently.
Once the mapping is gone, `get_or_create_profile_canister` mints a fresh canister
for that principal, and the `is_managed` check inside `finalize_profile_receipt`
can never match the old canister again. The pending receipt becomes
unfinalisable — no client, worker or operator tool can complete it.

It must only be called after confirming, from the receipt itself, that
finalisation is complete and both certificate fields are present. The browser
IDL deliberately omits this method so the frontend cannot reach it.

### O-1: a pending receipt blocks canister upgrade

While a receipt is pending, the finalization lock is held, and any operation
that would change certified data traps. Upgrading a profile canister runs
`post_upgrade` → `on_post_upgrade` → `upgrade_cascade`, which republishes the
certified commitment and therefore traps:

> MKTd02: cannot change certified data while finalization lock is held.
> Finalize the pending receipt before upgrading, refreshing state, or
> performing any action that changes certified data.

This is a hard invariant, not a race. Finalise pending receipts before
upgrading.

Relaxing this trap would not make upgrades safe. The lock exists to stop
certified data drifting between Phase A and Phase C. If the commitment can move
while a receipt is pending, the certificate captured at Phase B no longer
describes the state the receipt claims, and G2's comparison of certified against
embedded module hash loses its meaning. Removing the trap converts a blocked
upgrade — loud, immediate, recoverable — into a finalisation failure discovered
later, or a receipt that verifies against the wrong code identity. The trap may
only be relaxed as part of a redesign of G2's semantics.

## Liveness posture

DaffyDefs is a demonstration and its finalisation liveness is best-effort.

- Deletion itself is durable as soon as Phase A completes. The data is
  tombstoned on-chain and the receipt exists; only the certificates that
  complete it may still be outstanding.
- If the browser is closed mid-flight, finalisation resumes automatically on the
  next authenticated visit. The user is not asked to re-authorise the deletion.
- A receipt whose owner never returns may remain Pending indefinitely. There is
  no background worker in this deployment.
- The operator can complete a stranded receipt out-of-band using the
  off-canister finalisation CLI, which performs the same phases and the same
  guard.

The interface reflects this. Deletion-complete language and the download control
appear only after the receipt has been re-read from the canister and confirmed
finalised with both certificates present.

## Verification procedure

Anyone holding a downloaded receipt can verify it without access to DaffyDefs,
its operator, or any credential.

**Requirements:** the `mktd02-verify` binary from CVDR-Verify, and network access
to a public Internet Computer endpoint.

```bash
mktd02-verify --receipt-file deletion-receipt-<id>.json \
              --network https://icp-api.io
```

Verify the file exactly as downloaded. Do not edit it — reformatting or
stripping fields can change the parse and invalidate the result.

To additionally compare the receipt's code identity against an independently
published module hash, supply it:

```bash
mktd02-verify --receipt-file deletion-receipt-<id>.json \
              --network https://icp-api.io \
              --wasm-hash <published-module-hash>
```

The published profile-canister module hash is recorded in `RELEASES.md`.
Supplying it turns the module check into a three-way comparison: on-chain,
receipt, and published must all agree.

### Reading the output

Verification reports several checks. A sound receipt shows the state-transition
hashes recomputed and matching, the embedded certificate valid with its
certified data matching the receipt's commitment, the module hash agreeing
across all supplied sources, and the code identity subnet-attested.

Both certificate fields must be present in the file. `module_hash_certificate`
is what the attested-code-identity check consumes; a receipt missing it cannot
reach an attested verdict even if everything else is sound.

### Check-label translation

Version 0.6.1 of the verifier predates the check renumbering. Its labels map as
follows:

| v0.6.1 label | Current meaning |
|---|---|
| `V1` | Unchanged — state-transition hashes |
| `V2` | Unchanged — certificate path |
| `V3-A` (attested) | Current **V3** — attested code identity |
| `V3` (module, live) | Current **V4** — provenance leg |
| `V4` (tombstone) | **Retired.** It still runs and passes; it is not a current claim |

A `MISMATCH-EXPECTED` result on the live module check means the canister has been
upgraded since the deletion. The receipt remains valid under the code version it
was issued against; the attested check is what establishes that code identity.

## Verified examples

`docs/acceptance/` holds two receipts produced by real mainnet deletions,
together with their complete verifier output. They can be used to see what a
sound verification looks like before checking your own.
