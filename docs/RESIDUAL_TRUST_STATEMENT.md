# DaffyDefs — Residual Trust Statement

DaffyDefs is a demonstration application for ICP-Delete (Leaf). A user deleting a DaffyDefs profile can receive a Cryptographically Verifiable Deletion Receipt (CVDR).

## What the current checks establish

- **V1 — internal consistency:** the receipt's cryptographic relationships recompute correctly.
- **V2 — certified deletion-event evidence:** the deletion-event hash is backed by a valid IC certificate/delegation path for the relevant canister.
- **V3A — attested code identity:** the receipt preserves subnet-certified evidence of the profile canister module hash at finalisation time.
- **V3B — supplementary/non-gating build provenance:** an independent verifier rebuilds the profile WASM from the disclosed source/dependencies/toolchain/recipe and obtains the same hash as the receipt-attested module hash.

The supplied reference verifier evaluates V1, V2 and V3A for v5 validity with an explicitly selected trust root (`--trust-root mainnet` for this demo). V3B is supplementary/non-gating and is not evaluated without supplied build provenance.

## Internet Computer trust root and subnet residual

V2 and V3A ultimately rely on the public Internet Computer trust root and on the security assumptions of the subnet/NNS certificate system.

The subnet certifies **state**: the deletion-event hash and the canister module-hash state witnessed by the certificates. It does not independently observe or certify a physical "deletion act" outside that state model.

A successful CVDR verification therefore means the cryptographic state/evidence claims validate under the IC trust root; it is not an oracle for data copies outside the certified system boundary.

## Profile-WASM provenance boundary

The receipt's code-identity/provenance claim is about the **profile canister** identified by that receipt.

Byte-exact reproducibility is required for the final post-shrink `profile_canister.wasm`.

The profile factory, bulletin board, frontend, and reference verifier are outside that receipt's profile-WASM provenance boundary.

## Finalisation client

DaffyDefs uses the browser as the normal finalisation client. The browser is **not a trust anchor** for receipt validity. A modified or faulty client cannot make an invalid receipt valid.

Lazy repair on a later authenticated visit provides a recovery path if the browser is closed before finalisation completes.

## Operator control

The DaffyDefs operator controls the application canisters and can upgrade or stop them.

A later profile-canister upgrade can change the live module hash. That does not erase the archived module-hash certificate preserved by an already-finalised receipt.

## Live corroboration

A verifier may independently read the current profile canister module hash from ICP.

That is useful corroboration but is not a substitute for the archived code-identity evidence in an older receipt and is not V3B source provenance.

## Tombstone persistence

Tombstone persistence is informational and non-gating in the current DaffyDefs reference tool. A transport failure or tombstone-diagnostic failure does not become an integrity PASS; it simply does not alter the V1/V2/V3A validity result.

## Source/build provenance

The DaffyDefs repository includes the TAV-specific source required for the profile build. Public Rust dependencies are resolved through the committed `Cargo.lock` from ordinary public distribution infrastructure.

The released profile build is pinned to Rust `1.97.1` and `ic-wasm 0.11.1`; the canonical procedure is `scripts/build-profile-repro.sh`.

The product/build provenance anchor used for the accepted deployment is:

`e2b073971aae5f1c97edee59875bec15628821c7`

The released post-shrink profile hash is:

`30496752f6da4e2badf1cc50f6ac1a23cb567d08d4225038c0fa4b8a539dddeb`

The canonical build reproduced that hash. The accepted receipt from profile `petd6-ciaaa-aaaaj-qshha-cai` V3A-attests the same module hash; see the current release record and dated ceremony evidence.

No physically distinct-hardware reproduction is claimed.

## Application-data scope

Deleting a DaffyDefs profile proves the deletion/tombstoning claim for the profile state handled by the per-user profile canister.

Shared bulletin-board content is outside that narrow profile proof. Historical shared content may remain in application state in an orphaned/de-identified presentation. A profile-deletion CVDR must not be described as proof that every piece of shared application content associated with the user has been erased.

Copies that have already left the canister/application boundary — for example client caches, screenshots, exports, third-party scrapes, backups outside the proved system, or other independently retained copies — are outside the CVDR's scope unless a separate proof mechanism explicitly covers them.

## Reference verifier

The supplied verifier executable is a convenience implementation, not a trust anchor and not a compliance certification.

A verifier may inspect the source, run the supplied binary, build the source themselves, or independently implement the published verification procedure.

No claim is made that the supplied verifier binary itself has undergone a separate reproducible-build provenance exercise.

## Remaining availability dependency

Standard public Rust dependencies are not copied wholesale into the application repository. Their identity is lockfile/checksum constrained; their future availability depends on ordinary public software distribution/archive infrastructure.
