# DaffyDefs demo-capsule audit — 15 Aug 2026

## Publication-safety review

### Secrets

A full-history Gitleaks scan covered all refs and 95 commits.

Three findings were reviewed:

1. PocketIC test fixture `root_key_hex` — public test trust-root material, not a credential.
2. Product `vendor/zombie-core/.cargo-checksum.json` — Cargo integrity hashes.
3. Verifier `vendor/zombie-core/.cargo-checksum.json` — Cargo integrity hashes.

Result: **0 exposed secrets.** No credential rotation or history rewrite is required.

### Dependencies

OSV-Scanner 2.5.0 was run against the exact verified dependency locks.

- Frontend: 14 advisories across 6 packages, all identified in the lockfile as dev/build dependencies. No deployed-profile V4 impact. Refresh deferred outside the provenance freeze.
- Product Rust: `anyhow 1.0.102` and `paste 1.0.15`. The affected `anyhow::Error::downcast_mut` pattern is absent from the relevant product source; `paste` is a maintenance/unmaintained advisory. No reason was found to alter the proven profile dependency resolution.
- Reference verifier: lockfile advisories include target/feature-specific packages. `quinn-proto` is absent from the actual Linux build graph. No explicit CRL/revocation handling or affected rand/custom-logger pattern is present. `rustls-webpki` remains in the verifier's HTTPS stack; a verifier dependency refresh is deferred to the post-demo CVDR-Verify maintenance line.

Result: **no dependency finding was ruled a demo-freeze blocker.**

No dependency lockfile was modified during this audit.

### Licence / IP

No top-level licence or notice file is currently present. No licence is invented by this technical freeze pass; licence selection remains a TAV publication/policy decision.

The focused publication wording sweep found no confidential, proprietary, trade-secret, patent-pending or invention disclosure language requiring removal.

No tracked credential/key-like filenames were found.

## Provenance and live acceptance

- Product/build provenance anchor: `14fb08c40f42419a4ca767982c8f797351025ff1`.
- Released profile-WASM hash: `cb16ee538cd0dfc13ea3847a04b4b6c05f29ff9ad764d65cb52b9619a4af28c9`.
- Live factory hash: `837a44b3ece8b901ad1af305a1252f6bd53d93819e81ea288584e547e970699a`.
- Fresh profile: `5ff4g-7qaaa-aaaaj-qsehq-cai`.
- Fresh receipt: `050f152899a866cd16cf3b7b9f3d49f17ae6d58499ac27d3fb7793dabc0963e6`.
- Exact banked receipt SHA-256: `add5a6c5f3a996fa6e24184823e74ea1ff1bef0949fb86dff91b1cf04d2bf3e2`.
- Reference verifier: V1 PASS; V2 PASS; V3 SUBNET-ATTESTED; exit 0.
- Live ICP module corroboration: MATCH.
- Independent V4 rebuild: PASS; rebuilt profile hash equals the fresh receipt-attested hash.
- Reproduction qualification: same-host plus pinned Debian tracked-files-only container; no physically distinct-hardware reproduction claimed.

## Governance note

For the 15 Aug 2026 deployment/acceptance session, the encrypted `zd-deployer` identity available on the laptop was verified to resolve exactly to the sole controller principal before use.

The earlier controller-environment assumption that deployment had to occur only from the desktop is therefore superseded for this ceremony record.

The acceptance used fail-closed preflight checks and certified post-deployment state reads. No controller change was made.

## Release-pack closeout

The DaffyDefs demo capsule was frozen at commit `a386840de7feedb097a66a5e68285593b3a0c8f5`.

The reviewed `vnext-self-contained-baseline` branch was pushed first. `main` was then fast-forwarded to the same commit with no merge commit and no force push. At closeout the two branches were identical.

The Demo Pack, current acceptance evidence, release record and verification documentation are therefore aligned to the reviewed release-pack state. The clean Demo-Pack-only outsider walkthrough completed successfully through V1–V4.

Remaining items are intentionally deferred policy/maintenance work, not release-pack blockers:

- TAV licence selection before any intended open-source grant;
- dependency refreshes after the frozen demo/provenance line;
- wider documentation cleanup and upstream CVDR-Verify realignment as separate maintenance work.

## Demo-Pack-only outsider walkthrough — 15 August 2026

A clean-directory walkthrough was completed using `docs/DEMO_PACK.md`, public Internet resources, and a newly generated mainnet deletion receipt. The development checkout was not used to supply the verifier, receipt verification result, source archive, or rebuilt profile WASM.

Observed fresh receipt:

- receipt file: `deletion-receipt-efa96d26.json`
- receipt id: `efa96d26fc646db49890585193b6a1b9c7f0780a908ce72a24a7b729e1a5c58c`
- profile canister: `7d5ol-waaaa-aaaaj-qsekq-cai`
- V1: PASS
- V2: PASS (receipt-contained certificate path)
- V3: SUBNET-ATTESTED
- V4: established by the published source/build procedure
- published release hash, fresh receipt `module_hash`, anonymous live-canister module hash, and independently rebuilt post-shrink profile WASM SHA-256 all matched:
  `cb16ee538cd0dfc13ea3847a04b4b6c05f29ff9ad764d65cb52b9619a4af28c9`

The walkthrough also independently downloaded the packaged Linux x86_64 reference verifier from the public repository at provenance anchor `14fb08c40f42419a4ca767982c8f797351025ff1` and confirmed:

- version: `mktd02-verify 0.6.1`
- SHA-256: `c355fe7e92a2c7db1862fb7dfa55822efc53659739abac69648cc741db7b037f`

One real documentation usability defect was found and corrected during the walkthrough: the Demo Pack named the verifier path but did not give a direct public download command for a clean outsider.

The optional live-state command emitted a `dfx is deprecated, use icp-cli` warning. The command still returned the expected controller and module hash; this warning is a client-tool deprecation notice, not a verification failure.

Qualification: this was a clean same-host outsider walkthrough, not a reproduction on physically distinct hardware. No such distinct-hardware claim is made. The fresh walkthrough receipt is usability evidence and is not added to the repository acceptance-receipt set.
