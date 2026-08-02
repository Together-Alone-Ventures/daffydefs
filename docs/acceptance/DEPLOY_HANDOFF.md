# Frontend deploy handoff — browser finalisation bundle

Date of record: 2026-08-02.

The frontend asset canister `5b3yq-gqaaa-aaaaj-qp4ta-cai` still serves the
pre-finalisation bundle `index-BRUYhh7h.js`. The browser finalisation bundle is
built and reproducible but has not been deployed. This document carries
everything the deploying session needs; no rediscovery should be required.

## Why this is a handoff

Commit permission on the asset canister is held by exactly one principal:

```
$ dfx canister call 5b3yq-gqaaa-aaaaj-qp4ta-cai list_permitted \
    '(record { permission = variant { Commit } })' --network ic --identity anonymous
(vec { principal "q3gkv-ebczt-uo3k7-hpxo2-rcx3m-w6cwl-ba5to-ynhbw-gfguh-ywsdh-dqe" })
```

The `Prepare` list is empty, and `q3gkv-…-dqe` is also the sole controller. That
principal is signer `zd-deployer` (RELEASES.md §W5), which lives only on the
desktop. The deploy must run there; the key is not to be imported elsewhere.

## 1. Check out

```
git checkout feat/browser-finalize-r1
git rev-parse HEAD    # must print b1c7ed36c90ea0d7c958561b0ab347a979601d66
```

Pushed to `origin` at `b1c7ed3`. Do not deploy from any other SHA.

## 2. Recreate `.env`

`.env` is gitignored (`.gitignore:21`), so a fresh checkout will not have it, and
`vite.config.ts` loads it via `dotenv` from the repo root. It contains no
secrets — only the network name and public canister IDs. Write this to the repo
root:

```
DFX_NETWORK=ic
CANISTER_ID_BULLETIN_BOARD=5iytm-qyaaa-aaaaj-qp4sq-cai
CANISTER_ID_PROFILE_FACTORY=5g26e-liaaa-aaaaj-qp4tq-cai
CANISTER_ID_FRONTEND=5b3yq-gqaaa-aaaaj-qp4ta-cai
CANISTER_ID_INTERNET_IDENTITY=rdmx6-jaaaa-aaaaa-aaadq-cai
```

Those five lines are sufficient to reproduce the artifact. The working copy's
`.env` also carries a dfx-generated trailing block (`DFX_VERSION='0.32.0'`, the
same four canister IDs re-quoted, `CANISTER_ID`, and a
`CANISTER_CANDID_PATH='/home/stef/tav/daffydefs/.dfx/ic/canisters/frontend/assetstorage.did'`).
That block is machine-specific and inert for the build:
`vite-plugin-environment` injects only `CANISTER_ID_BULLETIN_BOARD`,
`CANISTER_ID_PROFILE_FACTORY`, `CANISTER_ID_INTERNET_IDENTITY` and
`DFX_NETWORK`. Do not copy the absolute path across machines.

## 3. Build

```
cd src/frontend
npm ci
npm run build          # tsc && vite build
```

`src/frontend/dist/` is gitignored (`.gitignore:15`), so the checkout starts with
no `dist/` and this build step is mandatory.

## 4. Expected artifact

The build is reproducible. Verified 2026-08-02 by cloning the repo at `b1c7ed3`
into a clean directory, restoring the `.env` above, and running `npm ci &&
npm run build`: the result was byte-identical to the working copy across all
four output files (`diff -rq`, no differences).

```
7560cac98640a505826827f757436a5584e9289f72e94d445cfaf184a2bff0d0  dist/assets/index-CgOaQqdM.js
d282cae60d8b6cec8f2fd2cb848e04aa5adad457f8135d5bcd1140eae779b97c  dist/assets/index-DN8eZZYV.css
a35bdc2af12b95d6f8fcff039163379fae183ac645f0e06837dcffd95d9e3b93  dist/index.html
30bf68165690ea800da54faf04a439b2745edcd70a9cecc1322300676b26858e  dist/manifest.json
```

Toolchain of the reproduction run: Node v22.23.1, npm 10.9.8, vite 6.4.1.

**If `dist/assets/index-CgOaQqdM.js` is absent or its sha256 is not
`7560cac9…0d0`, stop and do not deploy.** A differing hash means the desktop is
building something other than the reviewed and accepted bundle.

## 5. Deploy

```
dfx deploy frontend --network ic --no-asset-upgrade --identity zd-deployer
```

`--no-asset-upgrade` is required: it uploads assets without reinstalling the
asset canister wasm, so the canister's own module hash must not change.

**Abort condition.** dfx prints a `Deploying:` line before uploading anything.
It must name `frontend` and nothing else:

```
Deploying: frontend
```

If any other canister appears — `bulletin_board`, `profile_factory`,
`profile_canister` — abort immediately and do not proceed. That was the failure
mode of the first attempt: `dfx.json` declared frontend dependencies which
expanded the deploy set to all three canisters. Commit `b1c7ed3` removed them,
so no canister in `dfx.json` now declares a `dependencies` key. A reappearance
means the fix has been reverted or the checkout is at the wrong SHA.

Do not re-run a partially completed deploy. If it fails midway, report the
failure rather than retrying.

Standing constraints for the deploying session: set
`DFX_WARNING=-mainnet_plaintext_identity` in-process only (do not persist it to a
shell profile), and keep identity output suppressed.

## 6. Post-deploy verification

**a. Origin serves the new bundle.**

```
curl -s https://5b3yq-gqaaa-aaaaj-qp4ta-cai.icp0.io/ | grep -o 'index-[A-Za-z0-9_-]*\.js' | sort -u
```

Expect `index-CgOaQqdM.js`. Seeing `index-BRUYhh7h.js` means the deploy did not
take effect. Boundary-node caching can delay the change briefly; re-check before
concluding failure, and do not redeploy to force it.

**b. The two ledger-bearing canisters are untouched.** Anonymous verified
`read_state`, no identity required:

```
DFX_WARNING=-mainnet_plaintext_identity \
dfx canister info <id> --network ic --identity anonymous
```

| Canister | ID | Module hash — must be unchanged |
|---|---|---|
| profile_factory | `5g26e-liaaa-aaaaj-qp4tq-cai` | `ccbfbdfd1ecc74667d09ae76fea1f1dca708b8855ef6526b64a6166d219bb905` |
| bulletin_board | `5iytm-qyaaa-aaaaj-qp4sq-cai` | `2c05915e32a391c8c2838af16dcb8a017cef5fa8353f04a006f00096ac158cf9` |

Both were confirmed at these values on 2026-08-02, before the deploy. The
factory hash is the W5 go-live anchor. **If either has changed, stop everything
and escalate — an asset deploy must not touch these canisters.**

**c. The asset canister wasm is unchanged.** Same command against
`5b3yq-gqaaa-aaaaj-qp4ta-cai`; the module hash was
`2c24b5e1584890a7965011d5d1d827aca68c489c9a6308475730420fa53372e8` before the
deploy and `--no-asset-upgrade` should leave it at that value.

All three canisters listed `q3gkv-ebczt-…-dqe` as sole controller at the time of
record.

## State at handoff

| Item | State |
|---|---|
| `feat/browser-finalize-r1` on origin | `b1c7ed3` (verified via `git ls-remote`) |
| `dfx.json` dependency fix | present in `b1c7ed3` |
| Live origin | serving old `index-BRUYhh7h.js` — deploy never ran |
| `dist/` in the WSL working copy | built, matches the hashes above, not deployed |
| factory / board module hashes | unchanged from go-live anchors |
| Mainnet state | nothing mutated by the aborted first attempt |
