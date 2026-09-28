// Identity of the browser verifier served at /cvdr-wasm/.
//
// SERVED_WASM_SHA256 is the SHA-256 of public/cvdr-wasm/mktd02_verify_bg.wasm,
// the file the page actually loads. verifierBuild.test.ts fails if it drifts
// from that file. Provenance: docs/REFERENCE_VERIFIER.md,
// "Browser verifier (Quick Verify)".
export const SERVED_WASM_SHA256 =
  "1f8b4cd14280f2d384d530475ae195cff5d7fa2b7576b1f12ffe69194b3dc1d0";

export const VERIFIER_SOURCE_LABEL =
  "DaffyDefs 1ff2149 (tools/cvdr-verify = CVDR-Verify 67cbe4b)";

export const V3B_INSTRUCTIONS_URL =
  "https://github.com/Together-Alone-Ventures/daffydefs/blob/current-release/docs/DEMO_PACK.md#c-optional-v3b-rebuild-the-profile-wasm";
