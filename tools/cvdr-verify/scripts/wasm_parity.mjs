#!/usr/bin/env node

import { execFileSync, spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";

const crate = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const acceptedReceipt = process.env.ACCEPTED_RECEIPT;

if (!acceptedReceipt) {
    throw new Error("ACCEPTED_RECEIPT must name the accepted MKTd02-v5 receipt");
}

const fixtures = [
    {
        name: "accepted-mainnet",
        path: resolve(acceptedReceipt),
        source: `file:${resolve(acceptedReceipt)}`,
        expected: {
            receiptState: "FinalizedCandidate",
            checks: { v1: "pass", v2: "pass", v3a: "pass" },
            validity: "PASS",
        },
    },
    {
        name: "v1-invalid",
        path: "tests/fixtures/v5/quick-verify-state-matrix/v1-invalid.json",
        source: "file:tests/fixtures/v5/quick-verify-state-matrix/v1-invalid.json",
        expected: {
            checks: { v1: "fail" },
            validity: "FAIL",
        },
    },
    {
        name: "pending",
        path: "tests/fixtures/v5/quick-verify-state-matrix/pending.json",
        source: "file:tests/fixtures/v5/quick-verify-state-matrix/pending.json",
        expected: {
            receiptState: "Pending",
            checks: { v1: "pass", v2: "not_evaluated", v3a: "not_evaluated" },
            validity: "INCOMPLETE",
        },
    },
    {
        name: "incomplete",
        path: "tests/fixtures/v5/quick-verify-state-matrix/incomplete.json",
        source: "file:tests/fixtures/v5/quick-verify-state-matrix/incomplete.json",
        expected: {
            receiptState: "InvalidIncompleteFinalization",
            checks: { v1: "pass", v2: "fail", v3a: "fail" },
            validity: "FAIL",
        },
    },
    {
        name: "pocketic-finalized",
        path: "tests/fixtures/v5/pocketic-11-p17/receipt.cbor",
        source: "file:tests/fixtures/v5/pocketic-11-p17/receipt.cbor",
        expected: {
            receiptState: "FinalizedCandidate",
            checks: { v1: "pass", v2: "fail", v3a: "fail" },
            validity: "FAIL",
            receiptTrustRootKeyId: "mainnet",
            verificationRoot: "mainnet",
            trustRootMismatch: null,
        },
    },
];

const run = (program, args) => execFileSync(program, args, { cwd: crate, stdio: "inherit" });

run("cargo", ["build", "--locked", "--release", "--bin", "mktd02-verify"]);
run("cargo", [
    "build",
    "--locked",
    "--lib",
    "--release",
    "--no-default-features",
    "--features",
    "wasm",
    "--target",
    "wasm32-unknown-unknown",
]);

const bindings = mkdtempSync(join(tmpdir(), "mktd02-wasm-parity-"));
run("wasm-bindgen", [
    "--target",
    "nodejs",
    "--out-dir",
    bindings,
    "target/wasm32-unknown-unknown/release/mktd02_verify.wasm",
]);

const require = createRequire(import.meta.url);
const { verify_cvdr } = require(join(bindings, "mktd02_verify.js"));

for (const fixture of fixtures) {
    const native = spawnSync(
        join(crate, "target/release/mktd02-verify"),
        ["--receipt-file", fixture.path, "--trust-root", "mainnet", "--json"],
        { cwd: crate, encoding: "utf8" },
    );
    if (![0, 1, 4].includes(native.status)) {
        throw new Error(`${fixture.name}: native verifier exited ${native.status}: ${native.stderr}`);
    }

    const wasmJson = verify_cvdr(readFileSync(resolve(crate, fixture.path)), fixture.source);
    const nativeJson = native.stdout.trimEnd();
    if (nativeJson !== wasmJson) {
        throw new Error(`${fixture.name}: native/WASM JSON facts differ`);
    }

    const facts = JSON.parse(wasmJson);
    if (facts.source !== fixture.source) {
        throw new Error(`${fixture.name}: source fact differs from ${fixture.source}`);
    }
    if (fixture.expected.receiptState && facts.receipt_state !== fixture.expected.receiptState) {
        throw new Error(`${fixture.name}: receipt state is ${facts.receipt_state}`);
    }
    if (facts.validity.validity !== fixture.expected.validity) {
        throw new Error(`${fixture.name}: validity is ${facts.validity.validity}`);
    }
    for (const [check, outcome] of Object.entries(fixture.expected.checks)) {
        if (facts.checks[check].outcome !== outcome) {
            throw new Error(`${fixture.name}: ${check} is ${facts.checks[check].outcome}`);
        }
    }
    if (
        fixture.expected.receiptTrustRootKeyId
        && facts.receipt_trust_root_key_id !== fixture.expected.receiptTrustRootKeyId
    ) {
        throw new Error(`${fixture.name}: receipt trust-root key id changed`);
    }
    if (
        fixture.expected.verificationRoot
        && facts.trust_root_used.id !== fixture.expected.verificationRoot
    ) {
        throw new Error(`${fixture.name}: verification root changed`);
    }
    if (
        Object.hasOwn(fixture.expected, "trustRootMismatch")
        && facts.trust_root_mismatch !== fixture.expected.trustRootMismatch
    ) {
        throw new Error(`${fixture.name}: trust-root mismatch fact changed`);
    }
    console.log(`${fixture.name}: ${facts.validity.validity} (native exit ${native.status}; exact JSON parity)`);
}
