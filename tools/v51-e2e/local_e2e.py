#!/usr/bin/env python3
"""DaffyDefs mktd02-v5.1 local-replica end-to-end.

Prerequisites (see README.md): a running local replica with profile_factory,
bulletin_board and frontend deployed from this repository, the factory funded,
a dfx identity with a plaintext PEM that has never created a profile, and a
built zd-finalize-helper.

Flow: create profile -> upsert -> delete (Phase A) -> assert pending receipt ->
finalise through the factory proxy (zd-finalize-helper --factory) -> assert the
finalized receipt -> export the CVDR JSON and the local root PEM -> verify with
tools/cvdr-verify under that root -> require V1/V2/V3A PASS.
"""

import argparse
import json
import os
import subprocess
import sys

from cvdr_json import cvdr_from_dfx, dfx, local_root_pem, render, verify

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
PROFILE_DID = os.path.join(REPO, "src/profile_canister/profile_canister.did")
DEFAULT_VERIFIER = os.path.join(REPO, "tools/cvdr-verify/bin/linux-x86_64/mktd02-verify")


def call(canister, method, arg="()", identity=None, query=False, candid=None):
    args = ["canister", "call", canister, method, arg, "--output", "json"]
    if query:
        args.append("--query")
    if candid:
        args += ["--candid", candid]
    return json.loads(dfx(*args, identity=identity))


def ok(result, what):
    if "Ok" not in result:
        raise SystemExit(f"FAIL {what}: {result}")
    return result["Ok"]


def check(condition, message):
    print(("PASS " if condition else "FAIL ") + message)
    if not condition:
        raise SystemExit(1)


def principal_bytes(text):
    """Raw bytes of a textual principal (inverse of the CRC32/base32 text form)."""
    import base64
    b32 = text.replace("-", "").upper()
    b32 += "=" * (-len(b32) % 8)
    return base64.b32decode(b32)[4:]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--identity", required=True, help="dfx identity with a plaintext PEM and no existing profile")
    ap.add_argument("--helper", required=True, help="path to zd-finalize-helper")
    ap.add_argument("--expected-module-hash", required=True, help="profile WASM sha256 (deploy-time expectation for the helper guard)")
    ap.add_argument("--out", required=True, help="output directory")
    ap.add_argument("--verifier", default=DEFAULT_VERIFIER)
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)

    factory = dfx("canister", "id", "profile_factory").strip()
    caller = dfx("identity", "get-principal", identity=a.identity).strip()
    pem_identity = os.path.expanduser(f"~/.config/dfx/identity/{a.identity}/identity.pem")

    # Create profile and set it up.
    profile = ok(call(factory, "get_or_create_profile_canister", identity=a.identity), "create profile")
    print(f"profile canister {profile} for {caller}")
    ok(call(profile, "upsert_profile",
            '(record { email = "e2e@example.invalid"; birthdate = "2000-01-01"; gender = "n/a"; display_name = "E2E User" })',
            identity=a.identity, candid=PROFILE_DID), "upsert")

    # DD2: resolve() is self-only for ordinary callers.
    own = call(factory, "resolve", f'(principal "{caller}")', identity=a.identity, query=True)
    check(own.get("Ok") == profile, "resolve(own principal) returns own profile canister")
    other = call(factory, "resolve", '(principal "aaaaa-aa")', identity=a.identity, query=True)
    check("NotAuthorized" in other.get("Err", {}), "resolve(another principal) is refused for an ordinary caller")

    # Phase A.
    receipt_id = ok(call(profile, "delete_profile", identity=a.identity, candid=PROFILE_DID), "delete")
    pending = call(profile, "mktd_get_receipt", f'("{receipt_id}")', query=True, candid=PROFILE_DID)[0]
    with open(os.path.join(a.out, "pending.dfx.json"), "w") as f:
        json.dump(pending, f, indent=2)

    record_id = bytes(pending["record_id"])
    check(pending["protocol_version"] == "mktd02-v5.1", "pending protocol_version is mktd02-v5.1")
    check(len(record_id) == 32, "record_id is 32 bytes")
    check(record_id != principal_bytes(caller), "record_id is not the caller principal")
    check(principal_bytes(caller) not in record_id, "record_id does not contain the caller principal")
    for field in ("module_hash", "trust_root_key_id", "bls_certificate", "module_hash_certificate"):
        check(pending[field] == [], f"pending receipt omits {field}")

    # Phase B/C through the factory proxy.
    helper = subprocess.run([
        a.helper, "--ic-url", "http://127.0.0.1:4943", "--fetch-root-key",
        "--identity-pem", pem_identity,
        "finalize", "--canister-id", profile,
        "--expected-module-hash", a.expected_module_hash,
        "--pending-event-hash", pending["deletion_event_hash"],
        "--finalize-method", "finalize_profile_receipt",
        "--finalize-canister-id", factory, "--factory",
        "--receipt-id", receipt_id,
        "--out-cert", os.path.join(a.out, "module_hash_certificate.cbor"),
        "--out-report", os.path.join(a.out, "guard_report.json"),
    ], capture_output=True, text=True)
    print(helper.stdout.strip().splitlines()[-1] if helper.stdout.strip() else helper.stderr)
    check(helper.returncode == 0, "finalisation through factory proxy")

    final = call(profile, "mktd_get_receipt", f'("{receipt_id}")', query=True, candid=PROFILE_DID)[0]
    cvdr = cvdr_from_dfx(final)
    with open(os.path.join(a.out, "guard_report.json")) as f:
        certified_leaf = json.load(f)["certified_module_hash"]
    check(cvdr.get("module_hash") == certified_leaf, "finalized module_hash == certified /canister/<id>/module_hash leaf")
    for field in ("module_hash", "trust_root_key_id", "bls_certificate", "module_hash_certificate"):
        check(field in cvdr, f"finalized receipt carries {field}")

    receipt_path = os.path.join(a.out, "receipt.json")
    pem_path = os.path.join(a.out, "local_root.pem")
    with open(receipt_path, "w") as f:
        f.write(render(cvdr))
    with open(pem_path, "w") as f:
        f.write(local_root_pem())

    facts = verify(a.verifier, receipt_path, pem_path)
    with open(os.path.join(a.out, "verify.json"), "w") as f:
        json.dump(facts, f, indent=2)
    checks = {k: v.get("outcome") for k, v in facts["checks"].items()}
    print(f"verifier: validity={facts['validity']['validity']} checks={checks} "
          f"trust_root_mismatch={facts.get('trust_root_mismatch')}")
    for name in ("v1", "v2", "v3a"):
        check(checks.get(name) == "pass", f"{name.upper()} PASS")
    check(facts["validity"]["validity"] == "PASS", "overall validity PASS")
    print(f"receipt: {receipt_path}\nroot:    {pem_path}")


if __name__ == "__main__":
    sys.exit(main())
