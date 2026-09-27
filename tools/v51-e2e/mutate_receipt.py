#!/usr/bin/env python3
"""Field-by-field mutation matrix over a finalized mktd02-v5.1 receipt.

Each displayed field is changed on its own. For each mutation the matrix states
which gating checks (V1, V2, V3A) must fail and which must keep passing, and
the verifier's result is compared against that.

Usage:
  mutate_receipt.py --receipt receipt.json --root-pem local_root.pem [--verifier ...]
"""

import argparse
import json
import os
import sys
import tempfile

from cvdr_json import failing_checks, verify

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
DEFAULT_VERIFIER = os.path.join(REPO, "tools/cvdr-verify/bin/linux-x86_64/mktd02-verify")
ALL = {"V1", "V2", "V3A"}


def flip_hex(value):
    """Change the last byte of a hex string (keeps length and shape)."""
    return value[:-2] + format(int(value[-2:], 16) ^ 0x01, "02x")


# field -> (mutation, checks that must fail, extra checks allowed to fail, why)
MATRIX = {
    "receipt_id": (flip_hex, {"V1"}, set(), "receipt_id recomputation mismatches"),
    "record_id": (flip_hex, {"V1"}, set(), "receipt_id recomputed from record_id mismatches"),
    "canister_id": (lambda v: "aaaaa-aa", {"V1", "V2", "V3A"}, set(),
                    "receipt_id binds canister_id; both certificates are read under canister_id"),
    "deletion_seq": (lambda v: v + 1, {"V1"}, set(), "receipt_id and EVENT_V3 bind deletion_seq"),
    "timestamp": (lambda v: v + 1, {"V1"}, set(), "EVENT_V3 binds timestamp"),
    "pre_state_hash": (flip_hex, {"V1"}, set(), "EVENT_V3 binds pre_state_hash"),
    "post_state_hash": (flip_hex, {"V1"}, set(), "EVENT_V3 binds post_state_hash"),
    # V3A re-validates the BLS certificate (for certificate-time ordering)
    # against the receipt's deletion_event_hash, so it fails closed as well.
    "deletion_event_hash": (flip_hex, {"V1", "V2"}, {"V3A"},
                            "recomputed and certified value both differ; V3A's BLS-pair check also binds it"),
    "tombstone_hash": (flip_hex, set(), set(), "diagnostic only; not in the verification chain"),
    "module_hash": (flip_hex, {"V3A"}, set(), "not an EVENT_V3 operand; V3A compares the certified leaf"),
    "trust_root_key_id": (lambda v: "local-dev" if v != "local-dev" else "mainnet", set(), set(),
                          "label only; never selects the root; mismatch reported, non-gating"),
    "bls_certificate": (flip_hex, {"V2"}, {"V3A"},
                        "certificate signature no longer verifies; V3A uses it for time ordering"),
    "module_hash_certificate": (flip_hex, {"V3A"}, set(), "module-hash certificate signature no longer verifies"),
}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--receipt", required=True)
    ap.add_argument("--root-pem", required=True)
    ap.add_argument("--verifier", default=DEFAULT_VERIFIER)
    ap.add_argument("--out", help="write the matrix result as JSON here")
    a = ap.parse_args()

    with open(a.receipt) as f:
        base = json.load(f)

    baseline = verify(a.verifier, a.receipt, a.root_pem)
    if failing_checks(baseline) or baseline["validity"]["validity"] != "PASS":
        print(f"baseline receipt does not PASS: {failing_checks(baseline)}")
        return 1
    print("baseline: V1/V2/V3A PASS")

    rows, deviations = [], 0
    with tempfile.TemporaryDirectory() as tmp:
        for field, (mutate, must_fail, may_fail, why) in MATRIX.items():
            mutated = dict(base)
            mutated[field] = mutate(base[field])
            path = os.path.join(tmp, f"{field}.json")
            with open(path, "w") as f:
                json.dump(mutated, f, indent=2)
            facts = verify(a.verifier, path, a.root_pem)
            failed = failing_checks(facts)
            intake = facts.get("intake_error")
            validity = (facts.get("validity") or {}).get("validity")
            ok = (not intake) and must_fail <= failed and failed <= (must_fail | may_fail)
            if field == "trust_root_key_id":
                mismatch = facts.get("trust_root_mismatch") or {}
                ok = ok and validity == "PASS" and mismatch.get("receipt_says") == mutated[field]
            if not ok:
                deviations += 1
            still_pass = sorted(ALL - failed)
            print(f"{'OK ' if ok else 'DEV'} {field:24} fails={sorted(failed) or '-'} "
                  f"passes={still_pass or '-'} validity={validity}"
                  + (f" intake_error={intake}" if intake else "") + f"  ({why})")
            rows.append({"field": field, "must_fail": sorted(must_fail), "may_fail": sorted(may_fail),
                         "failed": sorted(failed), "still_passing": still_pass,
                         "validity": validity, "intake_error": intake, "ok": ok, "why": why})

    if a.out:
        with open(a.out, "w") as f:
            json.dump(rows, f, indent=2)
    print(f"{len(rows)} mutations, {deviations} deviation(s)")
    return 1 if deviations else 0


if __name__ == "__main__":
    sys.exit(main())
